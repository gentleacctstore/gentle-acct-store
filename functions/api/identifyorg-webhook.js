
/**
 * GentleLogs — IdentifyOrg live payment webhook
 *
 * Verifies signed payment events and credits customer wallets
 * exactly once using an atomic Firestore commit.
 */

import {
  firestoreBase,
  firestoreRequest,
  decodeFields,
  encodeFields
} from "../_shared/firebase-admin.js";

const MIN_AMOUNT = 100;
const MAX_AMOUNT = 5000000;
const SIGNATURE_TOLERANCE_SECONDS = 300;

async function verifySignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;

  const parts = {};

  for (const part of signatureHeader.split(",")) {
    const index = part.indexOf("=");

    if (index > 0) {
      parts[part.slice(0, index).trim()] =
        part.slice(index + 1).trim();
    }
  }

  const timestamp = parts.t;
  const suppliedSignature = String(parts.v1 || "").toLowerCase();

  if (
    !timestamp ||
    !/^[a-f0-9]{64}$/.test(suppliedSignature)
  ) {
    return false;
  }

  const timestampNumber = Number(timestamp);

  if (
    !Number.isFinite(timestampNumber) ||
    Math.abs(Date.now() / 1000 - timestampNumber) >
      SIGNATURE_TOLERANCE_SECONDS
  ) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signatureBytes = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(timestamp + "." + rawBody)
  );

  const expected = Array.from(new Uint8Array(signatureBytes))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  if (expected.length !== suppliedSignature.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < expected.length; i++) {
    difference |=
      expected.charCodeAt(i) ^
      suppliedSignature.charCodeAt(i);
  }

  return difference === 0;
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return json(
      { error: "Method not allowed. Use POST." },
      405
    );
  }

  try {
    if (
      !env.IDENTIFYORG_WEBHOOK_SECRET ||
      !env.FIREBASE_PROJECT_ID ||
      !env.FIREBASE_CLIENT_EMAIL ||
      !env.FIREBASE_PRIVATE_KEY
    ) {
      return json(
        { error: "Webhook configuration is incomplete." },
        503
      );
    }

    const contentType =
      request.headers.get("content-type") || "";

    if (!contentType.toLowerCase().includes("application/json")) {
      return json({ error: "Invalid content type." }, 415);
    }

    const rawBody = await request.text();

    if (!rawBody || rawBody.length > 1024 * 1024) {
      return json({ error: "Invalid webhook body." }, 400);
    }

    const signature =
      request.headers.get("X-IdentifyOrg-Signature");

    if (
      !(await verifySignature(
        rawBody,
        signature,
        env.IDENTIFYORG_WEBHOOK_SECRET
      ))
    ) {
      return json({ error: "Invalid webhook signature." }, 401);
    }

    let payload;

    try {
      payload = JSON.parse(rawBody);
    } catch {
      return json({ error: "Invalid JSON payload." }, 400);
    }

    const headerDeliveryId =
      request.headers.get("X-IdentifyOrg-Delivery");

    const deliveryId = String(headerDeliveryId || "");

    if (
      !deliveryId ||
      deliveryId !== String(payload.id || "") ||
      !/^[A-Za-z0-9_-]{1,180}$/.test(deliveryId)
    ) {
      return json({ error: "Invalid delivery identifier." }, 400);
    }

    // Ignore unrelated webhook event types.
    if (payload.event !== "payment.received") {
      return json({
        received: true,
        ignored: true
      });
    }

    const payment = payload.data || {};

    const reference = String(payment.reference || "");
    const amount = Number(payment.amount);
    const currency = String(payment.currency || "").toUpperCase();

    // Validate payment details.
    if (
      !/^mp_[A-Za-z0-9_-]{5,150}$/.test(reference) ||
      !Number.isSafeInteger(amount) ||
      amount < MIN_AMOUNT ||
      amount > MAX_AMOUNT ||
      currency !== "NGN"
    ) {
      return json({
        error: "Invalid payment details."
      }, 400);
    }

    // Held and failed payments must never credit a wallet.
    if (
      payment.status === "held" ||
      payment.status === "failed"
    ) {
      return json({
        received: true,
        ignored: true,
        reason: "Payment is not successful."
      });
    }

    if (payment.status !== "success") {
      return json({
        error: "Unknown payment status."
      }, 400);
    }

    // Only explicitly confirmed live payments are accepted.
    if (payment.test !== false) {
      return json({
        received: true,
        ignored: true,
        reason: "Payment is not confirmed as live."
      });
    }

    // Find the original pending funding request.
    const fundingPath =
      "/fundingRequests/" + encodeURIComponent(reference);

    let fundingDocument;

    try {
      fundingDocument = await firestoreRequest(env, fundingPath);
    } catch (error) {
      if (error.status === 404) {
        return json({
          error: "Matching funding request not found."
        }, 503);
      }

      throw error;
    }

    const funding = decodeFields(fundingDocument.fields);

    // Never credit an already approved request again.
    if (funding.status === "approved") {
      return json({
        received: true,
        alreadyProcessed: true
      });
    }

    if (
      funding.status !== "pending" ||
      funding.paymentMethod !== "identifyorg_checkout" ||
      funding.reference !== reference ||
      Number(funding.amount) !== amount ||
      String(funding.currency || "").toUpperCase() !== "NGN" ||
      !funding.userId
    ) {
      return json({
        error: "Payment does not match a pending funding request."
      }, 409);
    }

    const uid = String(funding.userId);

    if (!/^[A-Za-z0-9_-]{1,150}$/.test(uid)) {
      return json({ error: "Invalid customer account." }, 400);
    }

    // Check whether this exact webhook delivery was already processed.
    const deliveryPath =
      "/webhookDeliveries/" + encodeURIComponent(deliveryId);

    try {
      await firestoreRequest(env, deliveryPath);

      return json({
        received: true,
        alreadyProcessed: true
      });
    } catch (error) {
      if (error.status !== 404) throw error;
    }

    // Load the customer's wallet.
    const walletPath = "/wallets/" + encodeURIComponent(uid);

    let walletDocument;

    try {
      walletDocument = await firestoreRequest(env, walletPath);
    } catch (error) {
      if (error.status === 404) {
        return json({
          error: "Customer wallet does not exist."
        }, 409);
      }

      throw error;
    }

    const wallet = decodeFields(walletDocument.fields);
    const currentBalance = Number(wallet.balance);

    if (
      !Number.isSafeInteger(currentBalance) ||
      currentBalance < 0
    ) {
      return json({
        error: "Customer wallet balance is invalid."
      }, 409);
    }

    // Credit the full amount paid by the customer.
    // The business pays the provider fee.
    const newBalance = currentBalance + amount;

    if (!Number.isSafeInteger(newBalance)) {
      return json({
        error: "Wallet balance calculation is invalid."
      }, 409);
    }

    const providerFee = Number(payment.fee || 0);
    const providerNet = Number(payment.net || 0);

    if (
      !Number.isFinite(providerFee) ||
      providerFee < 0 ||
      !Number.isFinite(providerNet) ||
      providerNet < 0
    ) {
      return json({
        error: "Invalid provider payment fee details."
      }, 400);
    }

    const now = new Date().toISOString();

    // All three writes succeed together or none do.
    const commitBody = {
      writes: [
        {
          update: {
            name: walletDocument.name,
            fields: encodeFields({
              balance: newBalance,
              updatedAt: now
            })
          },
          updateMask: {
            fieldPaths: ["balance", "updatedAt"]
          },
          currentDocument: {
            updateTime: walletDocument.updateTime
          }
        },
        {
          update: {
            name: fundingDocument.name,
            fields: encodeFields({
              status: "approved",
              creditedAt: now,
              verifiedAt: now,
              providerFee,
              providerNet,
              providerPaymentStatus: payment.status,
              providerTest: payment.test
            })
          },
          updateMask: {
            fieldPaths: [
              "status",
              "creditedAt",
              "verifiedAt",
              "providerFee",
              "providerNet",
              "providerPaymentStatus",
              "providerTest"
            ]
          },
          currentDocument: {
            updateTime: fundingDocument.updateTime
          }
        },
        {
          update: {
            name: firestoreBase(env) +
              "/webhookDeliveries/" +
              encodeURIComponent(deliveryId),
            fields: encodeFields({
              eventId: deliveryId,
              reference,
              userId: uid,
              amount,
              currency,
              event: "payment.received",
              processedAt: now
            })
          },
          currentDocument: {
            exists: false
          }
        }
      ]
    };

    await firestoreRequest(env, ":commit", {
      method: "POST",
      body: JSON.stringify(commitBody)
    });

    console.log(
      "IdentifyOrg payment successfully processed:",
      reference
    );

    return json({
      received: true,
      credited: true,
      reference,
      amount,
      currency,
      newBalance
    });

  } catch (error) {
    console.error(
      "GentleLogs IdentifyOrg webhook error:",
      error.message || error
    );

    return json({
      error: "Payment processing failed. Please retry delivery."
    }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}
