
/**
 * GentleLogs — IdentifyOrg payment webhook
 *
 * - Verifies IdentifyOrg HMAC signatures.
 * - Checks webhook timestamp and delivery ID.
 * - Accepts only payment.received events.
 * - Matches the payment to a pending funding request.
 * - Verifies amount and NGN currency.
 * - Credits the customer's wallet atomically.
 * - Prevents duplicate wallet credits.
 *
 * Requires:
 * functions/_shared/firebase-admin.js
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
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      parts[key] = value;
    }
  }

  const timestamp = parts.t;
  const suppliedSignature = parts.v1;

  if (!timestamp || !suppliedSignature) return false;

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
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signatureBytes = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(timestamp + "." + rawBody)
  );

  const expectedSignature = Array.from(
    new Uint8Array(signatureBytes)
  )
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  if (
    expectedSignature.length !== suppliedSignature.length
  ) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < expectedSignature.length; i++) {
    difference |=
      expectedSignature.charCodeAt(i) ^
      suppliedSignature.charCodeAt(i);
  }

  return difference === 0;
}

export async function onRequestPost({ request, env }) {
  try {
    if (
      !env.IDENTIFYORG_WEBHOOK_SECRET ||
      !env.FIREBASE_PROJECT_ID ||
      !env.FIREBASE_CLIENT_EMAIL ||
      !env.FIREBASE_PRIVATE_KEY
    ) {
      console.error("Webhook configuration is incomplete.");

      return json({
        error: "Webhook configuration is incomplete."
      }, 503);
    }

    const contentType =
      request.headers.get("content-type") || "";

    if (!contentType.toLowerCase().includes("application/json")) {
      return json({
        error: "Invalid content type."
      }, 415);
    }

    // Read the original body before parsing.
    const rawBody = await request.text();

    if (!rawBody || rawBody.length > 1024 * 1024) {
      return json({
        error: "Invalid webhook body."
      }, 400);
    }

    // Verify the provider signature.
    const signature =
      request.headers.get("X-IdentifyOrg-Signature");

    const signatureIsValid = await verifySignature(
      rawBody,
      signature,
      env.IDENTIFYORG_WEBHOOK_SECRET
    );

    if (!signatureIsValid) {
      return json({
        error: "Invalid webhook signature."
      }, 401);
    }

    let payload;

    try {
      payload = JSON.parse(rawBody);
    } catch {
      return json({
        error: "Invalid JSON payload."
      }, 400);
    }

    // Confirm the provider's delivery identifier.
    const headerDeliveryId =
      request.headers.get("X-IdentifyOrg-Delivery");

    const deliveryId = String(
      headerDeliveryId || payload.id || ""
    );

    if (
      !deliveryId ||
      deliveryId !== String(payload.id || "") ||
      !/^[A-Za-z0-9_-]{1,180}$/.test(deliveryId)
    ) {
      return json({
        error: "Invalid delivery identifier."
      }, 400);
    }

    // Ignore events that do not represent received payments.
    if (payload.event !== "payment.received") {
      return json({
        received: true,
        ignored: true
      });
    }

    const payment = payload.data || {};

    const reference = String(payment.reference || "");
    const amount = Number(payment.amount);
    const currency = String(
      payment.currency || ""
    ).toUpperCase();

    if (
      !/^[A-Za-z0-9_-]{5,150}$/.test(reference) ||
      !Number.isSafeInteger(amount) ||
      amount < MIN_AMOUNT ||
      amount > MAX_AMOUNT ||
      currency !== "NGN"
    ) {
      return json({
        error: "Invalid payment details."
      }, 400);
    }

    // Find the funding request using the provider reference.
    const requestPath =
      "/fundingRequests/" + encodeURIComponent(reference);

    let fundingDocument;

    try {
      fundingDocument = await firestoreRequest(
        env,
        requestPath
      );
    } catch (error) {
      if (error.status === 404) {
        // Ask the provider to retry if the matching request
        // has not appeared in Firestore yet.
        return json({
          error: "Matching funding request not found."
        }, 503);
      }

      throw error;
    }

    const funding = decodeFields(
      fundingDocument.fields
    );

    // A request must match this exact payment.
    if (
      funding.status !== "pending" ||
      funding.paymentMethod !== "identifyorg_checkout" ||
      Number(funding.amount) !== amount ||
      !funding.userId
    ) {
      if (funding.status === "approved") {
        return json({
          received: true,
          alreadyProcessed: true
        });
      }

      return json({
        error: "Payment does not match a pending funding request."
      }, 409);
    }

    const uid = String(funding.userId);

    if (!/^[A-Za-z0-9_-]{1,150}$/.test(uid)) {
      return json({
        error: "Invalid customer account."
      }, 400);
    }

    // Check whether this delivery was already processed.
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

    // Load the customer's existing wallet.
    const walletPath =
      "/wallets/" + encodeURIComponent(uid);

    let walletDocument;

    try {
      walletDocument = await firestoreRequest(
        env,
        walletPath
      );
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
      !Number.isFinite(currentBalance) ||
      currentBalance < 0
    ) {
      return json({
        error: "Customer wallet balance is invalid."
      }, 409);
    }

    const newBalance = currentBalance + amount;

    if (!Number.isSafeInteger(newBalance)) {
      return json({
        error: "Wallet balance calculation is invalid."
      }, 409);
    }

    const now = new Date().toISOString();

    /*
     * ATOMIC FIRESTORE COMMIT
     *
     * All three operations succeed together or fail together:
     * 1. Update customer wallet.
     * 2. Mark funding request approved.
     * 3. Record unique webhook delivery.
     *
     * Document version checks prevent concurrent deliveries
     * from crediting the same funding request twice.
     */

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
            fieldPaths: [
              "balance",
              "updatedAt"
            ]
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
              verifiedAt: now
            })
          },
          updateMask: {
            fieldPaths: [
              "status",
              "creditedAt",
              "verifiedAt"
            ]
          },
          currentDocument: {
            updateTime: fundingDocument.updateTime
          }
        },
        {
          update: {
            name: firestoreBase(env) +
              "/webhookDeliveries/" + deliveryId,
            fields: encodeFields({
              eventId: deliveryId,
              reference: reference,
              userId: uid,
              amount: amount,
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

    await firestoreRequest(
      env,
      ":commit",
      {
        method: "POST",
        body: JSON.stringify(commitBody)
      }
    );

    console.log(
      "IdentifyOrg payment successfully processed:",
      reference
    );

    return json({
      received: true,
      credited: true
    });

  } catch (error) {
    console.error(
      "GentleLogs IdentifyOrg webhook error:",
      error.message || error
    );

    // A failed delivery should be retried by the provider.
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
