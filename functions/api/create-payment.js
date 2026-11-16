
import {
  firestoreRequest,
  encodeFields
} from "../_shared/firebase-admin.js";

const IDENTIFYORG_URL =
  "https://api.identifyorg.com/v1/business/charges";

const MIN_AMOUNT = 100;
const MAX_AMOUNT = 5000000;

const ALLOWED_METHODS = ["card", "transfer", "ussd"];

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequestPost({ request, env }) {
  try {
    if (
      !env.IDENTIFYORG_API_KEY ||
      !env.FIREBASE_API_KEY ||
      !env.FIREBASE_PROJECT_ID ||
      !env.FIREBASE_CLIENT_EMAIL ||
      !env.FIREBASE_PRIVATE_KEY
    ) {
      return json({
        error: "Payment server configuration is incomplete."
      }, 500);
    }

    // Verify the customer's Firebase session.
    const authorization =
      request.headers.get("Authorization") || "";

    const match = authorization.match(/^Bearer (.+)$/);

    if (!match) {
      return json({
        error: "Please sign in before making a payment."
      }, 401);
    }

    const verifyResponse = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" +
        encodeURIComponent(env.FIREBASE_API_KEY),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          idToken: match[1]
        })
      }
    );

    const verifyData = await verifyResponse.json();

    if (
      !verifyResponse.ok ||
      !verifyData.users ||
      !verifyData.users.length
    ) {
      return json({
        error: "Your sign-in session is invalid."
      }, 401);
    }

    const customer = verifyData.users[0];
    const uid = String(customer.localId || "");
    const email = String(customer.email || "").trim();

    if (!uid || !email) {
      return json({
        error: "Your account needs a valid email address."
      }, 400);
    }

    // Validate the requested payment.
    const body = await request.json();
    const amount = Number(body.amount);

    const selectedMethod =
      String(body.paymentMethod || "transfer").toLowerCase();

    if (
      !Number.isSafeInteger(amount) ||
      amount < MIN_AMOUNT ||
      amount > MAX_AMOUNT
    ) {
      return json({
        error: "Enter an amount between ₦100 and ₦5,000,000."
      }, 400);
    }

    if (!ALLOWED_METHODS.includes(selectedMethod)) {
      return json({
        error: "Unsupported payment method."
      }, 400);
    }

    const customerName =
      String(customer.displayName || email.split("@")[0]).trim();

    const siteUrl = new URL(request.url).origin;

    // Create the IdentifyOrg charge.
    const chargeResponse = await fetch(IDENTIFYORG_URL, {
      method: "POST",
      headers: {
        "X-IdentifyOrg-Key": env.IDENTIFYORG_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        amount,
        customer_name: customerName,
        customer_email: email,
        description: "GentleLogs wallet funding",
        redirect_url: siteUrl + "/fund.html",
        payment_methods: [selectedMethod]
      })
    });

    const chargeData = await chargeResponse.json();

    if (!chargeResponse.ok) {
      console.error("IdentifyOrg charge error:", chargeData);

      return json({
        error:
          chargeData.message ||
          chargeData.error ||
          "IdentifyOrg could not create your payment."
      }, 502);
    }

    const reference = String(chargeData.reference || "");
    const checkoutUrl = String(chargeData.checkout_url || "");

    if (
      !/^[A-Za-z0-9_-]{5,150}$/.test(reference) ||
      !checkoutUrl
    ) {
      return json({
        error: "IdentifyOrg returned incomplete payment details."
      }, 502);
    }

    // Only accept IdentifyOrg's documented hosted checkout domain.
    let parsedUrl;

    try {
      parsedUrl = new URL(checkoutUrl);
    } catch {
      return json({
        error: "Invalid checkout address returned by IdentifyOrg."
      }, 502);
    }

    if (
      parsedUrl.protocol !== "https:" ||
      parsedUrl.hostname !== "identifyorg.com"
    ) {
      return json({
        error: "The payment checkout address could not be verified."
      }, 502);
    }

    // Save the pending funding request using the provider reference
    // as its Firestore document ID. The webhook uses this same ID.
    const fundingRecord = {
      userId: uid,
      amount,
      currency: "NGN",
      reference,
      status: "pending",
      paymentMethod: "identifyorg_checkout",
      selectedPaymentMethod: selectedMethod,
      provider: "IdentifyOrg",
      customerEmail: email,
      createdAt: new Date().toISOString()
    };

    await firestoreRequest(
      env,
      "/fundingRequests?documentId=" +
        encodeURIComponent(reference),
      {
        method: "POST",
        body: JSON.stringify({
          fields: encodeFields(fundingRecord)
        })
      }
    );

    // Return checkout details to payment.html.
    return json({
      checkoutUrl: parsedUrl.href,
      reference,
      amount
    });

  } catch (error) {
    console.error(
      "GentleLogs payment creation error:",
      error.message || error
    );

    return json({
      error: "We could not prepare your payment. Please try again."
    }, 500);
  }
}
