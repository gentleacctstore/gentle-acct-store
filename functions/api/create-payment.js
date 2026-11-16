
const IDENTIFYORG_URL = "https://api.identifyorg.com/v1/business/charges";

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
    if (!env.IDENTIFYORG_API_KEY) {
      return json({ error: "Payment service is not configured." }, 500);
    }

    if (!env.FIREBASE_API_KEY) {
      return json({ error: "Firebase verification is not configured." }, 500);
    }

    const authorization = request.headers.get("Authorization") || "";
    const match = authorization.match(/^Bearer (.+)$/);

    if (!match) {
      return json({ error: "Please sign in before making a payment." }, 401);
    }

    const idToken = match[1];

    // Verify the Firebase ID token with Firebase Authentication.
    const verifyResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(env.FIREBASE_API_KEY)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken })
      }
    );

    const verifyData = await verifyResponse.json();

    if (!verifyResponse.ok || !verifyData.users?.length) {
      return json({ error: "Your sign-in session is invalid. Please sign in again." }, 401);
    }

    const customer = verifyData.users[0];

    if (!customer.email) {
  return json({ error: "Your account needs an email address." }, 400);
}

    const body = await request.json();

    const amount = Number(body.amount);
    const selectedMethod = String(body.paymentMethod || "transfer").toLowerCase();

    if (!Number.isSafeInteger(amount) || amount < MIN_AMOUNT || amount > MAX_AMOUNT) {
      return json({ error: "Enter an amount between ₦100 and ₦5,000,000." }, 400);
    }

    if (!ALLOWED_METHODS.includes(selectedMethod)) {
      return json({ error: "That payment method is not supported." }, 400);
    }

    const customerName =
      String(customer.displayName || customer.email.split("@")[0]).trim();

    const siteUrl = new URL(request.url).origin;

    const chargePayload = {
      amount,
      customer_name: customerName,
      customer_email: customer.email,
      description: "GentleLogs wallet funding",
      redirect_url: `${siteUrl}/payment-return.html`,
      payment_methods: [selectedMethod]
    };

    const chargeResponse = await fetch(IDENTIFYORG_URL, {
      method: "POST",
      headers: {
        "X-IdentifyOrg-Key": env.IDENTIFYORG_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(chargePayload)
    });

    const chargeData = await chargeResponse.json();

    if (!chargeResponse.ok) {
      console.error("IdentifyOrg charge error:", chargeData);

      return json({
        error: chargeData.message || chargeData.error ||
          "IdentifyOrg could not create the payment. Please try again."
      }, 502);
    }

    const checkoutUrl = chargeData.checkout_url;

    if (!checkoutUrl) {
      return json({ error: "IdentifyOrg did not return a checkout link." }, 502);
    }

    let parsedUrl;

    try {
      parsedUrl = new URL(checkoutUrl);
    } catch {
      return json({ error: "IdentifyOrg returned an invalid checkout link." }, 502);
    }

    if (
      parsedUrl.protocol !== "https:" ||
      parsedUrl.hostname !== "identifyorg.com"
    ) {
      return json({ error: "The checkout link could not be verified." }, 502);
    }

    return json({
      checkoutUrl: parsedUrl.href,
      reference: chargeData.reference,
      amount
    });

  } catch (error) {
    console.error("GentleLogs payment error:", error);

    return json({
      error: "We could not prepare your payment. Please try again."
    }, 500);
  }
}
