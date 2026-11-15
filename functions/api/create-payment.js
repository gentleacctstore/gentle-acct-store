
/**
 * GentleLogs — IdentifyOrg checkout creation
 * Cloudflare Pages Function
 */

const MIN_AMOUNT = 100;
const MAX_AMOUNT = 5000000;

const ALLOWED_METHODS = ["card", "transfer", "ussd"];

export async function onRequestPost({ request, env }) {
  try {
    if (!env.IDENTIFYORG_API_KEY || !env.FIREBASE_WEB_API_KEY) {
      return json({ error: "Payment configuration is incomplete." }, 503);
    }

    const authorization = request.headers.get("Authorization") || "";
    const tokenMatch = authorization.match(/^Bearer (.+)$/);

    if (!tokenMatch) {
      return json({ error: "Authentication required." }, 401);
    }

    // Verify the Firebase user token.
    const authResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${env.FIREBASE_WEB_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: tokenMatch[1] })
      }
    );

    if (!authResponse.ok) {
      return json({ error: "Your sign-in session is invalid." }, 401);
    }

    const authData = await authResponse.json();
    const user = authData.users?.[0];

    if (!user?.localId || user.disabled) {
      return json({ error: "Account verification failed." }, 401);
    }

    const body = await request.json();

    const amount = Number(body.amount);
    const method = body.paymentMethod;

    if (
      !Number.isSafeInteger(amount) ||
      amount < MIN_AMOUNT ||
      amount > MAX_AMOUNT
    ) {
      return json({
        error: "Amount must be between ₦100 and ₦5,000,000."
      }, 400);
    }

    if (!ALLOWED_METHODS.includes(method)) {
      return json({ error: "Invalid payment method." }, 400);
    }

    const customerName = String(
      user.displayName || "GentleLogs Customer"
    ).slice(0, 100);

    const customerEmail = String(user.email || "").trim();

    if (!customerEmail) {
      return json({
        error: "A verified customer email is required."
      }, 400);
    }

    const payload = {
      amount,
      customer_name: customerName,
      customer_email: customerEmail,
      description: `GentleLogs wallet funding - ${user.localId}`,
      redirect_url: "https://gentlelogs.pages.dev/payment.html",
      payment_methods: [method]
    };

    const paymentResponse = await fetch(
      "https://api.identifyorg.com/v1/business/charges",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-IdentifyOrg-Key": env.IDENTIFYORG_API_KEY
        },
        body: JSON.stringify(payload)
      }
    );

    const result = await paymentResponse.json();

    if (!paymentResponse.ok) {
      return json({
        error: result?.error?.message ||
          "IdentifyOrg could not create the payment."
      }, paymentResponse.status);
    }

    if (!result.checkout_url || !result.reference) {
      return json({
        error: "The payment provider returned an incomplete response."
      }, 502);
    }

    return json({
      success: true,
      checkoutUrl: result.checkout_url,
      reference: result.reference,
      amount,
      currency: "NGN"
    });

  } catch (error) {
    console.error("GentleLogs payment creation error:", error);

    return json({
      error: "Unable to start payment. Please try again."
    }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}
