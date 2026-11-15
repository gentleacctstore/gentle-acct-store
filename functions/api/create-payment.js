/**
 * GentleLogs — IdentifyOrg checkout preparation
 * Payments are intentionally disabled until secure server-side
 * provider integration and verification are completed.
 */

export async function onRequestPost({ request }) {
  const contentType = request.headers.get("content-type") || "";

  if (!contentType.includes("application/json")) {
    return json({ message: "Send a JSON request." }, 415);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ message: "Invalid JSON request." }, 400);
  }

  const amount = Number(body?.amount);
  const methods = ["transfer", "card", "ussd"];

  if (
    !Number.isSafeInteger(amount) ||
    amount < 100 ||
    amount > 5000000
  ) {
    return json({
      message: "Amount must be between ₦100 and ₦5,000,000."
    }, 400);
  }

  if (
    body?.currency !== "NGN" ||
    !methods.includes(body?.paymentMethod)
  ) {
    return json({
      message: "Unsupported currency or payment method."
    }, 400);
  }

  return json({
    code: "PAYMENTS_NOT_CONFIGURED",
    message: "Secure checkout is not activated yet."
  }, 503);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
