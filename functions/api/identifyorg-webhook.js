
/**
 * GentleLogs — IdentifyOrg webhook endpoint
 *
 * SAFETY MODE:
 * This endpoint does not accept or trust payment notifications yet.
 * It must not credit wallets until the provider's official webhook
 * signature verification and payment verification are implemented.
 */

export async function onRequestPost({ request }) {
  const contentType = request.headers.get("content-type") || "";

  if (!contentType.includes("application/json")) {
    return json({
      message: "Invalid content type."
    }, 415);
  }

  return json({
    code: "WEBHOOK_NOT_CONFIGURED",
    message: "Payment verification is not configured yet. No wallet was credited."
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
