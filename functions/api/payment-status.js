
/**
 * GentleLogs — Payment status endpoint
 *
 * SAFETY MODE:
 * Payment status cannot be confirmed until the secure
 * IdentifyOrg server-side integration is configured.
 */

export async function onRequestGet() {
  return json({
    code: "PAYMENT_STATUS_NOT_CONFIGURED",
    status: "unverified",
    message: "Payment confirmation is not available yet. Please do not assume your wallet has been credited."
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
