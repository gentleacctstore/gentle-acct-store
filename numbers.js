/**
 * Gentle Acct Store
 * Cloudflare Pages Function
 * XtraLogsTools number catalogue
 *
 * Required Cloudflare secret:
 * XTRALOGSTOOLS_API_KEY
 */
const API_BASE = "https://xtralogstools.com/api/v1";
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
export async function onRequestGet({ request, env }) {
  try {
    const apiKey = env.XTRALOGSTOOLS_API_KEY;
    if (!apiKey) {
      return jsonResponse({
        success: false,
        message: "Number service is not configured yet."
      }, 503);
    }
    const url = new URL(request.url);
    const scope = url.searchParams.get("scope") || "usa";
    const country = url.searchParams.get("country");
    // Only allow documented catalogue scopes.
    if (!["usa", "global"].includes(scope)) {
      return jsonResponse({
        success: false,
        message: "Invalid catalogue scope."
      }, 400);
    }
    if (
      country &&
      (!/^[a-zA-Z -]{2,56}$/.test(country))
    ) {
      return jsonResponse({
        success: false,
        message: "Invalid country value."
      }, 400);
    }
    const apiUrl = new URL(
      API_BASE + "/catalog/numbers"
    );
    apiUrl.searchParams.set("scope", scope);
    if (country && scope === "global") {
      apiUrl.searchParams.set("country", country);
    }
    const response = await fetch(apiUrl.toString(), {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Authorization": "Bearer " + apiKey
      },
      signal: AbortSignal.timeout(20000)
    });
    const result = await response.json().catch(() => null);
    if (!response.ok || !result) {
      console.error(
        "XtraLogsTools catalogue request failed:",
        response.status
      );
      return jsonResponse({
        success: false,
        message: "Unable to retrieve number services."
      }, 502);
    }
    // Return only catalogue information, never credentials.
    return jsonResponse({
      success: true,
      scope,
      data: result
    });
  } catch (error) {
    console.error(
      "Number catalogue error:",
      error?.message || "Unknown error"
    );
    return jsonResponse({
      success: false,
      message: "The number service is temporarily unavailable."
    }, 502);
  }
}