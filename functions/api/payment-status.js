
export async function onRequestGet({ env }) {
  if (!env.IDENTIFYORG_API_KEY) {
    return Response.json(
      { error: "IdentifyOrg API key is missing." },
      { status: 500 }
    );
  }

  try {
    const response = await fetch(
      "https://api.identifyorg.com/v1/business/overview",
      {
        method: "GET",
        headers: {
          "X-IdentifyOrg-Key": env.IDENTIFYORG_API_KEY
        }
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return Response.json(
        { error: data.message || data.error || "Unable to check account." },
        { status: response.status }
      );
    }

    return Response.json({
      status: data.status,
      live: data.live,
      business_verified: data.business_verified,
      limit: data.limit,
      remaining: data.remaining,
      balance: data.balance,
      fees: data.fees
    });

  } catch (error) {
    console.error("IdentifyOrg status error:", error);

    return Response.json(
      { error: "Could not connect to IdentifyOrg." },
      { status: 500 }
    );
  }
}
