
const ALLOWED_ORIGIN = "https://gentlelogs.pages.dev";
const ADMIN_UID = "UoEjCy99gbQKkGob59vGi3CunZi1";
const FIREBASE_API_KEY = "AIzaSyAhF6gcjPMqaHA5d1ZlKbaJdDBXOqGPlrg";

function json(data, status = 200, origin = ALLOWED_ORIGIN) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };

  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function base64url(value) {
  const bytes = typeof value === "string"
    ? new TextEncoder().encode(value)
    : new Uint8Array(value);

  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function pemBytes(pem) {
  const cleaned = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function getGoogleAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);

  const header = base64url(JSON.stringify({
    alg: "RS256",
    typ: "JWT"
  }));

  const claims = base64url(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  }));

  const unsigned = header + "." + claims;

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pemBytes(serviceAccount.private_key),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(unsigned)
  );

  const assertion = unsigned + "." + base64url(signature);

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion
      })
    }
  );

  const result = await response.json();

  if (!response.ok || !result.access_token) {
    console.error("Google access token request failed:", response.status);
    throw new Error("Google authentication failed");
  }

  return result.access_token;
}

async function handleNotification(request, env) {
  // Allow a missing Origin for direct requests, but reject a different origin.
  const origin = request.headers.get("Origin");

  if (origin && origin !== ALLOWED_ORIGIN) {
    return json({ error: "Origin not allowed" }, 403);
  }

  if (request.method !== "POST") {
    return json({ error: "POST required" }, 405);
  }

  if (!env.FCM_SERVICE_ACCOUNT_JSON || !env.ADMIN_FCM_TOKEN) {
    return json({ error: "Notification secrets are missing" }, 500);
  }

  const authorization = request.headers.get("Authorization") || "";
  const idToken = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!idToken) {
    return json({ error: "Sign-in token required" }, 401);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const requestId = body.requestId;

  if (
    typeof requestId !== "string" ||
    !/^[A-Za-z0-9_-]{1,150}$/.test(requestId)
  ) {
    return json({ error: "Invalid funding request ID" }, 400);
  }

  let serviceAccount;

  try {
    serviceAccount = JSON.parse(env.FCM_SERVICE_ACCOUNT_JSON);
  } catch {
    return json({ error: "Service account secret is invalid" }, 500);
  }

  if (
    !serviceAccount.project_id ||
    !serviceAccount.client_email ||
    !serviceAccount.private_key
  ) {
    return json({ error: "Service account fields are missing" }, 500);
  }

  // Verify the customer's Firebase ID token.
  const authResponse = await fetch(
    "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" +
      encodeURIComponent(FIREBASE_API_KEY),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    }
  );

  if (!authResponse.ok) {
    return json({ error: "Customer authentication failed" }, 401);
  }

  const authData = await authResponse.json();
  const user = authData.users && authData.users[0];

  if (!user || !user.emailVerified) {
    return json({ error: "Verified customer sign-in required" }, 403);
  }

  const accessToken = await getGoogleAccessToken(serviceAccount);
  const projectId = serviceAccount.project_id;

  // Read the funding request directly from Firestore.
  const documentUrl =
    "https://firestore.googleapis.com/v1/projects/" +
    encodeURIComponent(projectId) +
    "/databases/(default)/documents/fundingRequests/" +
    encodeURIComponent(requestId);

  const documentResponse = await fetch(documentUrl, {
    headers: { Authorization: "Bearer " + accessToken }
  });

  if (documentResponse.status === 404) {
    return json({ error: "Funding request not found" }, 404);
  }

  if (!documentResponse.ok) {
    console.error("Firestore request lookup failed:", documentResponse.status);
    return json({ error: "Could not verify funding request" }, 502);
  }

  const document = await documentResponse.json();
  const fields = document.fields || {};

  if (
    fields.userId?.stringValue !== user.localId ||
    fields.status?.stringValue !== "pending"
  ) {
    return json({ error: "Funding request does not match" }, 403);
  }

  if (fields.notificationSentAt) {
    return json({ message: "Notification already sent" });
  }

  // Send the push notification to the registered admin device.
  const fcmResponse = await fetch(
    "https://fcm.googleapis.com/v1/projects/" +
      encodeURIComponent(projectId) +
      "/messages:send",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer " + accessToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: {
          token: env.ADMIN_FCM_TOKEN,
          notification: {
            title: "New wallet funding request",
            body: "A customer submitted a funding request. Open Gentle Admin to review it."
          },
          data: {
            type: "funding_request",
            requestId
          },
          webpush: {
            notification: {
              icon: "/favicon.ico",
              tag: "funding-" + requestId
            },
            fcmOptions: {
              link: "/wallet-funding.html"
            }
          }
        }
      })
    }
  );

  if (!fcmResponse.ok) {
    const fcmError = await fcmResponse.text();
    console.error("FCM send failed:", fcmResponse.status, fcmError);
    return json({ error: "Firebase could not send the notification" }, 502);
  }

  // Record that a notification was sent for this request.
  const updateUrl = documentUrl +
    "?updateMask.fieldPaths=notificationSentAt";

  const updateResponse = await fetch(updateUrl, {
    method: "PATCH",
    headers: {
      Authorization: "Bearer " + accessToken,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      fields: {
        notificationSentAt: {
          timestampValue: new Date().toISOString()
        }
      }
    })
  });

  if (!updateResponse.ok) {
    console.error("Could not record notification status:", updateResponse.status);
    return json({
      message: "Notification sent, but its status could not be recorded"
    });
  }

  return json({ message: "Notification sent" });
}


const SPENCER_API_BASE = "https://www.spenceraccstore.com";

function supplierJson(data, status = 200, origin = ALLOWED_ORIGIN) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  };
  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  return new Response(JSON.stringify(data), { status, headers });
}

async function verifySupplierAdmin(request) {
  const origin = request.headers.get("Origin");
  if (origin && origin !== ALLOWED_ORIGIN) {
    return { ok: false, response: supplierJson({ error: "Origin not allowed" }, 403, null) };
  }

  const authorization = request.headers.get("Authorization") || "";
  const idToken = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!idToken) {
    return { ok: false, response: supplierJson({ error: "Admin sign-in required" }, 401, origin) };
  }

  const authResponse = await fetch(
    "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(FIREBASE_API_KEY),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    }
  );

  if (!authResponse.ok) {
    return { ok: false, response: supplierJson({ error: "Your admin session is invalid or expired" }, 401, origin) };
  }

  const authData = await authResponse.json();
  const user = authData.users && authData.users[0];
  if (!user || user.localId !== ADMIN_UID) {
    return { ok: false, response: supplierJson({ error: "This account is not authorised for supplier management" }, 403, origin) };
  }

  return { ok: true, origin };
}

async function handleSupplierApi(request, env) {
  const origin = request.headers.get("Origin");
  if (origin && origin !== ALLOWED_ORIGIN) {
    return supplierJson({ error: "Origin not allowed" }, 403, null);
  }
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin"
      }
    });
  }
  if (!env.SPENCER_API_KEY) {
    return supplierJson({ error: "Spencer API key is not configured in Cloudflare yet" }, 503, origin);
  }

  const auth = await verifySupplierAdmin(request);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/supplier\/?/, "");
  let endpoint = "";
  let method = "GET";
  let body;

  if (path === "balance" && request.method === "GET") {
    endpoint = "/api/v1/balance";
  } else if (path === "categories" && request.method === "GET") {
    endpoint = "/api/v1/categories";
  } else if (path === "products" && request.method === "GET") {
    endpoint = "/api/v1/products";
    const categoryId = url.searchParams.get("category_id");
    if (categoryId && /^\d+$/.test(categoryId)) endpoint += "?category_id=" + encodeURIComponent(categoryId);
  } else if (path === "order" && request.method === "GET") {
    endpoint = "/api/v1/order";
    const orderId = url.searchParams.get("order_id");
    const orderDbId = url.searchParams.get("order_db_id");
    const params = new URLSearchParams();
    if (orderId) params.set("order_id", orderId);
    if (orderDbId) params.set("order_db_id", orderDbId);
    if (![...params.keys()].length) return supplierJson({ error: "Provide order_id or order_db_id" }, 400, origin);
    endpoint += "?" + params.toString();
  } else if (path === "purchase" && request.method === "POST") {
    endpoint = "/api/v1/purchase";
    method = "POST";
    try { body = await request.json(); }
    catch { return supplierJson({ error: "Invalid JSON request" }, 400, origin); }
    const productId = Number(body.product_id);
    const quantity = body.quantity === undefined ? 1 : Number(body.quantity);
    if (!Number.isSafeInteger(productId) || productId < 1 || !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 100) {
      return supplierJson({ error: "A valid product_id and quantity between 1 and 100 are required" }, 400, origin);
    }
    const promoCode = typeof body.promo_code === "string" ? body.promo_code.trim() : "";
    body = { product_id: productId, quantity };
    if (promoCode) body.promo_code = promoCode;
  } else {
    return supplierJson({ error: "Unknown supplier API operation" }, 404, origin);
  }

  try {
    const upstream = await fetch(SPENCER_API_BASE + endpoint, {
      method,
      headers: {
        "Authorization": "Bearer " + env.SPENCER_API_KEY,
        "Accept": "application/json",
        ...(method === "POST" ? { "Content-Type": "application/json" } : {})
      },
      ...(method === "POST" ? { body: JSON.stringify(body) } : {})
    });
    const contentType = upstream.headers.get("content-type") || "";
    const payload = contentType.includes("application/json")
      ? await upstream.json()
      : { error: (await upstream.text()).slice(0, 500) || "Supplier returned an unreadable response" };
    return supplierJson(payload, upstream.status, origin);
  } catch (error) {
    console.error("Spencer supplier request failed:", error);
    return supplierJson({ error: "Could not connect to Spencer Acc Store" }, 502, origin);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/supplier/")) {
      try {
        return await handleSupplierApi(request, env);
      } catch (error) {
        console.error("Supplier API proxy error:", error);
        return supplierJson({ error: "Supplier service failed" }, 500, request.headers.get("Origin"));
      }
    }

    if (url.pathname === "/api/notify-funding") {
      const origin = request.headers.get("Origin");

      // Handle browser preflight requests.
      if (request.method === "OPTIONS") {
        if (origin !== ALLOWED_ORIGIN) {
          return json(
            { error: "Origin not allowed" },
            403,
            origin === ALLOWED_ORIGIN ? origin : null
          );
        }

        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400",
            "Vary": "Origin"
          }
        });
      }

      try {
        return await handleNotification(request, env);
      } catch (error) {
        console.error("Funding notification error:", error);
        return json({ error: "Notification service failed" }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
