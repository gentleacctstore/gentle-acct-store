
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




/* CUSTOMER CHECKOUT: REAL SPENCER PURCHASE */
function fsValue(v) {
  if (!v || typeof v !== "object") return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return Number(v.doubleValue);
  if ("booleanValue" in v) return v.booleanValue;
  if ("timestampValue" in v) return v.timestampValue;
  return null;
}
function fsNumber(n) {
  return Number.isInteger(n) ? { integerValue: String(n) } : { doubleValue: n };
}
async function fsGet(projectId, token, collection, id) {
  const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${collection}/${encodeURIComponent(id)}`;
  const r = await fetch(url, { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) return { response: r };
  return { document: await r.json() };
}
async function fsCommit(projectId, token, writes) {
  const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents:commit`;
  return fetch(url, {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ writes })
  });
}
async function handleCustomerSpencerPurchase(request, env) {
  const origin = request.headers.get("Origin");
  if (origin !== ALLOWED_ORIGIN) return supplierJson({ error: "Origin not allowed" }, 403, null);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400", Vary: "Origin"
  }});
  if (request.method !== "POST") return supplierJson({ error: "POST required" }, 405, origin);
  if (!env.SPENCER_API_KEY || !env.FCM_SERVICE_ACCOUNT_JSON) return supplierJson({ error: "Supplier checkout is not configured" }, 503, origin);
  const auth = request.headers.get("Authorization") || "";
  const idToken = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!idToken) return supplierJson({ error: "Sign in before purchasing" }, 401, origin);
  let body;
  try { body = await request.json(); } catch { return supplierJson({ error: "Invalid JSON" }, 400, origin); }
  const productId = String(body.productId || "");
  const requestId = String(body.requestId || "");
  if (!/^[A-Za-z0-9_-]{1,150}$/.test(productId) || !/^[A-Za-z0-9_-]{12,150}$/.test(requestId)) {
    return supplierJson({ error: "Invalid product or purchase reference" }, 400, origin);
  }
  const lookup = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(FIREBASE_API_KEY), {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken })
  });
  if (!lookup.ok) return supplierJson({ error: "Your sign-in session has expired. Sign in again." }, 401, origin);
  const user = (await lookup.json()).users?.[0];
  if (!user?.localId) return supplierJson({ error: "Customer authentication failed" }, 401, origin);
  let sa;
  try { sa = JSON.parse(env.FCM_SERVICE_ACCOUNT_JSON); } catch { return supplierJson({ error: "Firebase service configuration is invalid" }, 500, origin); }
  if (!sa.project_id || !sa.client_email || !sa.private_key) return supplierJson({ error: "Firebase service configuration is incomplete" }, 500, origin);
  const token = await getGoogleAccessToken(sa);
  const [productResult, walletResult, existingResult] = await Promise.all([
    fsGet(sa.project_id, token, "products", productId),
    fsGet(sa.project_id, token, "wallets", user.localId),
    fsGet(sa.project_id, token, "orders", requestId)
  ]);
  if (existingResult.document) {
    const f = existingResult.document.fields || {};
    if (fsValue(f.userId) !== user.localId) return supplierJson({ error: "Purchase reference conflict" }, 409, origin);
    if (fsValue(f.status) === "completed") return supplierJson({ success: true, orderId: requestId, purchaseText: fsValue(f.purchaseText) || "", balance: null, alreadyCompleted: true }, 200, origin);
    return supplierJson({ error: "This purchase is already being processed. Check your orders before trying again.", orderId: requestId, pending: true }, 202, origin);
  }
  if (!productResult.document) return supplierJson({ error: "Product not found" }, 404, origin);
  if (!walletResult.document) return supplierJson({ error: "Your wallet was not found" }, 404, origin);
  const pf = productResult.document.fields || {};
  const wf = walletResult.document.fields || {};
  if (fsValue(pf.supplierProvider) !== "spenceraccstore") return supplierJson({ error: "This is not a Spencer-supplied product" }, 400, origin);
  const supplierProductId = Number(fsValue(pf.supplierProductId));
  const price = Number(fsValue(pf.price));
  const stock = Number(fsValue(pf.stockCount) || 0);
  const balance = Number(fsValue(wf.balance) || 0);
  if (!Number.isSafeInteger(supplierProductId) || supplierProductId < 1 || !Number.isFinite(price) || price <= 0) return supplierJson({ error: "Product supplier details or selling price are invalid" }, 409, origin);
  if (stock <= 0 || fsValue(pf.supplierInStock) === false) return supplierJson({ error: "This product is currently out of stock" }, 409, origin);
  if (balance < price) return supplierJson({ error: "Insufficient wallet balance" }, 402, origin);
  const orderId = requestId;
  const newBalance = Number((balance - price).toFixed(2));
  const now = new Date().toISOString();
  const orderName = `projects/${sa.project_id}/databases/(default)/documents/orders/${orderId}`;
  const walletName = `projects/${sa.project_id}/databases/(default)/documents/wallets/${user.localId}`;
  const reserve = await fsCommit(sa.project_id, token, [
    { update: { name: walletName, fields: {
      balance: fsNumber(newBalance), updatedAt: { timestampValue: now }, lastOrderId: { stringValue: orderId }
    }}, updateMask: { fieldPaths: ["balance", "updatedAt", "lastOrderId"] }, currentDocument: { updateTime: walletResult.document.updateTime } },
    { update: { name: orderName, fields: {
      userId: { stringValue: user.localId }, userEmail: { stringValue: user.email || "" },
      productId: { stringValue: productId }, productName: { stringValue: fsValue(pf.name) || "" },
      amount: fsNumber(price), status: { stringValue: "supplier_processing" },
      supplierProvider: { stringValue: "spenceraccstore" }, createdAt: { timestampValue: now },
      purchaseReference: { stringValue: orderId }
    }}, currentDocument: { exists: false } }
  ]);
  if (!reserve.ok) return supplierJson({ error: "Your wallet or product changed. Refresh checkout and try again." }, 409, origin);
  let upstream;
  try {
    upstream = await fetch(SPENCER_API_BASE + "/api/v1/purchase", {
      method: "POST", headers: { Authorization: "Bearer " + env.SPENCER_API_KEY, Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ product_id: supplierProductId, quantity: 1 }), signal: AbortSignal.timeout(25000)
    });
  } catch (e) {
    console.error("Spencer purchase outcome is uncertain:", e);
    return supplierJson({ error: "Spencer is still processing this order. Your order is marked pending; do not purchase again yet.", orderId, pending: true }, 202, origin);
  }
  let payload;
  try { payload = await upstream.json(); } catch { payload = null; }
  const delivered = Array.isArray(payload?.delivered_items) ? payload.delivered_items : [];
  const success = upstream.ok && payload?.status === "success" && delivered.length > 0;
  if (!success) {
    // Only refund when Spencer explicitly confirms that the purchase failed.
    const explicitFailure = upstream.status >= 400 || payload?.status === "error" || payload?.status === "failed";
    if (!explicitFailure) return supplierJson({ error: "Supplier response could not confirm the result. Your order is pending review; do not retry yet.", orderId, pending: true }, 202, origin);
    const latestWallet = await fsGet(sa.project_id, token, "wallets", user.localId);
    if (latestWallet.document) {
      const latestBalance = Number(fsValue(latestWallet.document.fields?.balance) || 0);
      const refundCommit = await fsCommit(sa.project_id, token, [{ update: {
        name: walletName, fields: { balance: fsNumber(Number((latestBalance + price).toFixed(2))), updatedAt: { timestampValue: new Date().toISOString() } }
      }, updateMask: { fieldPaths: ["balance", "updatedAt"] }, currentDocument: { updateTime: latestWallet.document.updateTime } }]);
      if (!refundCommit.ok) console.error("Customer refund requires manual reconciliation for order", orderId);
    }
    const failedOrderUrl = `https://firestore.googleapis.com/v1/${orderName}?updateMask.fieldPaths=status&updateMask.fieldPaths=supplierMessage`;
    await fetch(failedOrderUrl, { method: "PATCH", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ fields: { status: { stringValue: "failed_refunded" }, supplierMessage: { stringValue: String(payload?.message || "Supplier rejected the purchase").slice(0, 400) } } }) });
    return supplierJson({ error: payload?.message || "Supplier could not complete this purchase. Your wallet has been refunded where the refund was confirmed." }, 502, origin);
  }
  const credentials = delivered.map(x => String(x.credentials || "").trim()).filter(Boolean);
  if (!credentials.length) return supplierJson({ error: "Supplier completed the purchase but returned no readable credentials. Order is pending support review.", orderId, pending: true }, 202, origin);
  const purchaseText = credentials.join("\n\n");
  const supplierOrderId = String(payload.order_details?.order_id || "");
  const finalUrl = `https://firestore.googleapis.com/v1/${orderName}?updateMask.fieldPaths=status&updateMask.fieldPaths=purchaseText&updateMask.fieldPaths=deliveredItems&updateMask.fieldPaths=supplierOrderId&updateMask.fieldPaths=supplierMessage&updateMask.fieldPaths=completedAt`;
  const finalResponse = await fetch(finalUrl, { method: "PATCH", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ fields: {
    status: { stringValue: "completed" }, purchaseText: { stringValue: purchaseText },
    deliveredItems: { arrayValue: { values: credentials.map(c => ({ stringValue: c })) } },
    supplierOrderId: { stringValue: supplierOrderId }, supplierMessage: { stringValue: String(payload.message || "Delivered").slice(0, 300) }, completedAt: { timestampValue: new Date().toISOString() }
  }}) });
  if (!finalResponse.ok) return supplierJson({ error: "Supplier delivered the product, but order saving is delayed. Contact support with order reference " + orderId, orderId, pending: true }, 202, origin);
  return supplierJson({ success: true, orderId, purchaseText, balance: newBalance, productName: fsValue(pf.name) || "Product" }, 200, origin);
}


/* AUTOMATIC SPENCER STOCK SYNCHRONISATION */
function firestoreFieldValue(value) {
  if (!value || typeof value !== "object") return null;
  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("booleanValue" in value) return value.booleanValue;
  if ("timestampValue" in value) return value.timestampValue;
  return null;
}

async function listFirestoreProducts(projectId, accessToken) {
  const all = [];
  let pageToken = "";
  do {
    const url = new URL(`https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/products`);
    url.searchParams.set("pageSize", "1000");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const response = await fetch(url, {
      headers: { Authorization: "Bearer " + accessToken }
    });
    const payload = await response.json();
    if (!response.ok) throw new Error("Could not read Gentle product records from Firestore");
    all.push(...(payload.documents || []));
    pageToken = payload.nextPageToken || "";
  } while (pageToken);
  return all;
}

async function syncSpencerStock(env) {
  if (!env.SPENCER_API_KEY) throw new Error("SPENCER_API_KEY is not configured");
  if (!env.FCM_SERVICE_ACCOUNT_JSON) throw new Error("FCM_SERVICE_ACCOUNT_JSON is not configured");

  let serviceAccount;
  try { serviceAccount = JSON.parse(env.FCM_SERVICE_ACCOUNT_JSON); }
  catch { throw new Error("FCM_SERVICE_ACCOUNT_JSON is invalid"); }
  if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) {
    throw new Error("The Firebase service account is missing required fields");
  }

  const accessToken = await getGoogleAccessToken(serviceAccount);
  const upstream = await fetch(SPENCER_API_BASE + "/api/v1/products", {
    headers: {
      Authorization: "Bearer " + env.SPENCER_API_KEY,
      Accept: "application/json"
    }
  });
  const contentType = upstream.headers.get("content-type") || "";
  const supplierPayload = contentType.includes("application/json") ? await upstream.json() : null;
  if (!upstream.ok || !supplierPayload || supplierPayload.status === "error") {
    throw new Error("Spencer did not return a valid product stock list");
  }

  const supplierList = Array.isArray(supplierPayload.products)
    ? supplierPayload.products
    : Array.isArray(supplierPayload.data)
      ? supplierPayload.data
      : null;
  if (!supplierList) throw new Error("Spencer product response format was not recognised; no stock was changed");

  const supplierById = new Map();
  for (const item of supplierList) {
    const id = Number(item.product_id);
    if (Number.isSafeInteger(id) && id > 0) supplierById.set(id, item);
  }

  const documents = await listFirestoreProducts(serviceAccount.project_id, accessToken);
  const imported = documents.filter(doc =>
    firestoreFieldValue(doc.fields?.supplierProvider) === "spenceraccstore"
  );

  let updated = 0;
  let missing = 0;
  const syncedAt = new Date().toISOString();
  for (const doc of imported) {
    const fields = doc.fields || {};
    const supplierId = Number(firestoreFieldValue(fields.supplierProductId));
    const supplierProduct = supplierById.get(supplierId);
    if (!supplierProduct) { missing++; continue; }

    const stock = Math.max(0, Math.floor(Number(supplierProduct.stock_count || 0)));
    const inStock = supplierProduct.in_stock === true && stock > 0;
    const documentName = doc.name;
    const patchUrl = new URL("https://firestore.googleapis.com/v1/" + documentName);
    ["stockCount", "supplierStockCount", "supplierInStock", "supplierSyncedAt", "updatedAt"].forEach(field =>
      patchUrl.searchParams.append("updateMask.fieldPaths", field)
    );
    const patch = await fetch(patchUrl, {
      method: "PATCH",
      headers: {
        Authorization: "Bearer " + accessToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        fields: {
          stockCount: { integerValue: String(stock) },
          supplierStockCount: { integerValue: String(stock) },
          supplierInStock: { booleanValue: inStock },
          supplierSyncedAt: { timestampValue: syncedAt },
          updatedAt: { timestampValue: syncedAt }
        }
      })
    });
    if (!patch.ok) {
      console.error("Stock sync failed for document", documentName, patch.status);
      continue;
    }
    updated++;
  }

  return { updated, missing, supplierProducts: supplierList.length, syncedAt };
}


/* XTRALOGS TOOLS — SECURE ADMIN CONNECTION AND PRICING SETTINGS */
const XTRALOGS_API_BASE = "https://xtralogstools.com/api/v1";

function xtraJson(data, status=200, origin=ALLOWED_ORIGIN) {
  const headers={"Content-Type":"application/json","Cache-Control":"no-store","Vary":"Origin","Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type, Authorization"};
  if(origin) headers["Access-Control-Allow-Origin"]=origin;
  return new Response(JSON.stringify(data),{status,headers});
}

async function xtraUpstream(env,path,method="GET",body,extraHeaders={}) {
  if(!env.XTRALOGS_API_KEY) throw new Error("XTRALOGS_API_KEY is not configured in Cloudflare Worker secrets.");
  const response=await fetch(XTRALOGS_API_BASE+path,{
    method,
    headers:{Authorization:"Bearer "+env.XTRALOGS_API_KEY,Accept:"application/json",...(body?{"Content-Type":"application/json"}:{}),...extraHeaders},
    ...(body?{body:JSON.stringify(body)}:{})
  });
  const type=response.headers.get("content-type")||"";
  let payload;
  try { payload=type.includes("application/json")?await response.json():{error:(await response.text()).slice(0,500)}; }
  catch { payload={error:"XtraLogs returned an unreadable response."}; }
  return {response,payload};
}

function xtraFirestoreDecode(value) {
  if(!value||typeof value!=="object") return value;
  if("stringValue" in value) return value.stringValue;
  if("integerValue" in value) return Number(value.integerValue);
  if("doubleValue" in value) return Number(value.doubleValue);
  if("booleanValue" in value) return value.booleanValue;
  if("timestampValue" in value) return value.timestampValue;
  if("mapValue" in value) return xtraFirestoreDecodeFields(value.mapValue.fields||{});
  if("arrayValue" in value) return (value.arrayValue.values||[]).map(xtraFirestoreDecode);
  return null;
}
function xtraFirestoreDecodeFields(fields) {
  const result={};
  for(const [key,value] of Object.entries(fields||{})) result[key]=xtraFirestoreDecode(value);
  return result;
}
function xtraFirestoreEncode(value) {
  if(value===null||value===undefined) return {nullValue:null};
  if(typeof value==="string") return {stringValue:value};
  if(typeof value==="boolean") return {booleanValue:value};
  if(typeof value==="number") return Number.isInteger(value)?{integerValue:String(value)}:{doubleValue:value};
  if(Array.isArray(value)) return {arrayValue:{values:value.map(xtraFirestoreEncode)}};
  if(typeof value==="object") {
    const fields={};
    for(const [key,item] of Object.entries(value)) fields[key]=xtraFirestoreEncode(item);
    return {mapValue:{fields}};
  }
  return {nullValue:null};
}

async function xtraGetPricing(env) {
  const sa=JSON.parse(env.FCM_SERVICE_ACCOUNT_JSON||"{}");
  if(!sa.project_id||!sa.client_email||!sa.private_key) throw new Error("Firebase service account is not configured.");
  const token=await getGoogleAccessToken(sa);
  const url=`https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sa.project_id)}/databases/(default)/documents/storeSettings/xtralogsPricing`;
  const response=await fetch(url,{headers:{Authorization:"Bearer "+token}});
  if(response.status===404) return {pricingMode:"automatic",defaultMarginPercent:20,overrides:{}};
  if(!response.ok) throw new Error("Could not read XtraLogs pricing settings from Firestore.");
  const doc=await response.json();
  return xtraFirestoreDecodeFields(doc.fields||{});
}

async function xtraSavePricing(env,settings) {
  const sa=JSON.parse(env.FCM_SERVICE_ACCOUNT_JSON||"{}");
  if(!sa.project_id||!sa.client_email||!sa.private_key) throw new Error("Firebase service account is not configured.");
  const token=await getGoogleAccessToken(sa);
  const url=new URL(`https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sa.project_id)}/databases/(default)/documents/storeSettings/xtralogsPricing`);
  ["pricingMode","defaultMarginPercent","overrides","updatedAt"].forEach(k=>url.searchParams.append("updateMask.fieldPaths",k));
  const fields={
    pricingMode:xtraFirestoreEncode(settings.pricingMode),
    defaultMarginPercent:xtraFirestoreEncode(settings.defaultMarginPercent),
    overrides:xtraFirestoreEncode(settings.overrides||{}),
    updatedAt:{timestampValue:new Date().toISOString()}
  };
  const response=await fetch(url,{method:"PATCH",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({fields})});
  if(!response.ok) throw new Error("Could not save XtraLogs pricing settings to Firestore.");
  return true;
}

const XTRALOGS_CATALOGS={
  "numbers-usa":"/catalog/numbers?scope=usa",
  "numbers-global":"/catalog/numbers?scope=global",
  "logs":"/catalog/logs",
  "smm":"/catalog/smm?page=1&per_page=80",
  "telegram":"/catalog/telegram",
  "esim":"/catalog/esim",
  "topup":"/catalog/topup",
  "gifts":"/catalog/gifts",
  "proxies":"/catalog/proxies",
  "vtu":"/catalog/vtu"
};

async function handleXtraLogs(request,env) {
  const origin=request.headers.get("Origin");
  if(origin&&origin!==ALLOWED_ORIGIN) return xtraJson({error:"Origin not allowed"},403,null);
  if(request.method==="OPTIONS") return new Response(null,{status:204,headers:{"Access-Control-Allow-Origin":ALLOWED_ORIGIN,"Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type, Authorization","Access-Control-Max-Age":"86400","Vary":"Origin"}});
  const auth=await verifySupplierAdmin(request);
  if(!auth.ok) return auth.response;
  if(request.method==="GET"&&new URL(request.url).pathname==="/api/xtralogs/admin/balance") {
    if(!env.XTRALOGS_API_KEY) return xtraJson({error:"XTRALOGS_API_KEY is not configured in Cloudflare Worker secrets."},503,origin);
    const result=await xtraUpstream(env,"/balance");
    const payload=result.payload;
    const balanceKeys=["balance","available_balance","wallet_balance","current_balance","account_balance","credits"];
    const minorKeys=["balance_minor","available_balance_minor","wallet_balance_minor","current_balance_minor","balance_kobo"];
    function findXtraBalance(value,depth=0) {
      if(!value || typeof value!=="object" || depth>5) return null;
      for(const key of balanceKeys) {
        if(value[key]!==undefined && value[key]!==null && value[key]!=="" && Number.isFinite(Number(value[key]))) {
          return {amount:Number(value[key]),currency:String(value.currency||value.currency_code||"NGN").toUpperCase(),source:key};
        }
      }
      for(const key of minorKeys) {
        if(value[key]!==undefined && value[key]!==null && value[key]!=="" && Number.isFinite(Number(value[key]))) {
          return {amount:Number(value[key])/100,currency:String(value.currency||value.currency_code||"NGN").toUpperCase(),source:key};
        }
      }
      for(const key of ["data","result","wallet","account","balance_info","payload"]) {
        const found=findXtraBalance(value[key],depth+1);
        if(found) return found;
      }
      return null;
    }
    const balanceInfo=findXtraBalance(payload);
    return xtraJson({...((payload&&typeof payload==="object"&&!Array.isArray(payload))?payload:{data:payload}),balanceInfo},result.response.status,origin);
  }
  if(request.method==="GET"&&new URL(request.url).pathname==="/api/xtralogs/admin/catalog") {
    if(!env.XTRALOGS_API_KEY) return xtraJson({error:"XTRALOGS_API_KEY is not configured in Cloudflare Worker secrets."},503,origin);
    const url=new URL(request.url);
    const key=url.searchParams.get("catalog")||"";
    let endpoint=XTRALOGS_CATALOGS[key];
    if(!endpoint) return xtraJson({error:"Unknown XtraLogs catalogue. Choose a supported catalogue."},400,origin);
    const allowedParams={country:["country"],page:["page"],per_page:["per_page"],service:["service"],username:["username"],quantity:["quantity"],network:["network"],kind:["kind"],type_id:["type_id"],number:["number"]};
    const query=new URLSearchParams(endpoint.split("?")[1]||"");
    for(const [name,allowed] of Object.entries(allowedParams)) {
      const value=url.searchParams.get(name);
      if(value!==null&&allowed.includes(name)&&/^[A-Za-z0-9._-]{1,80}$/.test(value)) query.set(name,value);
    }
    const path=endpoint.split("?")[0]+(query.size?"?"+query.toString():"");
    const result=await xtraUpstream(env,path);
    return xtraJson(result.payload,result.response.status,origin);
  }
  if(request.method==="GET"&&new URL(request.url).pathname==="/api/xtralogs/admin/pricing") {
    const settings=await xtraGetPricing(env);
    return xtraJson({success:true,settings},200,origin);
  }
  if(request.method==="POST"&&new URL(request.url).pathname==="/api/xtralogs/admin/pricing") {
    let body;
    try{body=await request.json();}catch{return xtraJson({error:"Invalid JSON"},400,origin);}
    const mode=body.pricingMode==="manual"?"manual":"automatic";
    const margin=Number(body.defaultMarginPercent);
    if(!Number.isFinite(margin)||margin<0||margin>500) return xtraJson({error:"Default profit percentage must be between 0 and 500."},400,origin);
    const overrides=body.overrides&&typeof body.overrides==="object"&&!Array.isArray(body.overrides)?body.overrides:{};
    const clean={};
    for(const [key,item] of Object.entries(overrides).slice(0,3000)) {
      if(!/^[a-z0-9-]{1,30}:[A-Za-z0-9._-]{1,100}$/i.test(key)||!item||typeof item!=="object") continue;
      const price=Number(item.sellingPrice);
      if(!Number.isFinite(price)||price<0||price>100000000) continue;
      clean[key]={sellingPrice:price,enabled:item.enabled!==false,currency:String(item.currency||"NGN").slice(0,8)};
    }
    await xtraSavePricing(env,{pricingMode:mode,defaultMarginPercent:margin,overrides:clean});
    return xtraJson({success:true,message:"XtraLogs pricing settings saved.",settings:{pricingMode:mode,defaultMarginPercent:margin,overrides:clean}},200,origin);
  }
  return xtraJson({error:"Unknown XtraLogs admin operation."},404,origin);
}


/* XTRALOGS CUSTOMER MARKETPLACE */
function xtraExtractCatalogItems(data,depth=0) {
  if(Array.isArray(data)) return data;
  if(!data || typeof data!=="object" || depth>5) return [];
  const keys=["services","products","items","countries","plans","operators","results","records","list"];
  for(const key of keys) if(Array.isArray(data[key])) return data[key];
  for(const key of ["data","result","payload","catalog","response"]) {
    const found=xtraExtractCatalogItems(data[key],depth+1);
    if(found.length) return found;
  }
  return [];
}
function xtraCatalogIdentity(item) {
  const id=item.service_id??item.product_id??item.item_id??item.id??item.package_id??item.operator_id;
  return id===undefined||id===null?"":String(id);
}
function xtraCatalogCost(item) {
  if(item.rank_price_minor!==undefined) return {amount:Number(item.rank_price_minor)/100,currency:"NGN"};
  if(item.price_minor!==undefined) return {amount:Number(item.price_minor)/100,currency:"NGN"};
  if(item.price!==undefined) return {amount:Number(item.price),currency:String(item.currency||"NGN").toUpperCase()};
  if(item.price_usd!==undefined) return {amount:Number(item.price_usd),currency:"USD"};
  return {amount:0,currency:String(item.currency||"NGN").toUpperCase()};
}
async function xtraCustomerIdentity(request) {
  const origin=request.headers.get("Origin");
  if(origin && origin!==ALLOWED_ORIGIN) return {error:supplierJson({error:"Origin not allowed"},403,null)};
  const auth=request.headers.get("Authorization")||"";
  const idToken=auth.startsWith("Bearer ")?auth.slice(7):"";
  if(!idToken) return {error:supplierJson({error:"Sign in before continuing"},401,origin)};
  const lookup=await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key="+encodeURIComponent(FIREBASE_API_KEY),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({idToken})});
  if(!lookup.ok) return {error:supplierJson({error:"Your sign-in session has expired. Sign in again."},401,origin)};
  const user=(await lookup.json()).users?.[0];
  if(!user?.localId) return {error:supplierJson({error:"Customer authentication failed"},401,origin)};
  return {user,origin};
}
async function xtraCustomerFirebase(env) {
  let sa;try{sa=JSON.parse(env.FCM_SERVICE_ACCOUNT_JSON||"{}");}catch{}
  if(!sa?.project_id||!sa?.client_email||!sa?.private_key) throw new Error("Firebase service configuration is incomplete.");
  return {sa,token:await getGoogleAccessToken(sa)};
}
function xtraSellingPrice(item,catalog,settings) {
  const id=xtraCatalogIdentity(item),key=catalog+":"+id,cost=xtraCatalogCost(item),override=settings.overrides?.[key];
  if(override&&override.enabled!==false&&Number.isFinite(Number(override.sellingPrice))) return {price:Number(override.sellingPrice),currency:String(override.currency||cost.currency).toUpperCase(),cost,key};
  return {price:Number((cost.amount*(1+Number(settings.defaultMarginPercent??20)/100)).toFixed(2)),currency:cost.currency,cost,key};
}
async function handleXtraCustomer(request,env) {
  const origin=request.headers.get("Origin");
  if(origin && origin!==ALLOWED_ORIGIN)return xtraJson({error:"Origin not allowed"},403,null);
  if(request.method==="OPTIONS") return new Response(null,{status:204,headers:{"Access-Control-Allow-Origin":ALLOWED_ORIGIN,"Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type, Authorization","Access-Control-Max-Age":"86400","Vary":"Origin"}});
  const auth=await xtraCustomerIdentity(request);if(auth.error)return auth.error;
  const {user}=auth;const url=new URL(request.url);const {sa,token}=await xtraCustomerFirebase(env);
  if(request.method==="GET"&&url.pathname==="/api/xtralogs/customer/catalog") {
    const catalog=url.searchParams.get("catalog")||"logs";const endpoint=XTRALOGS_CATALOGS[catalog];
    if(!endpoint)return xtraJson({error:"Unknown catalogue"},400,origin);
    const query=new URLSearchParams(endpoint.split("?")[1]||"");
    for(const key of ["country","page","per_page","service","username","quantity","network","kind","type_id","number"]){const v=url.searchParams.get(key);if(v&&/^[A-Za-z0-9._-]{1,80}$/.test(v))query.set(key,v);}
    const upstream=await xtraUpstream(env,endpoint.split("?")[0]+(query.size?"?"+query.toString():""));
    if(!upstream.response.ok)return xtraJson({error:upstream.payload?.message||upstream.payload?.error||"Could not load this catalogue."},upstream.response.status,origin);
    const items=xtraExtractCatalogItems(upstream.payload);const settings=await xtraGetPricing(env);
    if(catalog==="numbers-global"&&!url.searchParams.get("country")){
      const countries=items.map(item=>{
        if(typeof item==="string"){
          const code=item.length===2?item.toUpperCase():"";
          return {code,name:item};
        }
        const code=String(item.iso2??item.iso_code??item.country_code??item.code??item.country_iso??"").toUpperCase();
        const name=String(item.country_name??item.name??item.country??item.title??item.label??code);
        return {code,name};
      }).filter(x=>x.code&&/^[A-Z]{2}$/.test(x.code));
      return xtraJson({success:true,catalog,countries},200,origin);
    }
    const products=items.map(item=>{const p=xtraSellingPrice(item,catalog,settings);return {id:xtraCatalogIdentity(item),name:String(item.name??item.title??item.service_name??item.product_name??item.package_name??item.operator_name??"XtraLogs service"),description:String(item.description??item.details??""),price:p.price,currency:p.currency,available:item.available!==false&&item.in_stock!==false,category:catalog,raw:item};}).filter(x=>x.id);
    return xtraJson({success:true,catalog,products},200,origin);
  }
  if(request.method==="POST"&&url.pathname==="/api/xtralogs/customer/purchase") {
    let body;try{body=await request.json();}catch{return xtraJson({error:"Invalid purchase request"},400,origin);}
    const catalog=String(body.catalog||""),itemId=String(body.itemId||""),requestId=String(body.requestId||"");
    if(!XTRALOGS_CATALOGS[catalog]||!itemId||!/^[A-Za-z0-9_-]{16,100}$/.test(requestId))return xtraJson({error:"Invalid service or purchase reference"},400,origin);
    if(!["logs","numbers-usa","numbers-global","smm"].includes(catalog))return xtraJson({error:"Checkout for this service category is being prepared. Please try Logs, USA Numbers, World Numbers or Boosting first."},409,origin);
    const catalogQuery=new URLSearchParams(XTRALOGS_CATALOGS[catalog].split("?")[1]||"");
    if(catalog==="numbers-global"&&body.country)catalogQuery.set("country",String(body.country).toUpperCase());
    const {response:catalogResponse,payload:catalogPayload}=await xtraUpstream(env,XTRALOGS_CATALOGS[catalog].split("?")[0]+(catalogQuery.size?"?"+catalogQuery.toString():""));
    if(!catalogResponse.ok)return xtraJson({error:"Could not verify the latest supplier price. Please try again."},502,origin);
    const item=xtraExtractCatalogItems(catalogPayload).find(x=>xtraCatalogIdentity(x)===itemId);
    if(!item)return xtraJson({error:"This service is no longer available. Refresh the catalogue."},404,origin);
    const settings=await xtraGetPricing(env),selling=xtraSellingPrice(item,catalog,settings);
    if(!Number.isFinite(selling.price)||selling.price<=0||selling.currency!=="NGN")return xtraJson({error:"This service does not have a valid NGN selling price configured yet."},409,origin);
    const wallet=await fsGet(sa.project_id,token,"wallets",user.localId);
    if(!wallet.document)return xtraJson({error:"Your GentleLogs wallet was not found."},404,origin);
    const wf=wallet.document.fields||{},balance=Number(fsValue(wf.balance)||0);
    if(balance<selling.price)return xtraJson({error:"Insufficient GentleLogs wallet balance. Please add funds."},402,origin);
    const orderId=requestId,orderName=`projects/${sa.project_id}/databases/(default)/documents/xtralogsOrders/${orderId}`,walletName=`projects/${sa.project_id}/databases/(default)/documents/wallets/${user.localId}`;
    const existing=await fsGet(sa.project_id,token,"xtralogsOrders",orderId);
    if(existing.document)return xtraJson({error:"This purchase reference has already been used. Refresh your orders."},409,origin);
    const nextBalance=Number((balance-selling.price).toFixed(2)),now=new Date().toISOString();
    const reserve=await fsCommit(sa.project_id,token,[
      {update:{name:walletName,fields:{balance:fsNumber(nextBalance),updatedAt:{timestampValue:now},lastXtraLogsOrderId:{stringValue:orderId}}},updateMask:{fieldPaths:["balance","updatedAt","lastXtraLogsOrderId"]},currentDocument:{updateTime:wallet.document.updateTime}},
      {update:{name:orderName,fields:{userId:{stringValue:user.localId},userEmail:{stringValue:user.email||""},catalog:{stringValue:catalog},itemId:{stringValue:itemId},serviceName:{stringValue:String(item.name??item.title??item.service_name??"XtraLogs service")},amount:fsNumber(selling.price),currency:{stringValue:selling.currency},status:{stringValue:"processing"},createdAt:{timestampValue:now},requestId:{stringValue:orderId}}},currentDocument:{exists:false}}
    ]);
    if(!reserve.ok)return xtraJson({error:"Your wallet changed while checkout was processing. Refresh and try again."},409,origin);
    let supplierBody;
    if(catalog==="logs")supplierBody={type:"logs",product_id:Number(itemId),quantity:1};
    if(catalog==="numbers-usa"||catalog==="numbers-global")supplierBody={type:"numbers",service_id:Number(itemId)};
    if(catalog==="smm")supplierBody={type:"smm",item_id:Number(itemId),quantity:Number(body.quantity||1),payload:{link:String(body.link||"")}};
    let upstream;
    try { upstream=await xtraUpstream(env,"/orders","POST",supplierBody,{"Idempotency-Key":requestId}); }
    catch(error) { console.error("XtraLogs order outcome uncertain:",error); return xtraJson({success:true,pending:true,orderId,message:"The supplier response is taking longer than expected. Your order is marked processing; do not submit it again."},202,origin); }
    const supplierData=upstream.payload||{};
    if(!upstream.response.ok) {
      // Only refund for a definite supplier rejection; uncertain outcomes stay pending.
      if(upstream.response.status>=400&&upstream.response.status!==429) {
        const latest=await fsGet(sa.project_id,token,"wallets",user.localId);
        if(latest.document){const latestBalance=Number(fsValue(latest.document.fields?.balance)||0);await fsCommit(sa.project_id,token,[{update:{name:walletName,fields:{balance:fsNumber(Number((latestBalance+selling.price).toFixed(2))),updatedAt:{timestampValue:new Date().toISOString()}}},updateMask:{fieldPaths:["balance","updatedAt"]},currentDocument:{updateTime:latest.document.updateTime}}]);}
        const patch=`https://firestore.googleapis.com/v1/${orderName}?updateMask.fieldPaths=status&updateMask.fieldPaths=supplierMessage`;
        await fetch(patch,{method:"PATCH",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({fields:{status:{stringValue:"failed_refunded"},supplierMessage:{stringValue:String(supplierData.message||supplierData.error||"Supplier rejected the order").slice(0,300)}}})});
        return xtraJson({error:supplierData.message||supplierData.error||"Supplier rejected the order. Your GentleLogs wallet has been refunded."},502,origin);
      }
      return xtraJson({success:true,pending:true,orderId,message:"Your order is processing. Check XtraLogs Orders for updates."},202,origin);
    }
    const supplierOrder=supplierData.order||supplierData.data||supplierData;
    const supplierOrderId=String(supplierOrder.order_id??supplierOrder.id??supplierData.order_id??"");
    const sessionId=String(supplierData.session?.id??supplierOrder.session?.id??"");
    const status=String(supplierData.status||supplierOrder.status||"processing");
    const purchaseText=String(supplierData.credentials??supplierData.code??supplierData.number??supplierData.result??"");
    const patch=`https://firestore.googleapis.com/v1/${orderName}?updateMask.fieldPaths=status&updateMask.fieldPaths=supplierOrderId&updateMask.fieldPaths=sessionId&updateMask.fieldPaths=purchaseText&updateMask.fieldPaths=supplierResponse`;
    await fetch(patch,{method:"PATCH",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({fields:{status:{stringValue:status},supplierOrderId:{stringValue:supplierOrderId},sessionId:{stringValue:sessionId},purchaseText:{stringValue:purchaseText},supplierResponse:{stringValue:JSON.stringify(supplierData).slice(0,2500)}}})});
    return xtraJson({success:true,pending:true,orderId,message:"Your order was submitted successfully. Check XtraLogs Orders for delivery and status."},200,origin);
  }
  if(request.method==="GET"&&url.pathname==="/api/xtralogs/customer/orders") {
    const queryUrl=`https://firestore.googleapis.com/v1/projects/${encodeURIComponent(sa.project_id)}/databases/(default)/documents:runQuery`;
    const query={structuredQuery:{from:[{collectionId:"xtralogsOrders"}],where:{fieldFilter:{field:{fieldPath:"userId"},op:"EQUAL",value:{stringValue:user.localId}}},limit:100}};
    const response=await fetch(queryUrl,{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify(query)});
    if(!response.ok)return xtraJson({error:"Could not load your XtraLogs orders."},502,origin);
    const rows=await response.json();const orders=(rows||[]).filter(x=>x.document).map(x=>{const f=x.document.fields||{};return {id:x.document.name.split("/").pop(),catalog:fsValue(f.catalog),itemId:fsValue(f.itemId),serviceName:fsValue(f.serviceName),amount:fsValue(f.amount),currency:fsValue(f.currency),status:fsValue(f.status),createdAt:fsValue(f.createdAt),purchaseText:fsValue(f.purchaseText),supplierOrderId:fsValue(f.supplierOrderId),sessionId:fsValue(f.sessionId),supplierMessage:fsValue(f.supplierMessage)};}).sort((a,b)=>String(b.createdAt||"").localeCompare(String(a.createdAt||"")));
    return xtraJson({success:true,orders},200,origin);
  }
  return xtraJson({error:"Unknown XtraLogs customer operation."},404,origin);
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        const result = await syncSpencerStock(env);
        console.log("Spencer stock sync completed:", JSON.stringify(result));
      } catch (error) {
        console.error("Spencer stock sync failed:", error);
      }
    })());
  },

  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/xtralogs/customer/")) {
      try { return await handleXtraCustomer(request, env); }
      catch (error) { console.error("XtraLogs customer API error:", error); return xtraJson({ error: error.message || "XtraLogs customer service failed" }, 500, request.headers.get("Origin")); }
    }

    if (url.pathname.startsWith("/api/xtralogs/admin/")) {
      try { return await handleXtraLogs(request, env); }
      catch (error) {
        console.error("XtraLogs admin API error:", error);
        return xtraJson({ error: error.message || "XtraLogs service failed" }, 500, request.headers.get("Origin"));
      }
    }

    if (url.pathname === "/api/customer/spencer-purchase") {
      try { return await handleCustomerSpencerPurchase(request, env); }
      catch (error) {
        console.error("Customer Spencer checkout error:", error);
        return supplierJson({ error: "Purchase service encountered an error. Check your orders before retrying." }, 500, request.headers.get("Origin"));
      }
    }

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
