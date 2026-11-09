const SPENCER_API_BASE = "https://www.spenceraccstore.com";
const FIREBASE_PROJECT_ID = "gentle-acct-store";

function base64url(value) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function pemBytes(pem) {
  const cleaned = pem.replace(/-----BEGIN PRIVATE KEY-----/g, "").replace(/-----END PRIVATE KEY-----/g, "").replace(/\s/g, "");
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function getGoogleAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64url(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  }));
  const unsigned = header + "." + claims;
  const privateKey = await crypto.subtle.importKey("pkcs8", pemBytes(serviceAccount.private_key), {
    name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"
  }, false, ["sign"]);
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(unsigned));
  const assertion = unsigned + "." + base64url(signature);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });
  const result = await response.json();
  if (!response.ok || !result.access_token) throw new Error("Google authentication failed: " + (result.error_description || result.error || response.status));
  return result.access_token;
}

function fieldValue(value) {
  if (!value || typeof value !== "object") return null;
  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("booleanValue" in value) return value.booleanValue;
  return null;
}

async function listProducts(accessToken) {
  const documents = [];
  let pageToken = "";
  do {
    const url = new URL(`https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/products`);
    url.searchParams.set("pageSize", "1000");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const response = await fetch(url, { headers: { Authorization: "Bearer " + accessToken } });
    const payload = await response.json();
    if (!response.ok) throw new Error("Firestore product read failed: " + (payload.error?.message || response.status));
    documents.push(...(payload.documents || []));
    pageToken = payload.nextPageToken || "";
  } while (pageToken);
  return documents;
}

async function runStockSync(env) {
  if (!env.SPENCER_API_KEY) throw new Error("Missing SPENCER_API_KEY secret");
  if (!env.FIREBASE_SERVICE_ACCOUNT_JSON) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON secret");

  let serviceAccount;
  try { serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON); }
  catch { throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON"); }
  if (!serviceAccount.client_email || !serviceAccount.private_key) throw new Error("Firebase service account email/private key is missing");

  const accessToken = await getGoogleAccessToken(serviceAccount);
  const supplierResponse = await fetch(SPENCER_API_BASE + "/api/v1/products", {
    headers: { Authorization: "Bearer " + env.SPENCER_API_KEY, Accept: "application/json" }
  });
  const supplierPayload = (supplierResponse.headers.get("content-type") || "").includes("application/json")
    ? await supplierResponse.json() : null;
  if (!supplierResponse.ok || !supplierPayload || supplierPayload.status === "error") {
    throw new Error("Spencer product request failed: " + supplierResponse.status);
  }
  const supplierProducts = Array.isArray(supplierPayload.products) ? supplierPayload.products
    : Array.isArray(supplierPayload.data) ? supplierPayload.data : null;
  if (!supplierProducts) throw new Error("Spencer returned an unexpected product list; no stock was changed");

  const bySupplierId = new Map();
  for (const item of supplierProducts) {
    const id = Number(item.product_id);
    if (Number.isSafeInteger(id) && id > 0) bySupplierId.set(id, item);
  }

  const docs = await listProducts(accessToken);
  const imported = docs.filter(doc => fieldValue(doc.fields?.supplierProvider) === "spenceraccstore");
  const syncedAt = new Date().toISOString();
  let updated = 0;
  let missingFromSupplier = 0;
  let failed = 0;

  for (const doc of imported) {
    const supplierId = Number(fieldValue(doc.fields?.supplierProductId));
    const supplierProduct = bySupplierId.get(supplierId);
    if (!supplierProduct) { missingFromSupplier++; continue; }

    const stock = Math.max(0, Math.floor(Number(supplierProduct.stock_count || 0)));
    const inStock = supplierProduct.in_stock === true && stock > 0;
    const patchUrl = new URL("https://firestore.googleapis.com/v1/" + doc.name);
    for (const field of ["stockCount", "supplierStockCount", "supplierInStock", "supplierSyncedAt", "updatedAt"]) {
      patchUrl.searchParams.append("updateMask.fieldPaths", field);
    }
    const patchResponse = await fetch(patchUrl, {
      method: "PATCH",
      headers: { Authorization: "Bearer " + accessToken, "Content-Type": "application/json" },
      body: JSON.stringify({ fields: {
        stockCount: { integerValue: String(stock) },
        supplierStockCount: { integerValue: String(stock) },
        supplierInStock: { booleanValue: inStock },
        supplierSyncedAt: { timestampValue: syncedAt },
        updatedAt: { timestampValue: syncedAt }
      } })
    });
    if (patchResponse.ok) updated++;
    else {
      failed++;
      const errorText = await patchResponse.text();
      console.error("Could not update stock for", doc.name, patchResponse.status, errorText.slice(0, 300));
    }
  }

  console.log("Gentle stock sync:", JSON.stringify({ updated, missingFromSupplier, failed, supplierProducts: supplierProducts.length, syncedAt }));
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runStockSync(env).catch(error => console.error("Gentle stock sync failed:", error.message || error)));
  }
};
