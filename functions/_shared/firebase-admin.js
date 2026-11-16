
function base64url(value) {
  const bytes = typeof value === "string"
    ? new TextEncoder().encode(value)
    : value;

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function pemToBytes(pem) {
  const normalized = pem.replace(/\\n/g, "\n");

  const base64 = normalized
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  return Uint8Array.from(
    atob(base64),
    character => character.charCodeAt(0)
  );
}

export async function getFirebaseAccessToken(env) {
  if (
    !env.FIREBASE_CLIENT_EMAIL ||
    !env.FIREBASE_PRIVATE_KEY ||
    !env.FIREBASE_PROJECT_ID
  ) {
    throw new Error("Firebase Admin configuration is incomplete.");
  }

  const now = Math.floor(Date.now() / 1000);

  const header = base64url(JSON.stringify({
    alg: "RS256",
    typ: "JWT"
  }));

  const claim = base64url(JSON.stringify({
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
    scope: "https://www.googleapis.com/auth/datastore"
  }));

  const unsigned = header + "." + claim;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToBytes(env.FIREBASE_PRIVATE_KEY),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned)
  );

  const assertion =
    unsigned + "." + base64url(new Uint8Array(signature));

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type:
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion
      })
    }
  );

  const result = await response.json();

  if (!response.ok || !result.access_token) {
    throw new Error("Firebase service authentication failed.");
  }

  return result.access_token;
}

export function firestoreBase(env) {
  return (
    "https://firestore.googleapis.com/v1/projects/" +
    encodeURIComponent(env.FIREBASE_PROJECT_ID) +
    "/databases/(default)/documents"
  );
}

export async function firestoreRequest(env, path, options = {}) {
  const token = await getFirebaseAccessToken(env);

  const response = await fetch(firestoreBase(env) + path, {
    ...options,
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();

  let result = {};

  try {
    result = text ? JSON.parse(text) : {};
  } catch {
    result = {};
  }

  if (!response.ok) {
    const error = new Error(
      result.error?.message || "Firestore request failed."
    );

    error.status = response.status;
    throw error;
  }

  return result;
}

export function encodeFields(data) {
  const fields = {};

  for (const [key, value] of Object.entries(data)) {
    if (value === null) {
      fields[key] = { nullValue: null };
    } else if (typeof value === "string") {
      fields[key] = { stringValue: value };
    } else if (typeof value === "boolean") {
      fields[key] = { booleanValue: value };
    } else if (typeof value === "number") {
      fields[key] = Number.isInteger(value)
        ? { integerValue: String(value) }
        : { doubleValue: value };
    } else if (value instanceof Date) {
      fields[key] = {
        timestampValue: value.toISOString()
      };
    }
  }

  return fields;
}

export function decodeFields(fields = {}) {
  const result = {};

  for (const [key, value] of Object.entries(fields)) {
    if ("stringValue" in value) {
      result[key] = value.stringValue;
    } else if ("integerValue" in value) {
      result[key] = Number(value.integerValue);
    } else if ("doubleValue" in value) {
      result[key] = value.doubleValue;
    } else if ("booleanValue" in value) {
      result[key] = value.booleanValue;
    } else if ("timestampValue" in value) {
      result[key] = value.timestampValue;
    } else if ("nullValue" in value) {
      result[key] = null;
    }
  }

  return result;
}
