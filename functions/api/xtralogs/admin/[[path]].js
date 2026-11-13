// Cloudflare Pages Function
// File path: functions/api/xtralogs/admin/[[path]].js
//
// Required Cloudflare Pages environment variables:
// XTRALOGS_API_KEY       Secret: XtraLogs sandbox/live API key
// FIREBASE_WEB_API_KEY   GentleLogs Firebase web API key
// FIREBASE_PROJECT_ID    gentle-acct-store
//
// The XtraLogs key stays on the server and is never returned to the browser.

const XTRALOGS_BASE = "https://xtralogstools.com/api/v1";
const ADMIN_UID = "UoEjCy99gbQKkGob59vGi3CunZi1";
const SETTINGS_DOCUMENT = "settings/xtralogs";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function firestoreValue(value) {
  if (value === null) return { nullValue: null };

  if (typeof value === "boolean") {
    return { booleanValue: value };
  }

  if (typeof value === "number") {
    return Number.isInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }

  if (typeof value === "string") {
    return { stringValue: value };
  }

  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map(firestoreValue)
      }
    };
  }

  if (typeof value === "object") {
    const fields = {};

    for (const [key, item] of Object.entries(value)) {
      fields[key] = firestoreValue(item);
    }

    return { mapValue: { fields } };
  }

  return { nullValue: null };
}

function fromFirestoreValue(value) {
  if (!value || typeof value !== "object") return null;

  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("booleanValue" in value) return value.booleanValue;
  if ("nullValue" in value) return null;

  if (value.arrayValue) {
    return (value.arrayValue.values || []).map(fromFirestoreValue);
  }

  if (value.mapValue) {
    return fromFirestoreFields(value.mapValue.fields || {});
  }

  return null;
}

function fromFirestoreFields(fields = {}) {
  const result = {};

  for (const [key, value] of Object.entries(fields)) {
    result[key] = fromFirestoreValue(value);
  }

  return result;
}

async function verifyAdmin(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    throw new Error("Sign in to the authorised admin account first.");
  }

  if (!env.FIREBASE_WEB_API_KEY) {
    throw new Error(
      "Missing FIREBASE_WEB_API_KEY Cloudflare environment variable."
    );
  }

  const lookup = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        idToken: match[1]
      })
    }
  );

  const result = await lookup.json().catch(() => ({}));
  const user = result.users && result.users[0];

  if (
    !lookup.ok ||
    !user ||
    user.localId !== ADMIN_UID ||
    user.disabled
  ) {
    throw new Error(
      "This account is not authorised to access XtraLogs administration."
    );
  }

  return match[1];
}

async function xtraRequest(env, endpoint, options = {}) {
  if (!env.XTRALOGS_API_KEY) {
    throw new Error(
      "XTRALOGS_API_KEY is not configured in Cloudflare Pages secrets."
    );
  }

  const response = await fetch(`${XTRALOGS_BASE}${endpoint}`, {
    method: options.method || "GET",

    headers: {
      "Authorization": `Bearer ${env.XTRALOGS_API_KEY}`,
      "Accept": "application/json",

      ...(options.body
        ? { "Content-Type": "application/json" }
        : {})
    },

    ...(options.body
      ? { body: JSON.stringify(options.body) }
      : {})
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      payload.message ||
      payload.error ||
      `XtraLogs request failed (${response.status}).`;

    throw new Error(message);
  }

  return payload;
}

function firestoreDocumentUrl(env) {
  const projectId =
    env.FIREBASE_PROJECT_ID || "gentle-acct-store";

  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${SETTINGS_DOCUMENT}`;
}

async function loadSettings(env, idToken) {
  const response = await fetch(firestoreDocumentUrl(env), {
    headers: {
      "Authorization": `Bearer ${idToken}`
    }
  });

  if (response.status === 404) {
    return {
      pricingMode: "automatic",
      defaultMarginPercent: 20,
      overrides: {},
      importedCountries: []
    };
  }

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      payload.error?.message ||
      "Could not read XtraLogs settings from Firestore. Check the admin Firestore rules."
    );
  }

  return fromFirestoreFields(payload.fields || {});
}

async function saveSettings(env, idToken, settings) {
  const fields = {};

  for (const [key, value] of Object.entries(settings)) {
    fields[key] = firestoreValue(value);
  }

  const response = await fetch(firestoreDocumentUrl(env), {
    method: "PATCH",

    headers: {
      "Authorization": `Bearer ${idToken}`,
      "Content-Type": "application/json"
    },

    body: JSON.stringify({ fields })
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      payload.error?.message ||
      "Could not save XtraLogs settings to Firestore. Check the admin Firestore rules."
    );
  }

  return settings;
}

function getCountryCode(value) {
  return String(value || "").trim().toLowerCase();
}

export async function onRequest({ request, env }) {
  try {
    const idToken = await verifyAdmin(request, env);

    const url = new URL(request.url);

    const route = url.pathname.replace(
      /^\/api\/xtralogs\/admin\/?/,
      ""
    );

    const method = request.method.toUpperCase();

    // CHECK XTRALOGS BALANCE
    if (route === "balance" && method === "GET") {
      const result = await xtraRequest(env, "/balance");

      return json(result);
    }

    // LOAD USA AND GLOBAL NUMBERS CATALOGUES
    if (route === "catalog" && method === "GET") {
      const catalog = url.searchParams.get("catalog") || "";
      const country = url.searchParams.get("country") || "";

      if (catalog === "numbers-usa") {
        const result = await xtraRequest(
          env,
          "/catalog/numbers?scope=usa"
        );

        return json(result);
      }

      if (catalog === "numbers-global") {
        const suffix = country
          ? `&country=${encodeURIComponent(getCountryCode(country))}`
          : "";

        const result = await xtraRequest(
          env,
          `/catalog/numbers?scope=global${suffix}`
        );

        return json(result);
      }

      return json({
        error:
          "This backend currently supports the documented USA and Global Numbers catalogues. Other XtraLogs categories have not been connected yet."
      }, 400);
    }

    // LOAD PRICING SETTINGS
    if (route === "pricing" && method === "GET") {
      const settings = await loadSettings(env, idToken);

      return json({ settings });
    }

    // SAVE PRICING SETTINGS
    if (route === "pricing" && method === "POST") {
      const body = await request.json().catch(() => null);

      if (!body || typeof body !== "object") {
        return json({
          error: "A valid JSON settings object is required."
        }, 400);
      }

      const current = await loadSettings(env, idToken);

      const margin = Number(
        body.defaultMarginPercent ??
        current.defaultMarginPercent ??
        20
      );

      if (
        !Number.isFinite(margin) ||
        margin < 0 ||
        margin > 500
      ) {
        return json({
          error: "Default profit must be between 0 and 500 percent."
        }, 400);
      }

      const settings = {
        pricingMode:
          body.pricingMode === "manual"
            ? "manual"
            : "automatic",

        defaultMarginPercent: margin,

        overrides:
          body.overrides &&
          typeof body.overrides === "object"
            ? body.overrides
            : current.overrides || {},

        importedCountries:
          Array.isArray(body.importedCountries)
            ? body.importedCountries
            : current.importedCountries || []
      };

      await saveSettings(env, idToken, settings);

      return json({ settings });
    }

    // IMPORT A GLOBAL NUMBERS COUNTRY
    if (route === "world-import-country" && method === "POST") {
      const body = await request.json().catch(() => ({}));

      const countryCode = getCountryCode(body.countryCode);

      if (!countryCode) {
        return json({
          error: "A country code is required."
        }, 400);
      }

      const result = await xtraRequest(
        env,
        `/catalog/numbers?scope=global&country=${encodeURIComponent(countryCode)}`
      );

      const rows = Array.isArray(result)
        ? result
        : result.data ||
          result.services ||
          result.catalog ||
          result.results ||
          [];

      return json({
        success: true,
        countryCode,
        serviceCount: Array.isArray(rows) ? rows.length : 0,
        catalogue: result
      });
    }

    return json({
      error: "XtraLogs admin endpoint not found."
    }, 404);

  } catch (error) {
    const message =
      error && error.message
        ? error.message
        : "Unexpected XtraLogs server error.";

    const status =
      /sign in|authorised|authorized|token/i.test(message)
        ? 401
        : 500;

    return json({
      error: message
    }, status);
  }
}
