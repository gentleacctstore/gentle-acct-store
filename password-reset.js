const PROJECT_ID = "gentle-acct-store";
const GOOGLE_SCOPE = "https://www.googleapis.com/auth/identitytoolkit";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const IDENTITY_URL = `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/accounts:sendOobCode`;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function base64urlBytes(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlText(value) {
  return base64urlBytes(new TextEncoder().encode(value));
}

function pemToArrayBuffer(pem) {
  const clean = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function googleAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64urlText(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64urlText(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: GOOGLE_SCOPE,
    aud: GOOGLE_TOKEN_URL,
    iat: now,
    exp: now + 3600
  }));
  const unsigned = `${header}.${claims}`;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(serviceAccount.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned)
  );
  const assertion = `${unsigned}.${base64urlBytes(new Uint8Array(signature))}`;
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) {
    throw new Error("Google service-account authentication failed.");
  }
  return data.access_token;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function emailHtml(resetLink) {
  const safeLink = escapeHtml(resetLink);
  return `<!doctype html>
<html><body style="margin:0;padding:32px 12px;background:#f1f7f3;font-family:Arial,sans-serif;color:#17251b">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;background:#ffffff;border:1px solid #d6e6dc;border-radius:16px;overflow:hidden">
      <tr><td style="padding:26px 28px;background:#18572f;color:#ffffff;font-size:20px;font-weight:700">Gentle Acct Store</td></tr>
      <tr><td style="padding:30px 28px">
        <h1 style="margin:0 0 14px;font-size:22px;color:#173d25">Reset your password</h1>
        <p style="font-size:15px;line-height:1.7;color:#526258">We received a request to reset the password for your Gentle Acct Store account. Use the button below to choose a new password.</p>
        <p style="margin:26px 0"><a href="${safeLink}" style="display:inline-block;padding:14px 22px;border-radius:9px;background:#18572f;color:#ffffff;text-decoration:none;font-weight:700">Reset Password</a></p>
        <p style="font-size:13px;line-height:1.7;color:#6b756e">If you didn't request a password reset, you can ignore this email. Your password will not change unless you use the link.</p>
        <p style="font-size:12px;line-height:1.6;color:#87918a;word-break:break-all">If the button doesn't work, copy this link into your browser:<br>${safeLink}</p>
      </td></tr>
    </table>
    <p style="font-size:11px;color:#89958c;margin-top:18px">© ${new Date().getFullYear()} Gentle Acct Store</p>
  </td></tr></table>
</body></html>`;
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin");
  if (origin && env.SITE_ORIGIN && origin !== env.SITE_ORIGIN) {
    return json({ error: "Request not allowed." }, 403);
  }

  if (!env.FIREBASE_SERVICE_ACCOUNT || !env.RESEND_API_KEY || !env.RESET_FROM_EMAIL) {
    return json({ error: "Password reset email service is not configured yet." }, 503);
  }

  let body;
  try {
    if (Number(request.headers.get("Content-Length") || 0) > 3000) {
      return json({ error: "Invalid request." }, 413);
    }
    body = await request.json();
  } catch {
    return json({ error: "Invalid request." }, 400);
  }

  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: "Please enter a valid email address." }, 400);
  }

  try {
    const serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    if (!serviceAccount.client_email || !serviceAccount.private_key) {
      throw new Error("Service account JSON is missing required fields.");
    }

    const accessToken = await googleAccessToken(serviceAccount);
    const linkResponse = await fetch(IDENTITY_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        requestType: "PASSWORD_RESET",
        email,
        returnOobLink: true,
        userIp: request.headers.get("CF-Connecting-IP") || ""
      })
    });
    const linkData = await linkResponse.json();

    // Do not reveal whether an email address has a Gentle Acct Store account.
    if (!linkResponse.ok) {
      const message = String(linkData?.error?.message || "");
      if (message.includes("EMAIL_NOT_FOUND") || message.includes("USER_NOT_FOUND")) {
        return json({ ok: true });
      }
      console.error("Firebase reset-link generation failed:", message);
      return json({ error: "We couldn't send the reset email right now. Please try again later." }, 502);
    }

    if (!linkData.oobLink) {
      console.error("Firebase did not return a password reset link.");
      return json({ error: "We couldn't send the reset email right now. Please try again later." }, 502);
    }

    const mailResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: env.RESET_FROM_EMAIL,
        to: [email],
        subject: "Reset your Gentle Acct Store password",
        html: emailHtml(linkData.oobLink),
        text: `Reset your Gentle Acct Store password using this link: ${linkData.oobLink}\n\nIf you did not request this, ignore this email.`
      })
    });

    if (!mailResponse.ok) {
      const mailError = await mailResponse.text();
      console.error("Resend delivery failed:", mailError);
      return json({ error: "We couldn't send the reset email right now. Please try again later." }, 502);
    }

    return json({ ok: true });
  } catch (error) {
    console.error("Password reset endpoint error:", error);
    return json({ error: "We couldn't send the reset email right now. Please try again later." }, 500);
  }
}

export async function onRequestGet() {
  return json({ error: "Method not allowed." }, 405);
}
