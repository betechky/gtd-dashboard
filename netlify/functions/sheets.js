// netlify/functions/sheets.js
// This runs on Netlify's server - credentials never exposed to browser

exports.handler = async function(event, context) {
  const CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }

  try {
    const SHEET_ID    = process.env.SHEET_ID;
    const CLIENT_EMAIL = process.env.SA_EMAIL;
    const PRIVATE_KEY  = (process.env.SA_KEY || "").replace(/\\n/g, "\n");

    if (!SHEET_ID || !CLIENT_EMAIL || !PRIVATE_KEY) {
      return { statusCode: 500, headers: CORS,
        body: JSON.stringify({ error: "Missing environment variables" }) };
    }

    // ── Create JWT for Google OAuth ──
    const jwt = await createJWT(CLIENT_EMAIL, PRIVATE_KEY);
    const token = await getAccessToken(jwt);

    // ── Fetch both sheets ──
    const [dailyRows, targetRows] = await Promise.all([
      fetchSheet(SHEET_ID, "Daily Tracker", token),
      fetchSheet(SHEET_ID, "Monthly Targets", token),
    ]);

    return {
      statusCode: 200,
      headers: CORS,
      body: JSON.stringify({ daily: dailyRows, targets: targetRows }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: CORS,
      body: JSON.stringify({ error: err.message }),
    };
  }
};

// ── JWT / OAuth helpers ──────────────────────────────────────────────────────
async function createJWT(email, privateKey) {
  const header  = { alg: "RS256", typ: "JWT" };
  const now     = Math.floor(Date.now() / 1000);
  const payload = {
    iss: email,
    scope: "https://www.googleapis.com/auth/spreadsheets.readonly",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const enc = (obj) => Buffer.from(JSON.stringify(obj))
    .toString("base64")
    .replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");

  const signingInput = `${enc(header)}.${enc(payload)}`;

  // Use Node crypto to sign
  const crypto = require("crypto");
  const sign   = crypto.createSign("RSA-SHA256");
  sign.update(signingInput);
  const sig = sign.sign(privateKey, "base64")
    .replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");

  return `${signingInput}.${sig}`;
}

async function getAccessToken(jwt) {
  const https = require("https");
  const body  = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: "oauth2.googleapis.com",
      path: "/token",
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
      },
    }, (res) => {
      let data = "";
      res.on("data", (d) => data += d);
      res.on("end", () => {
        const json = JSON.parse(data);
        if (json.access_token) resolve(json.access_token);
        else reject(new Error(`Token error: ${JSON.stringify(json)}`));
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function fetchSheet(sheetId, sheetName, token) {
  const https  = require("https");
  const range  = encodeURIComponent(`${sheetName}!A1:S500`);
  const path   = `/v4/spreadsheets/${sheetId}/values/${range}`;

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: "sheets.googleapis.com",
      path,
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    }, (res) => {
      let data = "";
      res.on("data", (d) => data += d);
      res.on("end", () => {
        try {
          const json = JSON.parse(data);
          resolve(json.values || []);
        } catch(e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.end();
  });
}
