const crypto = require("crypto");

const OKX_BASE = "https://www.okx.com";

function sign(timestamp, method, path, body, secret) {
  const pre = timestamp + method.toUpperCase() + path + (body || "");
  return crypto.createHmac("sha256", secret).update(pre).digest("base64");
}

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }

  const { endpoint, method = "GET", params = {} } = JSON.parse(event.body || "{}");

  const key = process.env.OKX_API_KEY;
  const secret = process.env.OKX_SECRET;
  const passphrase = process.env.OKX_PASSPHRASE;

  if (!key || !secret || !passphrase) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: "OKX credentials not configured in environment variables." }),
    };
  }

  const timestamp = new Date().toISOString().replace(/\.\d{3}/, ".000");
  let path = endpoint;
  let bodyStr = "";

  if (method === "GET" && Object.keys(params).length > 0) {
    path += "?" + new URLSearchParams(params).toString();
  } else if (method === "POST") {
    bodyStr = JSON.stringify(params);
  }

  const sig = sign(timestamp, method, path, bodyStr, secret);

  try {
    const res = await fetch(OKX_BASE + path, {
      method,
      headers: {
        "OK-ACCESS-KEY": key,
        "OK-ACCESS-SIGN": sig,
        "OK-ACCESS-TIMESTAMP": timestamp,
        "OK-ACCESS-PASSPHRASE": passphrase,
        "OK-ACCESS-PROJECT": "",
        "Content-Type": "application/json",
      },
      ...(method === "POST" ? { body: bodyStr } : {}),
    });

    const data = await res.json();
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  } catch (err) {
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: err.message }),
    };
  }
};
