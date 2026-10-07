import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import nodemailer from "nodemailer";

const port = Number(process.env.MAIL_RELAY_PORT || 8787);
const token = process.env.MAIL_RELAY_TOKEN || "";
const from = process.env.SMTP_FROM || "";
const host = process.env.SMTP_HOST || "";
const smtpPort = Number(process.env.SMTP_PORT || 465);
const smtpUser = process.env.SMTP_USER || "";
const smtpPassword = process.env.SMTP_PASSWORD || "";
const secure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === "true" : smtpPort === 465;

if (!token || !from || !host || !smtpUser || !smtpPassword) {
  console.error("Set MAIL_RELAY_TOKEN, SMTP_FROM, SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASSWORD first.");
  process.exit(1);
}

const transport = nodemailer.createTransport({
  host,
  port: smtpPort,
  secure,
  auth: { user: smtpUser, pass: smtpPassword }
});

function allowedOrigin(origin) {
  return origin === "null" || origin === "http://localhost" || origin?.startsWith("http://localhost:") || origin === "http://127.0.0.1" || origin?.startsWith("http://127.0.0.1:");
}

function setCors(req, res) {
  const origin = req.headers.origin;
  if (!allowedOrigin(origin)) return false;
  res.setHeader("Access-Control-Allow-Origin", origin || "null");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
  res.setHeader("Access-Control-Max-Age", "600");
  res.setHeader("Vary", "Origin");
  res.setHeader("X-Content-Type-Options", "nosniff");
  return true;
}

function authorized(value) {
  const candidate = Buffer.from(value || "");
  const expected = Buffer.from(token);
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

const server = http.createServer(async (req, res) => {
  if (!setCors(req, res)) {
    res.writeHead(403).end("Origin not allowed");
    return;
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }
  if (req.method !== "POST" || req.url !== "/send") {
    res.writeHead(404).end("Not found");
    return;
  }
  if (!authorized(String(req.headers.authorization || "").replace(/^Bearer\s+/i, ""))) {
    res.writeHead(401, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: false, error: "Invalid relay token" }));
    return;
  }

  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 40000) {
      res.writeHead(413).end("Message too large");
      return;
    }
  }

  try {
    const message = JSON.parse(raw);
    const to = String(message.to || "").trim();
    const subject = String(message.subject || "").trim();
    const text = String(message.text || "");
    if (!to || !subject || !text || to.length > 500 || subject.length > 180 || text.length > 30000) {
      res.writeHead(400, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: false, error: "Recipient, subject, or message is missing or too long" }));
      return;
    }

    const result = await transport.sendMail({ from, to, subject, text });
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: true, messageId: result.messageId }));
  } catch (error) {
    res.writeHead(400, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: false, error: String(error.message || "Could not send message") }));
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Local mail relay listening at http://127.0.0.1:${port}/send`);
  console.log("Bound to this computer only. Do not expose this port to the clinic network.");
});
