import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';

try {
  process.loadEnvFile?.();
} catch (e) {
  // .env file optional if env vars are passed in process.env
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const HOST = '0.0.0.0';

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static assets from public, outputs, and uploads
app.use(express.static(path.join(__dirname, 'public')));
app.use('/outputs', express.static(path.join(__dirname, 'outputs')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const defaultSmtpConfig = {
  host: process.env.SMTP_HOST || 'smtp.hostinger.com',
  port: Number(process.env.SMTP_PORT || 465),
  secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : true,
  user: process.env.SMTP_USER || 'support@vntera.com',
  password: process.env.SMTP_PASSWORD || 'M@hamadHass@un1',
  from: process.env.SMTP_FROM || 'Vntera Support <support@vntera.com>'
};

let currentSmtpConfig = { ...defaultSmtpConfig };

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Get current SMTP configuration (masking password)
app.get('/api/smtp-config', (req, res) => {
  res.json({
    host: currentSmtpConfig.host,
    port: currentSmtpConfig.port,
    secure: currentSmtpConfig.secure,
    user: currentSmtpConfig.user,
    from: currentSmtpConfig.from,
    hasPassword: Boolean(currentSmtpConfig.password)
  });
});

// Update or reset SMTP configuration
app.post('/api/smtp-config', (req, res) => {
  const { host, port, secure, user, password, from, reset } = req.body || {};
  if (reset) {
    currentSmtpConfig = { ...defaultSmtpConfig };
    return res.json({ ok: true, message: 'Reset to Hostinger defaults', config: currentSmtpConfig });
  }
  if (host) currentSmtpConfig.host = String(host).trim();
  if (port) currentSmtpConfig.port = Number(port);
  if (secure !== undefined) currentSmtpConfig.secure = Boolean(secure);
  if (user) currentSmtpConfig.user = String(user).trim();
  if (password && String(password).trim()) currentSmtpConfig.password = String(password).trim();
  if (from) currentSmtpConfig.from = String(from).trim();
  return res.json({ ok: true, message: 'Configuration saved' });
});

// SMTP status check
app.get('/api/smtp-status', async (req, res) => {
  const { host, user, password, port, secure } = currentSmtpConfig;

  if (!host || !user || !password) {
    return res.json({ configured: false, message: 'SMTP credentials not configured' });
  }

  try {
    const transport = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user, pass: password }
    });
    await transport.verify();
    return res.json({ configured: true, connected: true, host, user });
  } catch (err) {
    return res.json({ configured: true, connected: false, error: err.message });
  }
});

function extractCleanReply(fullText) {
  if (!fullText) return '';
  const lines = fullText.split('\n');
  const cleanLines = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^on\s.+wrote:$/i.test(trimmed)) break;
    if (/^-----\s*original message\s*-----/i.test(trimmed)) break;
    if (/^from:\s.+/i.test(trimmed) && cleanLines.length > 0) break;
    if (trimmed.startsWith('>')) break;
    cleanLines.push(line);
  }
  const clean = cleanLines.join('\n').trim();
  return clean || fullText.trim();
}

function getImapHost(smtpHost) {
  if (!smtpHost) return 'imap.hostinger.com';
  if (smtpHost.includes('hostinger')) return 'imap.hostinger.com';
  return smtpHost.replace(/^smtp\./i, 'imap.');
}

// IMAP status check
app.get('/api/imap-status', async (req, res) => {
  const host = getImapHost(currentSmtpConfig.host);
  const user = currentSmtpConfig.user;
  const password = currentSmtpConfig.password;

  if (!host || !user || !password) {
    return res.json({ configured: false, message: 'IMAP credentials not configured' });
  }

  try {
    const client = new ImapFlow({
      host,
      port: 993,
      secure: true,
      auth: { user, pass: password },
      logger: false
    });
    await client.connect();
    const lock = await client.getMailboxLock('INBOX');
    const exists = client.mailbox.exists;
    lock.release();
    await client.logout();
    return res.json({ configured: true, connected: true, host, user, totalMessages: exists });
  } catch (err) {
    return res.json({ configured: true, connected: false, error: err.message });
  }
});

// Fetch incoming real replies from Hostinger IMAP
app.all(['/api/check-incoming-emails', '/api/sync-replies'], async (req, res) => {
  const host = getImapHost(currentSmtpConfig.host);
  const user = currentSmtpConfig.user;
  const password = currentSmtpConfig.password;

  if (!host || !user || !password) {
    return res.json({ ok: false, error: 'Mailbox credentials not configured' });
  }

  const limit = Math.min(Number(req.query?.limit || req.body?.limit || 25), 50);

  let client = null;
  try {
    client = new ImapFlow({
      host,
      port: 993,
      secure: true,
      auth: { user, pass: password },
      logger: false,
      emitLogs: false
    });

    await client.connect();
    const lock = await client.getMailboxLock('INBOX');
    const messages = [];

    try {
      const total = client.mailbox.exists;
      if (total > 0) {
        const start = Math.max(1, total - limit + 1);
        for (let seq = total; seq >= start; seq--) {
          try {
            const download = await client.download(String(seq));
            if (download && download.content) {
              const parsed = await simpleParser(download.content);
              const fromEmail = (parsed.from?.value?.[0]?.address || '').toLowerCase().trim();

              // Skip emails sent from the clinic's own address
              if (fromEmail && fromEmail !== user.toLowerCase().trim()) {
                const rawText = parsed.text || '';
                const cleanBody = extractCleanReply(rawText);
                messages.push({
                  id: `imap-${seq}-${parsed.messageId ? parsed.messageId.replace(/[^a-zA-Z0-9]/g, '').slice(-16) : seq}`,
                  seq,
                  fromEmail,
                  fromName: parsed.from?.value?.[0]?.name || parsed.from?.text || fromEmail,
                  subject: parsed.subject || '(No subject)',
                  body: cleanBody || '(Empty email body)',
                  fullText: rawText,
                  date: parsed.date ? parsed.date.toISOString() : new Date().toISOString(),
                  messageId: parsed.messageId || String(seq),
                  inReplyTo: parsed.inReplyTo || ''
                });
              }
            }
          } catch (itemErr) {
            console.error(`Error parsing message ${seq}:`, itemErr.message);
          }
        }
      }
    } finally {
      lock.release();
    }

    await client.logout();
    return res.json({ ok: true, count: messages.length, messages });
  } catch (err) {
    if (client) {
      try { await client.logout(); } catch (_) {}
    }
    console.error('IMAP error fetching replies:', err);
    return res.status(500).json({ ok: false, error: err.message || 'Failed to fetch incoming emails' });
  }
});

// Mail relay endpoint compatible with morrow-smtp-relay
app.post(['/send', '/api/send'], async (req, res) => {
  const token = process.env.MAIL_RELAY_TOKEN || '';
  const authHeader = req.headers.authorization || '';
  const bearerToken = authHeader.replace(/^Bearer\s+/i, '');

  if (token && bearerToken !== token) {
    return res.status(401).json({ ok: false, error: 'Invalid relay token' });
  }

  const { to, subject, text, from: customFrom } = req.body || {};
  if (!to || !subject || !text) {
    return res.status(400).json({ ok: false, error: 'Recipient, subject, and message are required' });
  }

  const { host, user, password, port, secure, from: defaultFrom } = currentSmtpConfig;
  const from = customFrom || defaultFrom || 'support@vntera.com';

  if (!host || !user || !password) {
    console.log(`[Mail Relay Simulated] To: ${to}, Subject: ${subject}`);
    return res.json({
      ok: true,
      messageId: `simulated-${Date.now()}`,
      note: 'SMTP credentials not configured in environment; delivery simulated.'
    });
  }

  try {
    const transport = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user, pass: password }
    });
    const info = await transport.sendMail({ from, to, subject, text });
    return res.json({ ok: true, messageId: info.messageId });
  } catch (error) {
    console.error('Mail transport error:', error);
    return res.status(500).json({ ok: false, error: error.message || 'Failed to send mail' });
  }
});

// SPA fallback: serve index.html for any remaining route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`Doctor CRM running on http://${HOST}:${PORT}`);
});
