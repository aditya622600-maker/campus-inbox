import "dotenv/config";
import express from "express";
import session from "express-session";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { google } from "googleapis";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createStorage } from "./storage.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === "production";
const sessionCookieName = production ? "__Host-campus.sid" : "campus.sid";
const redirectUri = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${port}/auth/google/callback`;
const dataDirectory = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, ".data");
const storage = await createStorage({ dataDirectory, databaseUrl:process.env.DATABASE_URL });
const configured = () => Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be set to a random value of at least 32 characters.");
}
const tokenEncryptionKey = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY || "", "base64");
if (tokenEncryptionKey.length !== 32) {
  throw new Error("TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
}
const dataOwnershipKey = Buffer.from(process.env.DATA_OWNERSHIP_KEY || "", "base64");
if (dataOwnershipKey.length !== 32) {
  throw new Error("DATA_OWNERSHIP_KEY must be a base64-encoded 32-byte key.");
}
function ownerIdForEmail(emailAddress) {
  return crypto.createHmac("sha256", dataOwnershipKey).update(emailAddress.trim().toLowerCase()).digest("hex");
}

function encryptTokens(tokens) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", tokenEncryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(tokens), "utf8"), cipher.final()]);
  return { version:1, iv:iv.toString("base64"), tag:cipher.getAuthTag().toString("base64"), ciphertext:ciphertext.toString("base64") };
}
function decryptTokens(encrypted) {
  if (!encrypted || encrypted.version !== 1) throw new Error("Unsupported encrypted-token format.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", tokenEncryptionKey, Buffer.from(encrypted.iv, "base64"));
  decipher.setAuthTag(Buffer.from(encrypted.tag, "base64"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(encrypted.ciphertext, "base64")), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}
const encryptionSelfTest = { access_token:"self-test", expiry_date:1 };
if (decryptTokens(encryptTokens(encryptionSelfTest)).access_token !== encryptionSelfTest.access_token) {
  throw new Error("OAuth token encryption self-test failed.");
}

function oauthClient(userSession) {
  if (!configured()) throw new Error("Add your Google OAuth credentials to .env first.");
  const client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, redirectUri);
  if (userSession?.encryptedTokens) client.setCredentials(decryptTokens(userSession.encryptedTokens));
  client.on("tokens", tokens => {
    if (!userSession) return;
    const existing = userSession.encryptedTokens ? decryptTokens(userSession.encryptedTokens) : {};
    userSession.encryptedTokens = encryptTokens({ ...existing, ...tokens });
    userSession.save(() => {});
  });
  return client;
}
function decode(value = "") { return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"); }
function bodyOf(payload) {
  if (!payload) return "";
  if (payload.mimeType === "text/plain" && payload.body?.data) return decode(payload.body.data);
  for (const part of payload.parts || []) { const body = bodyOf(part); if (body) return body; }
  return payload.body?.data ? decode(payload.body.data).replace(/<[^>]+>/g, " ") : "";
}
const clean = (value = "") => value.replace(/\s+/g, " ").trim();
const priorityRules = {
  critical:["exam","examination","assignment","submission","deadline","fee due","academic warning","urgent","admit card","timetable revised"],
  moderate:["hackathon","internship","placement","scholarship","competition","workshop","coding contest"],
  low:["newsletter","survey","photo walk","club event","general announcement"]
};
function classifyEmail(email, body) {
  const text = `${email.subject} ${email.preview} ${body}`.toLowerCase();
  const attendance = text.match(/attendance[^\d]{0,40}(\d{1,3}(?:\.\d+)?)\s*%/i);
  if (attendance && Number(attendance[1]) < 75) return { priority:"critical", reason:`Attendance is ${attendance[1]}% — below 75%` };
  if (attendance) return { priority:"low", reason:`Attendance is ${attendance[1]}% — above 75%` };
  const critical = priorityRules.critical.find(word => text.includes(word));
  if (critical) return { priority:"critical", reason:`Detected: ${critical}` };
  const moderate = priorityRules.moderate.find(word => text.includes(word));
  if (moderate) return { priority:"moderate", reason:`Opportunity: ${moderate}` };
  const low = priorityRules.low.find(word => text.includes(word));
  return { priority:"low", reason:low ? `Filtered: ${low}` : "No urgent action detected" };
}
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy:{ directives:{ defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'", "https://fonts.googleapis.com"], fontSrc:["'self'", "https://fonts.gstatic.com", "data:"], imgSrc:["'self'", "data:"], connectSrc:["'self'"], formAction:["'self'"], frameAncestors:["'none'"], upgradeInsecureRequests:production ? [] : null } },
  crossOriginEmbedderPolicy:false,
  hsts:production ? undefined : false,
  referrerPolicy:{ policy:"no-referrer" }
}));
const authLimiter = rateLimit({ windowMs:15 * 60 * 1000, limit:20, standardHeaders:"draft-8", legacyHeaders:false, message:"Too many sign-in attempts. Please wait and try again." });
const gmailLimiter = rateLimit({ windowMs:60 * 1000, limit:30, standardHeaders:"draft-8", legacyHeaders:false, message:{ error:"Too many inbox refreshes. Please wait one minute and try again." } });
const mutationLimiter = rateLimit({ windowMs:15 * 60 * 1000, limit:20, standardHeaders:"draft-8", legacyHeaders:false, message:{ error:"Too many account requests. Please wait and try again." } });
app.use(session({
  name:sessionCookieName,
  store:storage.sessionStore,
  secret:process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    secure:production,
    maxAge:7 * 24 * 60 * 60 * 1000
  }
}));
app.use(express.static(__dirname));
app.get("/api/health", async (_req, res) => {
  try {
    await storage.health();
    res.set("Cache-Control", "no-store").json({ status:"ok" });
  } catch {
    res.status(503).json({ status:"unavailable" });
  }
});
function validCsrfToken(req) {
  const expected = req.session.csrfToken;
  const provided = req.get("x-csrf-token");
  if (!expected || !provided || expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
}
async function revokeGoogleAccess(userSession) {
  if (!userSession.encryptedTokens) return true;
  try {
    const tokens = decryptTokens(userSession.encryptedTokens);
    const tokenToRevoke = tokens.refresh_token || tokens.access_token;
    if (!tokenToRevoke) return true;
    await oauthClient(userSession).revokeToken(tokenToRevoke);
    return true;
  } catch (error) {
    console.warn("Google access revocation failed; local cleanup will still complete:", error.message);
    return false;
  }
}
function destroySession(req, res, payload) {
  req.session.destroy(() => {
    res.clearCookie(sessionCookieName, { path:"/", httpOnly:true, sameSite:"lax", secure:production });
    res.json(payload);
  });
}
app.get("/api/auth/status", (req, res) => {
  req.session.csrfToken ||= crypto.randomBytes(32).toString("base64url");
  res.set("Cache-Control", "no-store").json({ configured:configured(), connected:Boolean(req.session.encryptedTokens && req.session.ownerId), csrfToken:req.session.csrfToken });
});
app.get("/auth/google", authLimiter, (req, res) => {
  try {
    const state = crypto.randomBytes(24).toString("hex");
    req.session.oauthState = { value:state, expiresAt:Date.now() + 600000 };
    req.session.save(error => {
      if (error) return res.status(500).send("Could not start a secure sign-in session.");
      res.redirect(oauthClient().generateAuthUrl({ access_type:"offline", prompt:"consent", scope:["https://www.googleapis.com/auth/gmail.readonly"], state }));
    });
  } catch (error) { console.error("OAuth setup failed:", error.message); res.status(500).send("<h1>Sign-in is temporarily unavailable</h1><p>Please try again later.</p>"); }
});
app.get("/auth/google/callback", authLimiter, async (req, res) => {
  const pending = req.session.oauthState;
  delete req.session.oauthState;
  if (!pending || pending.value !== req.query.state || pending.expiresAt < Date.now()) return res.status(400).send("Invalid or expired OAuth request. Return and try again.");
  if (req.query.error) return res.redirect(`/?auth_error=${encodeURIComponent(req.query.error)}`);
  try {
    const { tokens } = await oauthClient().getToken(req.query.code);
    const profileClient = oauthClient();
    profileClient.setCredentials(tokens);
    const profile = await google.gmail({ version:"v1", auth:profileClient }).users.getProfile({ userId:"me" });
    if (!profile.data.emailAddress) throw new Error("Google did not return an account identity.");
    const ownerId = ownerIdForEmail(profile.data.emailAddress);
    req.session.regenerate(error => {
      if (error) return res.redirect("/?auth_error=session_failed");
      req.session.encryptedTokens = encryptTokens(tokens);
      req.session.ownerId = ownerId;
      req.session.save(saveError => res.redirect(saveError ? "/?auth_error=session_failed" : "/?connected=1"));
    });
  }
  catch (error) { console.error("OAuth callback failed:", error.message); res.redirect("/?auth_error=callback_failed"); }
});
app.get("/api/emails", gmailLimiter, async (req, res) => {
  if (!req.session.encryptedTokens || !req.session.ownerId) return res.status(401).json({ error:"Gmail is not connected." });
  try {
    const gmail = google.gmail({ version:"v1", auth:oauthClient(req.session) });
    const list = await gmail.users.messages.list({ userId:"me", maxResults:75, q:"newer_than:30d" });
    const messageRefs = list.data.messages || [];
    const cache = await storage.readEmailCache(req.session.ownerId);
    const missing = messageRefs.filter(({id}) => !cache[id]);
    const details = await Promise.all(missing.map(({id}) => gmail.users.messages.get({ userId:"me", id, format:"full" })));
    details.forEach(({data}) => {
      const headers = Object.fromEntries((data.payload?.headers || []).map(h => [h.name.toLowerCase(), h.value]));
      const sender = clean(headers.from || "Unknown sender").replace(/<[^>]+>/, "").replace(/^"|"$/g, "");
      const body = clean(bodyOf(data.payload));
      const email = { id:data.id, sender, subject:clean(headers.subject || "(No subject)"), preview:clean(body || data.snippet || "").slice(0,240), date:new Date(Number(data.internalDate)).toISOString(), initials:sender.split(/\s+/).slice(0,2).map(w=>w[0]).join("").toUpperCase() };
      cache[data.id] = { ...email, ...classifyEmail(email, clean(`${data.snippet || ""} ${body}`)) };
    });
    const activeIds = new Set(messageRefs.map(({id}) => id));
    const trimmedCache = Object.fromEntries(Object.entries(cache).filter(([id]) => activeIds.has(id)));
    await storage.writeEmailCache(req.session.ownerId, trimmedCache);
    const emails = messageRefs.map(({id}) => trimmedCache[id]).filter(Boolean);
    res.set("Cache-Control", "no-store").json({ emails, cache:{ reused:emails.length-missing.length, downloaded:missing.length } });
  } catch (error) { console.error("Gmail fetch failed:", error.message); if (error.code === 401) delete req.session.encryptedTokens; res.status(error.code === 401 ? 401 : 500).json({ error:"Could not load Gmail messages." }); }
});
app.post("/api/auth/logout", mutationLimiter, async (req, res) => {
  if (!validCsrfToken(req)) return res.status(403).json({ error:"Invalid security token. Refresh the page and try again." });
  const revoked = await revokeGoogleAccess(req.session);
  destroySession(req, res, { connected:false, revoked, warning:revoked ? null : "Local session ended, but Google access could not be revoked. Remove Campus Inbox from your Google Account permissions." });
});
app.delete("/api/account/data", mutationLimiter, async (req, res) => {
  if (!validCsrfToken(req)) return res.status(403).json({ error:"Invalid security token. Refresh the page and try again." });
  if (!req.session.ownerId) return res.status(401).json({ error:"Connect Gmail before deleting account data." });
  const deletedRecords = await storage.deleteOwnerData(req.session.ownerId);
  const revoked = await revokeGoogleAccess(req.session);
  destroySession(req, res, { deleted:true, deletedRecords, connected:false, revoked, warning:revoked ? null : "Your cached data was deleted and local session ended, but Google access could not be revoked. Remove Campus Inbox from your Google Account permissions." });
});
app.use("/api", (_req, res) => res.status(404).json({ error:"API endpoint not found." }));
app.use((error, req, res, _next) => {
  const requestId = crypto.randomUUID();
  console.error(`Unhandled request error ${requestId}:`, error.message);
  if (res.headersSent) return;
  if (req.path.startsWith("/api/")) return res.status(500).json({ error:"An unexpected server error occurred.", requestId });
  res.status(500).send(`<h1>Something went wrong</h1><p>Please try again. Reference: ${requestId}</p>`);
});
app.listen(port, production ? "0.0.0.0" : "127.0.0.1", () => { console.log(`Campus Inbox running on port ${port}`); console.log(configured() ? "Google OAuth credentials detected." : "Add credentials to .env to connect Gmail."); console.log(`User-isolated ${storage.kind} cache and session store ready.`); });
