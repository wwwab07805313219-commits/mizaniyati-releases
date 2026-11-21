import http from "node:http";
import {randomBytes} from "node:crypto";
import {readFile} from "node:fs/promises";

const clientId = process.env.GOOGLE_CLIENT_ID || "";
const port = Number(process.env.PORT || 3000);
const origin = new URL(process.env.APP_ORIGIN || process.env.RENDER_EXTERNAL_URL || "http://localhost:" + port).origin;
const secure = origin.startsWith("https:") ? "; Secure" : "";
const publisher = process.env.ADSENSE_PUBLISHER_ID || "";
if (publisher && !/^pub-[0-9]{16}$/.test(publisher)) throw Error("Invalid ADSENSE_PUBLISHER_ID");
const contact = process.env.CONTACT_EMAIL || "";
if (contact && !/^[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(contact)) throw Error("Invalid CONTACT_EMAIL");
const sessions = new Map();
const lifetime = 8 * 60 * 60;
const verifier = clientId ? new (await import("google-auth-library")).OAuth2Client(clientId) : null;

setInterval(() => {
  for (const [key, session] of sessions) {
    if (session.expires <= Date.now()) sessions.delete(key);
  }
}, 60000).unref();

http.createServer(async (req, res) => {
  function send(code, body = {}) {
    res.writeHead(code, {"Content-Type":"application/json", "Cache-Control":"no-store"});
    res.end(JSON.stringify(body));
  }
  function cookie(value, age) {
    res.setHeader("Set-Cookie", "hasabati=" + value + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + age + secure);
  }
  const token = (req.headers.cookie || "").match(/(?:^|;\s*)hasabati=([\da-f]{64})(?:;|$)/)?.[1];
  try {
    if (req.method === "GET" && req.url === "/ads.txt" && publisher) {
      res.writeHead(200, {"Content-Type":"text/plain; charset=utf-8"});
      return res.end("google.com, " + publisher + ", DIRECT, f08c47fec0942fa0\n");
    }
    const pathname = req.url.split("?")[0];
    if (req.method === "GET" && ["/", "/hasabati-modern.html"].includes(pathname)) {
      const page = await readFile(new URL("./hasabati-modern.html", import.meta.url), "utf8");
      res.writeHead(200, {"Content-Type":"text/html; charset=utf-8","Cross-Origin-Opener-Policy":"same-origin-allow-popups"});
            const ads = publisher
        ? '<script async crossorigin="anonymous" src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-' + publisher + '"></script>'
        : "";
      const contactLink = contact ? '<a href="mailto:' + contact + '">اتصل بنا</a>' : "";
      return res.end(page.replace("<!-- advertising -->", ads).replace("<!-- contact -->", contactLink));
    }
    if (req.method === "GET" && req.url === "/api/account") {
      const session = sessions.get(token);
      return send(200, {clientId, user:session && session.expires > Date.now() ? session.user : null});
    }
    if (req.method !== "POST") return send(404);
    if (req.headers.origin !== origin || req.headers["x-hasabati"] !== "1") return send(403);
    if (req.url === "/api/logout") {
      sessions.delete(token);
      cookie("", 0);
      return send(200);
    }
    if (req.url !== "/api/login") return send(404);
    if (!verifier) return send(503);
    let body = "";
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 16000) return send(413);
    }
    let payload;
    try {
      const {credential} = JSON.parse(body);
      if (typeof credential !== "string" || !credential) return send(400);
      const ticket = await verifier.verifyIdToken({idToken:credential, audience:clientId});
      payload = ticket.getPayload();
      if (!payload?.sub) return send(401);
    } catch { return send(401); }
    const key = randomBytes(32).toString("hex");
    sessions.delete(token);
    sessions.set(key, {expires:Date.now() + lifetime * 1000, user:{id:payload.sub, name:payload.name || payload.email || "مستخدم"}});
    cookie(key, lifetime);
    send(200);
  } catch { send(500); }
}).listen(port, process.env.HOST || "127.0.0.1", () => console.log("Hasabati: " + origin));
