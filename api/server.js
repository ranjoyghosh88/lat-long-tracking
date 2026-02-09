import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Pool } from "pg";
import { z } from "zod";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function loadEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, "utf8").split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const k = trimmed.slice(0, idx).trim();
    const v = trimmed.slice(idx + 1).trim();
    if (!process.env[k]) process.env[k] = v;
  }
}
loadEnv();

const PORT = Number(process.env.PORT || 3001);
const DATABASE_URL = process.env.DATABASE_URL;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";
const PHOTO_DIR = process.env.PHOTO_DIR || "./uploads";
const CHALLENGE_TTL_SECONDS = Number(process.env.CHALLENGE_TTL_SECONDS || 120);
const ACCURACY_THRESHOLD_METERS = Number(process.env.ACCURACY_THRESHOLD_METERS || 5);

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL in api/.env");
  process.exit(1);
}

fs.mkdirSync(path.join(__dirname, PHOTO_DIR), { recursive: true });

const pool = new Pool({ connectionString: DATABASE_URL });

const app = express();
app.use(helmet());
// Allow any localhost port during dev to avoid port churn issues.
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (origin === CORS_ORIGIN) return callback(null, true);
      if (/^http:\/\/localhost:\d+$/.test(origin)) return callback(null, true);
      if (/^http:\/\/127\.0\.0\.1:\d+$/.test(origin)) return callback(null, true);
      if (/^http:\/\/192\.168\.\d+\.\d+:\d+$/.test(origin)) return callback(null, true);
      if (/^http:\/\/10\.\d+\.\d+\.\d+:\d+$/.test(origin)) return callback(null, true);
      if (/^http:\/\/172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+:\d+$/.test(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    }
  })
);
app.use(express.json({ limit: "2mb" }));

app.use("/uploads", express.static(path.join(__dirname, PHOTO_DIR)));

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/api/vendors", (req, res) => {
  res.json({
    items: [
      "Vendor One",
      "Vendor Two",
      "Vendor Three",
      "Vendor Four",
      "Vendor Five"
    ]
  });
});

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function createChallenge() {
  const id = crypto.randomUUID();
  const nonce = crypto.randomBytes(24).toString("base64url");
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000);
  await pool.query(
    `INSERT INTO server_challenges (id, nonce, expires_at) VALUES ($1, $2, $3)`,
    [id, nonce, expiresAt.toISOString()]
  );
  return { id, nonce, expiresAt };
}

app.get("/api/challenge", async (req, res) => {
  try {
    const c = await createChallenge();
    res.json({ challengeId: c.id, nonce: c.nonce, expiresAt: c.expiresAt.toISOString() });
  } catch {
    res.status(500).json({ error: "Failed to create challenge" });
  }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

app.post("/api/photos", upload.single("photo"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing photo" });

    const mime = req.file.mimetype || "";
    if (!mime.startsWith("image/")) return res.status(400).json({ error: "Invalid file type" });

    const rawVendor = String(req.body?.vendorName || "").trim();
    if (!rawVendor) return res.status(400).json({ error: "Missing vendorName" });
    const vendorSlug = rawVendor.replace(/\s+/g, "-");
    const ext = mime.includes("png") ? "png" : "jpg";
    const filename = `${vendorSlug}.${ext}`;

    const filePath = path.join(__dirname, PHOTO_DIR, filename);
    fs.writeFileSync(filePath, req.file.buffer);

    const sha = sha256Hex(req.file.buffer);
    const publicUrl = `/uploads/${filename}`;

    res.json({ photoUrl: publicUrl, photoSha256: sha });
  } catch {
    res.status(500).json({ error: "Photo upload failed" });
  }
});

const EventSchema = z.object({
  eventType: z.enum(["CHECK_IN", "CHECK_OUT"]),
  vendorName: z.string().min(1).max(255),
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  accuracyMeters: z.number().min(0).max(100000),
  capturedAt: z.string().datetime(),
  photoUrl: z.string().min(1),
  photoSha256: z.string().length(64),
  devicePublicKey: z.string().min(1),
  deviceSignature: z.string().min(1),
  challengeId: z.string().uuid(),
  challengeNonce: z.string().min(1)
});

function buildSigningPayload(p) {
  return [
    p.challengeNonce,
    p.eventType,
    p.vendorName,
    String(p.latitude),
    String(p.longitude),
    String(p.accuracyMeters),
    p.capturedAt,
    p.photoSha256
  ].join("|");
}

async function verifyChallenge(challengeId, challengeNonce) {
  const r = await pool.query(
    `SELECT id, nonce, expires_at, used_at FROM server_challenges WHERE id = $1`,
    [challengeId]
  );

  if (r.rowCount === 0) return { ok: false, reason: "Challenge not found" };
  const row = r.rows[0];

  if (row.used_at) return { ok: false, reason: "Challenge already used" };

  const expiresAt = new Date(row.expires_at);
  if (Date.now() > expiresAt.getTime()) return { ok: false, reason: "Challenge expired" };

  if (row.nonce !== challengeNonce) return { ok: false, reason: "Challenge nonce mismatch" };

  await pool.query(`UPDATE server_challenges SET used_at = NOW() WHERE id = $1`, [challengeId]);
  return { ok: true };
}

function verifySignature(devicePublicKeyBase64, signatureBase64, payloadString) {
  try {
    const publicKeyDer = Buffer.from(devicePublicKeyBase64, "base64");
    const signature = Buffer.from(signatureBase64, "base64");

    const publicKey = crypto.createPublicKey({
      key: publicKeyDer,
      format: "der",
      type: "spki"
    });

    return crypto.verify(
      "sha256",
      Buffer.from(payloadString, "utf8"),
      publicKey,
      signature
    );
  } catch {
    return false;
  }
}

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length > 0) return xf.split(",")[0].trim();
  return req.socket?.remoteAddress || null;
}

function photoExists(photoUrl) {
  if (!photoUrl.startsWith("/uploads/")) return false;
  const p = path.join(__dirname, photoUrl);
  return fs.existsSync(p);
}

async function insertEvent({ visitId, body, req }) {
  if (body.accuracyMeters > ACCURACY_THRESHOLD_METERS) {
    return { ok: false, status: 400, error: `Accuracy must be <= ${ACCURACY_THRESHOLD_METERS} meters` };
  }

  if (!photoExists(body.photoUrl)) {
    return { ok: false, status: 400, error: "Photo not found. Upload photo first." };
  }

  const challenge = await verifyChallenge(body.challengeId, body.challengeNonce);
  if (!challenge.ok) return { ok: false, status: 400, error: challenge.reason };

  const payload = buildSigningPayload(body);
  const sigOk = verifySignature(body.devicePublicKey, body.deviceSignature, payload);
  if (!sigOk) return { ok: false, status: 400, error: "Invalid device signature" };

  const id = crypto.randomUUID();
  const userAgent = String(req.headers["user-agent"] || "");
  const ip = getClientIp(req);

  try {
    await pool.query(
      `INSERT INTO visit_events
        (id, visit_id, event_type, vendor_name, latitude, longitude, accuracy_meters, captured_at,
         photo_url, photo_sha256, device_public_key, device_signature, server_challenge_id,
         user_agent, ip_address)
       VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [
        id,
        visitId,
        body.eventType,
        body.vendorName,
        body.latitude,
        body.longitude,
        body.accuracyMeters,
        body.capturedAt,
        body.photoUrl,
        body.photoSha256,
        body.devicePublicKey,
        body.deviceSignature,
        body.challengeId,
        userAgent,
        ip
      ]
    );

    return { ok: true, id };
  } catch {
    return { ok: false, status: 500, error: "Failed to save event" };
  }
}

app.post("/api/visits/check-in", async (req, res) => {
  const parsed = EventSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() });

  const body = parsed.data;
  if (body.eventType !== "CHECK_IN") return res.status(400).json({ error: "eventType must be CHECK_IN" });

  try {
    const existing = await pool.query(
      `SELECT id FROM visits WHERE LOWER(vendor_name) = LOWER($1) LIMIT 1`,
      [body.vendorName]
    );
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: "Vendor name already exists" });
    }
  } catch {
    return res.status(500).json({ error: "Failed to validate vendor name" });
  }

  const visitId = crypto.randomUUID();

  const normalizedVendor = body.vendorName.trim();
  try {
    await pool.query(`INSERT INTO visits (id, vendor_name) VALUES ($1, $2)`, [visitId, normalizedVendor]);
  } catch {
    return res.status(500).json({ error: "Failed to create visit" });
  }

  const r = await insertEvent({ visitId, body, req });
  if (!r.ok) return res.status(r.status).json({ error: r.error });

  res.status(201).json({ visitId, eventId: r.id });
});

app.post("/api/visits/:visitId/check-out", async (req, res) => {
  const visitId = req.params.visitId;

  const parsed = EventSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() });

  const body = parsed.data;
  if (body.eventType !== "CHECK_OUT") return res.status(400).json({ error: "eventType must be CHECK_OUT" });

  const visit = await pool.query(`SELECT vendor_name FROM visits WHERE id = $1`, [visitId]);
  if (visit.rowCount === 0) return res.status(404).json({ error: "Visit not found" });
  
  const checkInVendor = String(visit.rows[0].vendor_name || "");
  const normalizedCheckIn = checkInVendor.trim().toLowerCase();
  const normalizedCheckOut = body.vendorName.trim().toLowerCase();
  if (normalizedCheckOut !== normalizedCheckIn) {
    return res.status(400).json({ error: `Vendor mismatch: check-in was "${checkInVendor}" but check-out is "${body.vendorName}"` });
  }
  const r = await insertEvent({ visitId, body, req });
  if (!r.ok) return res.status(r.status).json({ error: r.error });

  res.status(201).json({ visitId, eventId: r.id });
});

app.get("/api/visits/recent", async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 50), 200);
  const q = `
    SELECT
      v.id AS "visitId",
      v.vendor_name AS "vendorName",
      MIN(CASE WHEN e.event_type='CHECK_IN' THEN e.captured_at END) AS "checkInAt",
      MIN(CASE WHEN e.event_type='CHECK_OUT' THEN e.captured_at END) AS "checkOutAt",
      (SELECT photo_url FROM visit_events WHERE visit_id = v.id AND event_type='CHECK_IN' LIMIT 1) AS "checkInPhotoUrl"
    FROM visits v
    LEFT JOIN visit_events e ON e.visit_id = v.id
    GROUP BY v.id, v.vendor_name
    ORDER BY COALESCE(MIN(CASE WHEN e.event_type='CHECK_IN' THEN e.captured_at END), v.created_at) DESC
    LIMIT $1
  `;

  try {
    const r = await pool.query(q, [limit]);
    res.json({ items: r.rows });
  } catch {
    res.status(500).json({ error: "Failed to load visits" });
  }
});

app.get("/api/export.csv", async (req, res) => {
  const q = `
    SELECT
      e.visit_id,
      v.vendor_name,
      e.event_type,
      e.latitude,
      e.longitude,
      e.accuracy_meters,
      e.captured_at,
      e.photo_url,
      e.photo_sha256,
      e.user_agent,
      e.ip_address,
      e.created_at
    FROM visit_events e
    JOIN visits v ON v.id = e.visit_id
    ORDER BY e.captured_at DESC
  `;

  try {
    const r = await pool.query(q);
    const headers = [
      "visit_id","vendor_name","event_type","latitude","longitude","accuracy_meters","captured_at",
      "photo_url","photo_sha256","user_agent","ip_address","created_at"
    ];

    const escapeCsv = (v) => {
      if (v === null || v === undefined) return "";
      const s = String(v);
      if (s.includes('"') || s.includes(",") || s.includes("\n")) return `"${s.replaceAll('"', '""')}"`;
      return s;
    };

    const lines = [];
    lines.push(headers.join(","));
    for (const row of r.rows) {
      lines.push(headers.map((h) => escapeCsv(row[h])).join(","));
    }

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=visit_events.csv");
    res.send(lines.join("\n"));
  } catch {
    res.status(500).json({ error: "Export failed" });
  }
});

app.get("/api/export.geojson", async (req, res) => {
  const q = `
    SELECT
      e.visit_id,
      v.vendor_name,
      e.event_type,
      e.latitude,
      e.longitude,
      e.accuracy_meters,
      e.captured_at,
      e.photo_url,
      e.photo_sha256
    FROM visit_events e
    JOIN visits v ON v.id = e.visit_id
    ORDER BY e.captured_at DESC
  `;

  try {
    const r = await pool.query(q);
    const features = r.rows.map((row) => ({
      type: "Feature",
      geometry: { type: "Point", coordinates: [row.longitude, row.latitude] },
      properties: {
        visitId: row.visit_id,
        vendorName: row.vendor_name,
        eventType: row.event_type,
        accuracyMeters: row.accuracy_meters,
        capturedAt: row.captured_at,
        photoUrl: row.photo_url,
        photoSha256: row.photo_sha256
      }
    }));

    res.json({ type: "FeatureCollection", features });
  } catch {
    res.status(500).json({ error: "Export failed" });
  }
});

app.listen(PORT, "0.0.0.0", () => {  
  console.log(`API running on http://localhost:${PORT}`);
  console.log(`Uploads at http://localhost:${PORT}/uploads/...`);
});