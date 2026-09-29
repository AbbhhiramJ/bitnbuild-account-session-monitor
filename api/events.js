import pg from "pg";

const { Pool } = pg;
const pool = globalThis.__monitorPool || new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: true },
  max: 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 5000
});
globalThis.__monitorPool = pool;

const allowedTypes = new Set([
  "sign_in", "sign_out", "session_created", "session_revoked",
  "mfa_challenge", "password_changed", "risk_detected", "other"
]);
const severities = new Set(["info", "low", "medium", "high", "critical"]);
const text = (v, max) => typeof v === "string" ? v.trim().slice(0, max) : "";

function authorized(req) {
  const expected = process.env.MONITOR_API_KEY;
  const header = req.headers.authorization || "";
  if (!expected || !header.startsWith("Bearer ")) return false;
  const supplied = header.slice(7);
  if (supplied.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ supplied.charCodeAt(i);
  return diff === 0;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  if (!process.env.DATABASE_URL || !process.env.MONITOR_API_KEY) {
    return res.status(503).json({ error: "Service is not configured" });
  }
  if (!authorized(req)) return res.status(401).json({ error: "Unauthorized" });

  try {
    if (req.method === "POST") {
      const b = req.body;
      if (!b || typeof b !== "object" || Array.isArray(b)) return res.status(400).json({ error: "JSON object required" });
      const eventType = text(b.eventType, 40);
      const severity = text(b.severity || "info", 16).toLowerCase();
      const score = Number(b.riskScore ?? 0);
      const occurredAt = b.occurredAt ? new Date(b.occurredAt) : new Date();
      if (!allowedTypes.has(eventType)) return res.status(400).json({ error: "Unsupported eventType" });
      if (!severities.has(severity)) return res.status(400).json({ error: "Unsupported severity" });
      if (!Number.isInteger(score) || score < 0 || score > 100) return res.status(400).json({ error: "riskScore must be an integer from 0 to 100" });
      if (Number.isNaN(occurredAt.getTime())) return res.status(400).json({ error: "Invalid occurredAt timestamp" });
      const details = b.details && typeof b.details === "object" && !Array.isArray(b.details) ? b.details : {};
      if (JSON.stringify(details).length > 8000) return res.status(413).json({ error: "details payload too large" });
      const result = await pool.query(
        `INSERT INTO security_events (occurred_at, source, actor, event_type, ip_address, user_agent, severity, risk_score, summary, details)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
         RETURNING id, occurred_at, source, actor, event_type, ip_address, severity, risk_score, summary`,
        [occurredAt.toISOString(), text(b.source, 120) || "unspecified", text(b.actor, 255) || "unknown",
         eventType, text(b.ipAddress, 64) || null, text(b.userAgent, 512) || null,
         severity, score, text(b.summary, 1000) || eventType, JSON.stringify(details)]
      );
      return res.status(201).json({ event: result.rows[0] });
    }

    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit || "50", 10) || 50));
    const before = req.query.before ? new Date(req.query.before) : null;
    const beforeId = typeof req.query.beforeId === "string" ? req.query.beforeId : "";
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(beforeId);
    if (before && Number.isNaN(before.getTime())) return res.status(400).json({ error: "Invalid before timestamp" });
    if (beforeId && (!before || !isUuid)) return res.status(400).json({ error: "beforeId requires a valid before timestamp and UUID" });

    const columns = "id, occurred_at, source, actor, event_type, ip_address, severity, risk_score, summary, details";
    let result;
    if (before && beforeId) {
      result = await pool.query(
        `SELECT ${columns} FROM security_events WHERE occurred_at < $1 OR (occurred_at = $1 AND id < $2::uuid) ORDER BY occurred_at DESC, id DESC LIMIT $3`,
        [before.toISOString(), beforeId, limit]
      );
    } else if (before) {
      result = await pool.query(
        `SELECT ${columns} FROM security_events WHERE occurred_at < $1 ORDER BY occurred_at DESC, id DESC LIMIT $2`,
        [before.toISOString(), limit]
      );
    } else {
      result = await pool.query(
        `SELECT ${columns} FROM security_events ORDER BY occurred_at DESC, id DESC LIMIT $1`,
        [limit]
      );
    }
    const last = result.rows.at(-1);
    return res.status(200).json({
      events: result.rows,
      count: result.rowCount,
      limit,
      nextCursor: result.rowCount === limit && last
        ? { before: last.occurred_at, beforeId: last.id }
        : null
    });
  } catch {
    return res.status(500).json({ error: "Request could not be completed" });
  }
}
