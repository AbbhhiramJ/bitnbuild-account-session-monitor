export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const configured = Boolean(process.env.DATABASE_URL && process.env.MONITOR_API_KEY);
  return res.status(configured ? 200 : 503).json({
    status: configured ? "configured" : "configuration_required",
    service: "account-session-monitor-api",
    mode: "provider-neutral-foundation",
    databaseConfigured: Boolean(process.env.DATABASE_URL),
    ingestionKeyConfigured: Boolean(process.env.MONITOR_API_KEY),
    identityProviderConnected: false
  });
}
