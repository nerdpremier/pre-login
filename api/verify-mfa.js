import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    const { logId, code, remember } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const log = (await client.query("SELECT * FROM login_risks WHERE id = $1 AND mfa_code = $2 AND updated_at > NOW() - INTERVAL '5 minutes'", [logId, code])).rows[0];

        if (log) {
            await client.query("BEGIN");
            await client.query("UPDATE login_risks SET is_success = TRUE, mfa_code = NULL WHERE id = $1", [logId]);
            if (remember === "true" || remember === true) {
                await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [log.current_fingerprint, log.username]);
            }
            await client.query("COMMIT");
            return res.status(200).json({ success: true });
        }
        res.status(401).json({ error: "Invalid OTP" });
    } finally { await client.end(); }
}