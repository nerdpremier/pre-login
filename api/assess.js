import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { username, fingerprint, device } = req.body;
        const ip = req.headers['x-forwarded-for'] || "127.0.0.1";

        const userRes = await client.query("SELECT authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const fp_match = userRes.rows[0].authorized_fingerprint === fingerprint;
        const level = fp_match ? "LOW" : "MEDIUM";

        const result = await client.query(
            "INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, risk_level, is_success) VALUES ($1, $2, $3, $4, $5, FALSE) RETURNING id",
            [username, ip, device, fingerprint, level]
        );
        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } finally { await client.end(); }
}