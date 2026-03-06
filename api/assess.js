import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { username, ip, location, device, fp_mismatch } = req.body;

        // เช็ค Login Rate (5 นาทีล่าสุด)
        const rateCheck = await client.query("SELECT count(*) FROM login_risks WHERE username = $1 AND created_at > NOW() - INTERVAL '5 minutes'", [username]);
        const loginRate = parseInt(rateCheck.rows[0].count);

        // คำนวณ Score
        let score = 0.1;
        if (fp_mismatch) score += 0.4;
        if (loginRate > 5) score += 0.5;

        const level = score >= 0.8 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        await client.query(
            `INSERT INTO login_risks (username, ip_address, network_location, device_info, fingerprint_mismatch, login_rate, risk_score, risk_level) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [username, ip, location, device, fp_mismatch, loginRate, score, level]
        );

        return res.status(200).json({ risk_level: level });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    } finally { await client.end(); }
}