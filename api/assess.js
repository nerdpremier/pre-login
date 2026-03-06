import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const { username, ip, location, device, fp_mismatch } = req.body;
    if (!username) return res.status(400).json({ error: "Missing data" });

    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        
        // 1. AUTO-CLEANUP: ลบ Log เก่ากว่า 15 นาทีทิ้ง
        await client.query("DELETE FROM login_risks WHERE created_at < NOW() - INTERVAL '15 minutes'");

        // 2. COUNT RATE: นับครั้งที่ลองใน 15 นาที
        const rateCheck = await client.query("SELECT count(*) FROM login_risks WHERE username = $1", [username]);
        const loginRate = parseInt(rateCheck.rows[0].count);

        // 3. CALC SCORE:
        let score = 0.1;
        if (loginRate >= 2 && loginRate < 4) score = 0.4; // MEDIUM
        else if (loginRate >= 4) score = 0.8; // HIGH
        if (fp_mismatch) score += 0.4;

        const level = score >= 0.8 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 4. INSERT: บันทึก Log ใหม่
        await client.query(
            "INSERT INTO login_risks (username, ip_address, network_location, device_info, fingerprint_mismatch, login_rate, risk_score, risk_level) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            [username, ip, location, device, fp_mismatch, loginRate, score, level]
        );
        res.status(200).json({ risk_level: level });
    } catch (err) { res.status(500).json({ error: err.message }); }
    finally { await client.end(); }
}