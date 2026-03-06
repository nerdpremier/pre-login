import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    
    const client = new Client({ 
        connectionString: process.env.DATABASE_URL, 
        ssl: { rejectUnauthorized: false } 
    });

    try {
        await client.connect();
        const { username, device, fp_mismatch } = req.body;
        
        // ดึง IP ของ User จาก Vercel Header (แก้ปัญหา Error 429)
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. AUTO-CLEANUP: ลบ Log เก่ากว่า 15 นาที
        await client.query("DELETE FROM login_risks WHERE created_at < NOW() - INTERVAL '15 minutes'");

        // 2. COUNT RATE: นับการลองใน 15 นาที
        const rateCheck = await client.query("SELECT count(*) FROM login_risks WHERE username = $1", [username]);
        const loginRate = parseInt(rateCheck.rows[0].count);

        // 3. CALC SCORE: ปรับความ Sensitive
        let score = 0.1;
        if (loginRate >= 2 && loginRate < 4) score = 0.4; // MEDIUM
        else if (loginRate >= 4) score = 0.8; // HIGH
        if (fp_mismatch) score += 0.4;

        const level = score >= 0.8 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 4. INSERT: บันทึก Log
        await client.query(
            "INSERT INTO login_risks (username, ip_address, device_info, fingerprint_mismatch, login_rate, risk_score, risk_level) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            [username, ip, device, fp_mismatch, loginRate, score, level]
        );

        res.status(200).json({ risk_level: level });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}