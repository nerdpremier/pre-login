import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(450);

    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {
        await client.connect();
        const { username, ip, location, device, fp_mismatch } = req.body;

        // 1. เช็ค Login Rate (ดูว่าคนนี้พยายามล็อกอินไปกี่ครั้งใน 5 นาที)
        const rateCheck = await client.query(
            "SELECT count(*) FROM login_risks WHERE username = $1 AND created_at > NOW() - INTERVAL '5 minutes'",
            [username]
        );
        const loginRate = parseInt(rateCheck.rows[0].count);

        // 2. คำนวณ Risk Score (0.0 - 1.0)
        let score = 0.1; // คะแนนพื้นฐาน
        if (fp_mismatch) score += 0.4; // ถ้าเครื่องเปลี่ยน เสี่ยงเพิ่ม 0.4
        if (loginRate > 3) score += 0.5; // ถ้าลองถี่ยิบ เสี่ยงเพิ่ม 0.5

        // 3. กำหนดระดับ
        let level = "LOW";
        if (score >= 0.8) level = "HIGH";
        else if (score >= 0.4) level = "MEDIUM";

        // 4. บันทึกลง Database
        await client.query(
            `INSERT INTO login_risks (username, ip_address, network_location, device_info, fingerprint_mismatch, login_rate, risk_score, risk_level)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [username, ip, location, device, fp_mismatch, loginRate, score, level]
        );

        await client.end();
        return res.status(200).json({ risk_level: level, score: score });

    } catch (err) {
        if (client) await client.end();
        return res.status(500).json({ error: err.message });
    }
}