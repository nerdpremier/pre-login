import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fp_mismatch } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. เช็ค User (Prepared Statement)
        const userCheck = await client.query("SELECT id FROM users WHERE username = $1", [username]);
        if (userCheck.rows.length === 0) {
            return res.status(200).json({ risk_level: "LOW", logId: null });
        }

        // 2. ลบ Log เก่า 15 นาที
        await client.query("DELETE FROM login_risks WHERE updated_at < NOW() - INTERVAL '15 minutes'");

        // 3. หา Record เดิมเพื่อรวม ID (Aggregation)
        const existing = await client.query(
            "SELECT id, attempts FROM login_risks WHERE username = $1 AND ip_address = $2 AND is_success = FALSE LIMIT 1",
            [username, ip]
        );

        let attempts = 1;
        let logId = null;
        if (existing.rows.length > 0) {
            attempts = existing.rows[0].attempts + 1;
            logId = existing.rows[0].id;
        }

        // 4. RISK LOGIC (Score 0.1 - 1.0)
        let score = 0.1; 
        if (attempts >= 2 && attempts < 4) score = 0.3;
        else if (attempts >= 4) score = 0.6; // เพดานพฤติกรรม 0.6

        // ถ้าเครื่องใหม่/เปลี่ยนเครื่อง (fp_mismatch เป็น true) บวกเพิ่ม 0.4
        if (fp_mismatch === true) score += 0.4; 

        const finalScore = Math.min(score, 1.0);
        const level = finalScore >= 0.7 ? "HIGH" : (finalScore >= 0.4 ? "MEDIUM" : "LOW");

        if (logId) {
            await client.query(
                "UPDATE login_risks SET attempts = $1, risk_score = $2, risk_level = $3, fingerprint_mismatch = $4, updated_at = NOW() WHERE id = $5",
                [attempts, finalScore, level, fp_mismatch, logId]
            );
        } else {
            const result = await client.query(
                `INSERT INTO login_risks (username, ip_address, device_info, fingerprint_mismatch, attempts, risk_score, risk_level) 
                 VALUES ($1, $2, $3, $4, 1, $5, $6) RETURNING id`,
                [username, ip, device, fp_mismatch, finalScore, level]
            );
            logId = result.rows[0].id;
        }

        res.status(200).json({ risk_level: level, logId });
    } catch (err) { res.status(500).json({ error: "Risk Calculation Error" }); }
    finally { await client.end(); }
}