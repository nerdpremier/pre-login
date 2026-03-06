import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ตรวจสอบ Fingerprint ที่บันทึกไว้
        const userRes = await client.query("SELECT authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const savedFp = userRes.rows[0].authorized_fingerprint;
        
        // LOGIC: ถ้ามีประวัติแล้วต้องตรงกันถึงจะเป็น TRUE (เครื่องเดิม)
        // ถ้าไม่ตรงจะเป็น FALSE (เปลี่ยนเครื่อง)
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 2. จัดการ Log Aggregation (รวมกลุ่มภายใน 15 นาที)
        await client.query("DELETE FROM login_risks WHERE updated_at < NOW() - INTERVAL '15 minutes'");
        const existing = await client.query(
            "SELECT id, attempts FROM login_risks WHERE username = $1 AND ip_address = $2 AND is_success = FALSE LIMIT 1",
            [username, ip]
        );

        let attempts = 1, logId = null;
        if (existing.rows.length > 0) {
            attempts = existing.rows[0].attempts + 1;
            logId = existing.rows[0].id;
        }

        // 3. คำนวณความเสี่ยง (Scale 1.0)
        let score = 0.1;
        if (attempts >= 2 && attempts < 4) score = 0.3;
        else if (attempts >= 4) score = 0.6;
        
        // ถ้าเปลี่ยนเครื่อง (fp_match เป็น false) บวกคะแนนความเสี่ยงเพิ่ม 0.4
        if (fp_match === false) score += 0.4;

        const finalScore = Math.min(score, 1.0);
        const level = finalScore >= 0.7 ? "HIGH" : (finalScore >= 0.4 ? "MEDIUM" : "LOW");

        if (logId) {
            await client.query(
                "UPDATE login_risks SET attempts = $1, risk_score = $2, risk_level = $3, fingerprint_match = $4, current_fingerprint = $5, updated_at = NOW() WHERE id = $6",
                [attempts, finalScore, level, fp_match, fingerprint, logId]
            );
        } else {
            const result = await client.query(
                `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, attempts, risk_score, risk_level) 
                 VALUES ($1, $2, $3, $4, $5, 1, $6, $7) RETURNING id`,
                [username, ip, device, fingerprint, fp_match, finalScore, level]
            );
            logId = result.rows[0].id;
        }
        res.status(200).json({ risk_level: level, logId });
    } catch (err) { res.status(500).json({ error: err.message }); }
    finally { await client.end(); }
}