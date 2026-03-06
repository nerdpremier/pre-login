import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ดึงข้อมูล User และนับจำนวน Attempts ที่ผิดพลาดล่าสุด (ในช่วง 5 นาที)
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        
        // ถ้าไม่เจอ User ให้ตีเป็น LOW เพื่อไปให้ด่าน api/auth ตอบว่า "รหัสผิด"
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const { authorized_fingerprint: savedFp } = userRes.rows[0];
        const fp_match = savedFp === fingerprint;

        // ดึงจำนวนครั้งที่ผิดมานับต่อ
        const attemptRes = await client.query(
            `SELECT COUNT(*) as count FROM login_risks 
             WHERE username = $1 AND is_success = FALSE 
             AND updated_at > NOW() - INTERVAL '5 minutes'`,
            [username]
        );
        const failAttempts = parseInt(attemptRes.rows[0].count);
        const currentAttempt = failAttempts + 1;

        // 2. คำนวณความเสี่ยง (Risk Scoring)
        let score = 0.1;
        if (!fp_match) score += 0.4; // เครื่องใหม่ = 0.5 (MEDIUM)
        
        // เพิ่มคะแนนตามจำนวนครั้งที่ผิด
        if (currentAttempt > 3) score += 0.3; // ผิดเกิน 3 ครั้งเสี่ยงสูงขึ้น
        if (currentAttempt > 5) score = 1.0;  // ผิดเกิน 5 ครั้ง บล็อคทันที

        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 3. บันทึกลงตาราง login_risks (ไม่ต้องส่งเมลที่นี่แล้ว!)
        const result = await client.query(
            `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, attempts, is_success) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
            [username, ip, device, fingerprint, fp_match, score, level, currentAttempt]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id, attempts: currentAttempt });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}