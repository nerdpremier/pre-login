import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ค้นหา Log ล่าสุดของ User นี้ที่ "ยังไม่สำเร็จ" ภายใน 15 นาทีที่ผ่านมา
        const recentLog = await client.query(
            `SELECT id, attempts FROM login_risks 
             WHERE username = $1 AND ip_address = $2 AND is_success = FALSE 
             AND updated_at > NOW() - INTERVAL '15 minutes' 
             ORDER BY updated_at DESC LIMIT 1`,
            [username, ip]
        );

        let logId = null;
        let currentAttempts = 1;

        if (recentLog.rows.length > 0) {
            logId = recentLog.rows[0].id;
            currentAttempts = recentLog.rows[0].attempts + 1; // บวกจำนวนครั้งเพิ่ม
        }

        // 2. เช็คการเปลี่ยนเครื่อง (Fingerprint)
        const userRes = await client.query("SELECT authorized_fingerprint FROM users WHERE username = $1", [username]);
        const savedFp = userRes.rows.length > 0 ? userRes.rows[0].authorized_fingerprint : null;
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 3. คำนวณความเสี่ยง (Risk Score)
        // สูตร: $score = base + (attempts \times 0.1) + (fp\_mismatch \times 0.4)$
        let score = 0.1;
        if (!fp_match) score += 0.4;
        if (currentAttempts >= 3) score += 0.2;
        
        // กำหนดระดับความเสี่ยง
        let level = "LOW";
        if (currentAttempts >= 5 || score >= 0.7) {
            level = "HIGH"; // ล็อกเอาท์หรือบล็อก
        } else if (score >= 0.4) {
            level = "MEDIUM"; // ต้องใช้ MFA (แต่ยังไม่ส่งเมลที่นี่!)
        }

        // 4. บันทึกลงฐานข้อมูล (ถ้ามี Log เดิมให้ Update ถ้าไม่มีให้ Insert)
        if (logId) {
            await client.query(
                `UPDATE login_risks 
                 SET attempts = $1, risk_score = $2, risk_level = $3, updated_at = NOW(), mfa_code = NULL 
                 WHERE id = $4`,
                [currentAttempts, score, level, logId]
            );
        } else {
            const result = await client.query(
                `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, attempts, risk_score, risk_level, is_success) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
                [username, ip, device, fingerprint, fp_match, currentAttempts, score, level]
            );
            logId = result.rows[0].id;
        }

        // ส่งแค่ระดับความเสี่ยงและ logId กลับไป (ห้ามส่ง mfa_code หรือส่งเมลที่นี่)
        res.status(200).json({ risk_level: level, logId: logId });

    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}