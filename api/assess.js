import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    const { username, device, fingerprint } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        await client.connect();

        // 1. ค้นหา Log ล่าสุดของ User นี้ (ที่ยังไม่สำเร็จ ภายใน 15 นาที) เพื่อเช็คจำนวน Attempt
        const recentLog = await client.query(
            `SELECT id, attempts FROM login_risks 
             WHERE username = $1 AND ip_address = $2 AND is_success = FALSE 
             AND updated_at > NOW() - INTERVAL '15 minutes' 
             ORDER BY updated_at DESC LIMIT 1`,
            [username, ip]
        );

        let logId = recentLog.rows.length > 0 ? recentLog.rows[0].id : null;
        let currentAttempts = recentLog.rows.length > 0 ? recentLog.rows[0].attempts + 1 : 1;

        // 2. ตรวจสอบว่าเคย "จดจำอุปกรณ์" (Authorized Fingerprint) นี้ไว้หรือไม่
        const userRes = await client.query("SELECT authorized_fingerprint FROM users WHERE username = $1", [username]);
        
        // ถ้าไม่พบ User ให้มองเป็น LOW ไว้ก่อน (เพื่อไม่ให้แฮกเกอร์รู้ว่ามี Username นี้ในระบบจากความหน่วงของ MFA)
        if (userRes.rows.length === 0) {
            return res.status(200).json({ risk_level: "LOW", logId: null });
        }

        const savedFp = userRes.rows[0].authorized_fingerprint;
        const fp_match = savedFp ? (savedFp === fingerprint) : false; // ถ้าไม่มี savedFp เลย ให้ถือว่าเครื่องใหม่ (MFA)

        // 3. คำนวณความเสี่ยง (Risk Score)
        // สูตร: base(0.1) + mismatch(0.4) + attempts(>=3 ? 0.2)
        let score = 0.1;
        if (!fp_match) score += 0.4;        // เครื่องเปลี่ยน = เสี่ยง MEDIUM ทันที
        if (currentAttempts >= 3) score += 0.2; // พิมพ์ผิดบ่อย = เสี่ยงเพิ่ม
        
        let level = "LOW";
        if (currentAttempts >= 5 || score >= 0.7) {
            level = "HIGH";  // บล็อกการเข้าถึง
        } else if (score >= 0.4) {
            level = "MEDIUM"; // ต้องยืนยัน MFA
        }

        // 4. บันทึกข้อมูลลงใน login_risks
        // หมายเหตุ: ห้ามส่งอีเมลหรือสร้าง mfa_code ที่นี่! ให้ไปทำใน api/auth.js หลังจากรหัสผ่านถูกต้องแล้ว
        if (logId) {
            await client.query(
                `UPDATE login_risks 
                 SET attempts = $1, risk_score = $2, risk_level = $3, updated_at = NOW(), device_info = $4, current_fingerprint = $5, fingerprint_match = $6
                 WHERE id = $7`,
                [currentAttempts, score, level, device, fingerprint, fp_match, logId]
            );
        } else {
            const result = await client.query(
                `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, attempts, risk_score, risk_level, is_success) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
                [username, ip, device, fingerprint, fp_match, currentAttempts, score, level]
            );
            logId = result.rows[0].id;
        }

        // ส่งระดับความเสี่ยงและ logId กลับไปให้หน้าบ้าน
        res.status(200).json({ risk_level: level, logId: logId });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        await client.end();
    }
}