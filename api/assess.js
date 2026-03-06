import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ดึงข้อมูล User และข้อมูลความเสี่ยงล่าสุดจากแถวเดียว
        const userRes = await client.query(`
            SELECT u.authorized_fingerprint, lr.attempts, lr.is_success, lr.updated_at 
            FROM users u
            LEFT JOIN login_risks lr ON u.username = lr.username
            WHERE u.username = $1`, [username]);
        
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const userData = userRes.rows[0];
        const fp_match = userData.authorized_fingerprint === fingerprint;

        // 2. คำนวณ currentAttempt จากเลขใน DB
        let currentAttempt = 1;
        // ถ้าเคยมีประวัติ และ (ครั้งล่าสุดผิดพลาด) และ (ยังไม่เกิน 5 นาที) ให้บวกเพิ่ม
        const isRecent = userData.updated_at && (new Date() - new Date(userData.updated_at) < 5 * 60 * 1000);
        if (userData.attempts && !userData.is_success && isRecent) {
            currentAttempt = parseInt(userData.attempts) + 1;
        }

        // 3. คำนวณความเสี่ยง (Risk Scoring)
        let score = 0.1;
        if (!fp_match) score += 0.4; 
        if (currentAttempt > 3) score += 0.3; 
        if (currentAttempt > 5) score = 1.0; 

        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 4. UPSERT: บันทึกหรืออัปเดต (ใช้คำสั่งที่คุณเขียนมา แต่ปรับปรุงนิดหน่อย)
        const result = await client.query(
            `INSERT INTO login_risks 
                (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, attempts, is_success, updated_at) 
             VALUES 
                ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, NOW()) 
             ON CONFLICT (username) 
             DO UPDATE SET 
                ip_address = EXCLUDED.ip_address,
                device_info = EXCLUDED.device_info,
                current_fingerprint = EXCLUDED.current_fingerprint,
                fingerprint_match = EXCLUDED.fingerprint_match,
                attempts = $8, -- ใช้ค่าที่เราคำนวณไว้ข้างบน
                risk_score = EXCLUDED.risk_score,
                risk_level = EXCLUDED.risk_level,
                is_success = FALSE,
                updated_at = NOW()
             RETURNING id`,
            [username, ip, device, fingerprint, fp_match, score, level, currentAttempt]
        );

        res.status(200).json({ 
            risk_level: level, 
            logId: result.rows[0].id, 
            attempts: currentAttempt 
        });

    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}