import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ดึงข้อมูล User (ดึง email มาด้วยเพื่อเตรียมส่ง MFA)
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const { email, authorized_fingerprint: savedFp } = userRes.rows[0];
        
        // เช็คว่าเครื่องปัจจุบันตรงกับที่เคยลงทะเบียนไว้ไหม
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 2. จัดการ Log Aggregation
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

        // 3. คำนวณความเสี่ยง
        let score = 0.1;
        if (attempts >= 2 && attempts < 4) score = 0.3;
        else if (attempts >= 4) score = 0.6;
        
        if (fp_match === false) score += 0.4; // ถ้าเปลี่ยนเครื่อง คะแนนจะพุ่งไป 0.5 (MEDIUM) ทันที

        const finalScore = Math.min(score, 1.0);
        const level = finalScore >= 0.7 ? "HIGH" : (finalScore >= 0.4 ? "MEDIUM" : "LOW");

        // --- จุดสำคัญ: สร้าง MFA Code เมื่อความเสี่ยงคือ MEDIUM ---
        let mfaCode = null;
        if (level === "MEDIUM") {
            mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
            
            // TODO: เพิ่มโค้ดส่งรหัส mfaCode เข้าไปที่ email ของผู้ใช้ที่นี่
            console.log(`MFA for ${username}: ${mfaCode} sent to ${email}`);
        }

        // 4. บันทึกลงฐานข้อมูล (รวม mfa_code เข้าไปด้วย)
        if (logId) {
            await client.query(
                `UPDATE login_risks 
                 SET attempts = $1, risk_score = $2, risk_level = $3, 
                     fingerprint_match = $4, current_fingerprint = $5, 
                     mfa_code = $6, updated_at = NOW() 
                 WHERE id = $7`,
                [attempts, finalScore, level, fp_match, fingerprint, mfaCode, logId]
            );
        } else {
            const result = await client.query(
                `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, attempts, risk_score, risk_level, mfa_code) 
                 VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8) RETURNING id`,
                [username, ip, device, fingerprint, fp_match, finalScore, level, mfaCode]
            );
            logId = result.rows[0].id;
        }

        res.status(200).json({ risk_level: level, logId });

    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}