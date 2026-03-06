import pkg from 'pg';
const { Client } = pkg;
// import nodemailer from 'nodemailer'; // ปลดคอมเมนต์เมื่อตั้งค่าเมลแล้ว

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ดึงข้อมูล User และประวัติเครื่องที่อนุญาต
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const { email, authorized_fingerprint: savedFp } = userRes.rows[0];
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 2. เช็คประวัติการพยายามล็อกอินผิดใน 15 นาทีล่าสุด (Aggregation)
        const recentFailRes = await client.query(
            "SELECT COUNT(*) as attempts FROM login_risks WHERE username = $1 AND is_success = FALSE AND updated_at > NOW() - INTERVAL '15 minutes'",
            [username]
        );
        const attempts = parseInt(recentFailRes.rows[0].attempts);

        // 3. คำนวณความเสี่ยงแบบละเอียด
        let score = 0.1; 
        
        // ความเสี่ยงจากจำนวนครั้งที่ผิด
        if (attempts >= 3) score += 0.3; // ผิด 3 ครั้ง เริ่มเสี่ยง (0.4 = MEDIUM)
        if (attempts >= 5) score += 0.6; // ผิด 5 ครั้ง เสี่ยงสูง (0.7+ = HIGH)

        // ความเสี่ยงจากการเปลี่ยนเครื่อง
        if (!fp_match) score += 0.4; // ถ้าเปลี่ยนเครื่อง คะแนนจะพุ่งไปที่ MEDIUM ทันที

        const finalScore = Math.min(score, 1.0);
        const level = finalScore >= 0.7 ? "HIGH" : (finalScore >= 0.4 ? "MEDIUM" : "LOW");

        // 4. จัดการรหัส MFA เมื่อเป็น MEDIUM
        let mfaCode = null;
        if (level === "MEDIUM") {
            mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
            
            // --- โค้ดส่ง Email (ตัวอย่าง) ---
            /*
            let transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: 'your-email@gmail.com', pass: 'your-app-password' } });
            await transporter.sendMail({
                from: '"Security System" <your-email@gmail.com>',
                to: email,
                subject: "Your MFA Code",
                text: `Your security code is: ${mfaCode}`
            });
            */
            console.log(`MFA Code for ${username}: ${mfaCode} (Sent to ${email})`);
        }

        // 5. บันทึก Log การประเมินครั้งนี้
        const result = await client.query(
            `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, mfa_code, is_success) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
            [username, ip, device, fingerprint, fp_match, finalScore, level, mfaCode]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}