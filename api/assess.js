import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ตรวจสอบข้อมูลผู้ใช้เดิม
        const userRes = await client.query("SELECT authorized_fingerprint FROM users WHERE username = $1", [username]);
        const savedFp = userRes.rows.length > 0 ? userRes.rows[0].authorized_fingerprint : null;
        
        // ถ้าเป็น User ใหม่ หรือเครื่องตรงกัน fp_match = true
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 2. คำนวณความเสี่ยง
        let score = 0.1;
        if (!fp_match) score += 0.4; // เปลี่ยนเครื่องปุ๊บ กลายเป็น 0.5 (MEDIUM)

        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 3. สร้าง MFA Code ถ้าความเสี่ยงระดับ MEDIUM
        let mfaCode = null;
        if (level === "MEDIUM") {
            mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
            console.log(`MFA Code for ${username}: ${mfaCode}`); // สำหรับทดสอบดูใน Vercel Log
        }

        // 4. บันทึกลงตาราง login_risks เสมอ (สำคัญ!)
        const result = await client.query(
            `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, mfa_code, is_success) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
            [username, ip, device, fingerprint, fp_match, score, level, mfaCode]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        await client.end();
    }
}