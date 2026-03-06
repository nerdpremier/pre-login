import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ดึงข้อมูลเครื่องเดิมที่เคยใช้อยู่
        const userRes = await client.query("SELECT authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const savedFp = userRes.rows[0].authorized_fingerprint;
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 2. คำนวณความเสี่ยง
        let score = 0.1;
        if (!fp_match) score += 0.4; // เปลี่ยนเครื่อง = 0.5 (MEDIUM)

        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 3. สร้างรหัส MFA หากเป็น MEDIUM
        let mfaCode = null;
        if (level === "MEDIUM") {
            mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
            // ตรงนี้ถ้ามี nodemailer ให้ใส่โค้ดส่งเมลที่นี่
            console.log(`MFA for ${username}: ${mfaCode}`);
        }

        // 4. บันทึกลงตาราง login_risks (ต้องมีคอลัมน์ mfa_code ใน DB)
        const result = await client.query(
            `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, mfa_code, is_success) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
            [username, ip, device, fingerprint, fp_match, score, level, mfaCode]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}