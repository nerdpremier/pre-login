import pkg from 'pg';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const { username, password, risk_level, logId, remember, fingerprint } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const userRes = await client.query("SELECT * FROM users WHERE username = $1", [username]);
        const user = userRes.rows[0];

        // 1. ตรวจสอบรหัสผ่านก่อน
        if (user && await bcrypt.compare(password, user.password_hash)) {
            
            // 2. ถ้าความเสี่ยงคือ MEDIUM (เครื่องใหม่) -> บังคับทำ MFA
            if (risk_level === 'MEDIUM') {
                const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();

                // บันทึกรหัสลง Log เพื่อรอการ Verify
                await client.query(
                    "UPDATE login_risks SET mfa_code = $1, updated_at = NOW() WHERE id = $2",
                    [mfaCode, logId]
                );

                // ส่งอีเมลหา User
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
                });

                await transporter.sendMail({
                    from: '"Security System" <no-reply@yourdomain.com>',
                    to: user.email,
                    subject: '🔒 รหัสยืนยันการเข้าสู่ระบบของคุณ',
                    html: `<h2>รหัสยืนยันคือ: <b style="color:blue;">${mfaCode}</b></h2><p>รหัสนี้มีอายุ 5 นาที</p>`
                });

                return res.status(200).json({ mfa_required: true });
            }

            // 3. ถ้าความเสี่ยงต่ำ (LOW) และ User อยากให้จำเครื่อง
            if (remember && fingerprint) {
                await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
            }
            
            await client.query("UPDATE login_risks SET is_success = TRUE WHERE id = $1", [logId]);
            return res.status(200).json({ success: true });
        }

        return res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}