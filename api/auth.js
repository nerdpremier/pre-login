import pkg from 'pg';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    
    // รับ action เพิ่มเข้ามาเพื่อแยกระหว่าง login กับ register
    const { action, username, email, password, risk_level, logId, remember, fingerprint } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();

        // ----------------- ส่วนที่ 1: สมัครสมาชิก (REGISTER) -----------------
        if (action === 'register') {
            // เช็คว่ามี username หรือ email นี้หรือยัง
            const checkUser = await client.query("SELECT id FROM users WHERE username = $1 OR email = $2", [username, email]);
            if (checkUser.rows.length > 0) {
                return res.status(400).json({ error: "ชื่อผู้ใช้หรืออีเมลนี้ถูกใช้ไปแล้ว" });
            }

            // Hash รหัสผ่านก่อนบันทึก
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // บันทึกลงตาราง users
            await client.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
                [username, email, hashedPassword]
            );

            return res.status(200).json({ success: true });
        }

        // ----------------- ส่วนที่ 2: เข้าสู่ระบบ (LOGIN) -----------------
        // (โค้ดเดิมของคุณที่ทำไว้ดีอยู่แล้ว)
        const userRes = await client.query("SELECT * FROM users WHERE username = $1", [username]);
        const user = userRes.rows[0];

        if (user && await bcrypt.compare(password, user.password_hash)) {
            
            if (risk_level === 'MEDIUM') {
                const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
                await client.query(
                    "UPDATE login_risks SET mfa_code = $1, updated_at = NOW() WHERE id = $2",
                    [mfaCode, logId]
                );

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

            if (remember && fingerprint) {
                await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
            }
            
            await client.query("UPDATE login_risks SET is_success = TRUE WHERE id = $1", [logId]);
            return res.status(200).json({ success: true });
        }

        return res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}