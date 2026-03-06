import pkg from 'pg';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer'; // เพิ่มเพื่อส่งเมล MFA
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    // รับค่าเพิ่ม: risk_level, logId, remember
    const { action, username, email, password, fingerprint, risk_level, logId, remember } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();

        if (action === 'register') {
            // 1. เช็คชื่อซ้ำ
            const userExist = await client.query("SELECT id FROM users WHERE username = $1", [username]);
            if (userExist.rows.length > 0) return res.status(400).json({ error: "ชื่อนี้ถูกใช้ไปแล้ว" });

            // 2. Hash และ Save
            const hashed = await bcrypt.hash(password, 10);
            await client.query("INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)", [username, email, hashed]);

            // 3. *** สำคัญมาก *** ต้อง return ทันที!
            return res.status(200).json({ success: true }); 
        } 
        
        else if (action === 'login') {
            const userRes = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            const user = userRes.rows[0];

            if (user && await bcrypt.compare(password, user.password_hash)) {
                
                // --- เพิ่มส่วน MFA สำหรับอุปกรณ์ใหม่ ---
                if (risk_level === 'MEDIUM') {
                    const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
                    
                    // บันทึกรหัสลง Log
                    await client.query("UPDATE login_risks SET mfa_code = $1, updated_at = NOW() WHERE id = $2", [mfaCode, logId]);

                    // ส่งเมล (ใช้ Nodemailer)
                    const transporter = nodemailer.createTransport({
                        service: 'gmail',
                        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
                    });
                    await transporter.sendMail({
                        from: '"Security System" <no-reply@yourdomain.com>',
                        to: user.email,
                        subject: '🔒 รหัสยืนยันการเข้าสู่ระบบ',
                        html: `<h2>รหัสคือ: <b style="color:blue;">${mfaCode}</b></h2>`
                    });

                    return res.status(200).json({ mfa_required: true });
                }

                // ถ้าจำเครื่อง (Low Risk)
                if (remember && fingerprint) {
                    await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
                }

                // อัปเดต Log ว่าสำเร็จ (เพื่อให้ Attempts รีเซ็ตในอนาคต หรือหยุดนับ)
                if (logId) await client.query("UPDATE login_risks SET is_success = TRUE WHERE id = $1", [logId]);

                return res.status(200).json({ success: true });
            }

            // กรณีรหัสผิด (ไม่ต้องทำอะไรเพิ่ม เพราะ api/assess บันทึก is_success = FALSE ไปแล้ว)
            return res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
        }
    } catch (err) { res.status(500).json({ error: err.message }); } 
    finally { await client.end(); }
}