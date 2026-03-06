import pkg from 'pg';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    
    // รับค่า 'remember' เพิ่มเติมจาก req.body
    const { action, username, email, password, fingerprint, logId, risk_level, remember } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();

        // --- กรณีสมัครสมาชิก (Register) ---
        if (action === 'register') {
            if (!/^[a-zA-Z0-9]+$/.test(username)) return res.status(400).json({ error: "Username ภาษาอังกฤษเท่านั้น" });
            if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password)) {
                return res.status(400).json({ error: "Password ไม่ปลอดภัยพอ" });
            }
            const hashed = await bcrypt.hash(password, 10);
            await client.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)", 
                [username, email, hashed]
            );
            return res.status(200).json({ success: true });
        } 
        
        // --- กรณีล็อกอิน (Login) ---
        else if (action === 'login') {
            const userQuery = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            const user = userQuery.rows[0];

            // 1. ตรวจสอบรหัสผ่าน
            if (user && await bcrypt.compare(password, user.password_hash)) {
                
                // 2. กรณีความเสี่ยงปานกลาง (MEDIUM) -> ส่ง MFA
                if (risk_level === 'MEDIUM') {
                    const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
                    
                    const transporter = nodemailer.createTransport({
                        service: 'gmail',
                        auth: {
                            user: process.env.EMAIL_USER,
                            pass: process.env.EMAIL_PASS
                        }
                    });

                    await transporter.sendMail({
                        from: `"Security System" <${process.env.EMAIL_USER}>`,
                        to: user.email,
                        subject: '🔒 รหัสยืนยันตัวตนสำหรับการเข้าสู่ระบบ',
                        html: `<h3>รหัส MFA ของคุณคือ: <b style="font-size: 24px; color: blue;">${mfaCode}</b></h3><p>รหัสนี้จะหมดอายุในไม่ช้า</p>`
                    });

                    if (logId) {
                        await client.query(
                            "UPDATE login_risks SET mfa_code = $1, updated_at = NOW() WHERE id = $2",
                            [mfaCode, logId]
                        );
                    }

                    return res.status(200).json({ mfa_required: true });
                }

                // 3. กรณีความเสี่ยงต่ำ (LOW) -> ล็อกอินสำเร็จ
                if (logId) {
                    await client.query("UPDATE login_risks SET is_success = TRUE, updated_at = NOW() WHERE id = $1", [logId]);
                }
                
                // 4. เงื่อนไขการบันทึก Fingerprint (จดจำอุปกรณ์)
                // จะบันทึกก็ต่อเมื่อ User ติ๊กถูก (remember === true) และเป็นเครื่องที่ยังไม่เคยจดจำ
                if (remember === true && fingerprint) {
                    await client.query(
                        "UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", 
                        [fingerprint, username]
                    );
                }

                return res.status(200).json({ success: true });

            } else {
                return res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
            }
        }
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}