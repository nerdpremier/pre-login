import pkg from 'pg';
import nodemailer from 'nodemailer'; // เพิ่มบรรทัดนี้เพื่อเรียกใช้ Nodemailer
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. ดึงข้อมูล User และดึง Email มาด้วย (สำคัญมาก ต้องดึงมาให้ได้)
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const { email, authorized_fingerprint: savedFp } = userRes.rows[0];
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 2. คำนวณความเสี่ยง
        let score = 0.1;
        if (!fp_match) score += 0.4; // เครื่องเปลี่ยน = 0.5 (MEDIUM)

        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 3. สร้างรหัส MFA และ "ส่งอีเมล" หากเป็น MEDIUM
        let mfaCode = null;
        if (level === "MEDIUM") {
            mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
            
            // --- ระบบส่งอีเมลด้วย Nodemailer ---
            try {
                const transporter = nodemailer.createTransport({
                    service: 'gmail', // ถ้าใช้ Gmail
                    auth: {
                        user: process.env.EMAIL_USER, // ดึงจาก Environment Variable
                        pass: process.env.EMAIL_PASS  // ดึงจาก Environment Variable
                    }
                });

                const mailOptions = {
                    from: `"ระบบรักษาความปลอดภัย" <${process.env.EMAIL_USER}>`,
                    to: email, // ส่งไปที่อีเมลของ User ที่ได้จาก Database
                    subject: '🔒 รหัสยืนยันตัวตน (MFA Code) สำหรับการเข้าสู่ระบบ',
                    html: `
                        <h2>ตรวจพบการเข้าสู่ระบบจากอุปกรณ์ใหม่</h2>
                        <p>คุณ <b>${username}</b>,</p>
                        <p>เราพบความพยายามเข้าสู่ระบบจากอุปกรณ์ที่ยังไม่เคยได้รับการยืนยัน</p>
                        <p>รหัสยืนยันตัวตน (MFA) 6 หลักของคุณคือ:</p>
                        <h1 style="color: #3b82f6; letter-spacing: 5px;">${mfaCode}</h1>
                        <p><i>โปรดอย่านำรหัสนี้ไปให้บุคคลอื่นเด็ดขาด</i></p>
                    `
                };

                // สั่งส่งอีเมล
                await transporter.sendMail(mailOptions);
                console.log(`✅ ส่ง MFA Code ไปที่อีเมล ${email} สำเร็จ!`);

            } catch (mailError) {
                console.error("❌ เกิดข้อผิดพลาดในการส่งอีเมล:", mailError);
                // ระบบอาจจะเดินต่อได้แม้เมลส่งไม่ผ่าน แต่เก็บ error ไว้ดู
            }
        }

        // 4. บันทึกลงตาราง login_risks
        const result = await client.query(
            `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, mfa_code, is_success) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
            [username, ip, device, fingerprint, fp_match, score, level, mfaCode]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}