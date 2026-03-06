import pkg from 'pg';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    // ป้องกันการเรียกใช้ที่ไม่ใช่ POST
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const client = new Client({ 
        connectionString: process.env.DATABASE_URL, 
        ssl: { rejectUnauthorized: false } 
    });

    try {
        await client.connect();
        const { username, fingerprint } = req.body;

        // ดึงข้อมูล User
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        
        if (userRes.rows.length === 0) {
            return res.status(200).json({ risk_level: "LOW" });
        }

        const { email, authorized_fingerprint } = userRes.rows[0];
        const fp_match = (authorized_fingerprint === fingerprint);
        let mfa = null; 
        let risk = "LOW";

        // ตรวจสอบว่าเป็นเครื่องใหม่หรือไม่ (และต้องเคยมีเครื่องที่ลงทะเบียนไว้แล้ว)
        if (!fp_match && authorized_fingerprint !== null) {
            risk = "MEDIUM";
            mfa = Math.floor(100000 + Math.random() * 900000).toString();

            // ส่ง Email
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: { 
                    user: process.env.EMAIL_USER, 
                    pass: process.env.EMAIL_PASS // ต้องเป็น App Password 16 หลัก
                }
            });

            await transporter.sendMail({
                from: `"Security System" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: `Verification Code: ${mfa}`,
                html: `<div style="font-family:sans-serif;padding:20px;border:1px solid #ddd;border-radius:10px;">
                        <h2 style="color:#3b82f6;">Identity Verification</h2>
                        <p>A sign-in attempt was made from a new device. Use this code to verify:</p>
                        <h1 style="letter-spacing:10px;text-align:center;background:#f8fafc;padding:10px;">${mfa}</h1>
                       </div>`
            });
        }

        // บันทึก Log การตรวจความเสี่ยง
        const result = await client.query(
            "INSERT INTO login_risks (username, current_fingerprint, fingerprint_match, mfa_code, risk_level) VALUES ($1,$2,$3,$4,$5) RETURNING id",
            [username, fingerprint, fp_match, mfa, risk]
        );

        res.status(200).json({ risk_level: risk, logId: result.rows[0].id });

    } catch (e) {
        console.error("ERROR_LOG:", e.message); // ดู Error จริงได้ใน Vercel Logs
        res.status(500).json({ error: "Server Error: " + e.message });
    } finally {
        await client.end();
    }
}