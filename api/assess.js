import pkg from 'pg';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { username, fingerprint } = req.body;
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW" });

        const { email, authorized_fingerprint } = userRes.rows[0];
        const fp_match = (authorized_fingerprint === fingerprint);
        let mfa = null; let risk = "LOW";

        // กรณีเครื่องใหม่ และเคยมีเครื่องเดิมบันทึกไว้แล้ว
        if (!fp_match && authorized_fingerprint !== null) {
            risk = "MEDIUM";
            mfa = Math.floor(100000 + Math.random() * 900000).toString();

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: { 
                    user: process.env.EMAIL_USER, // เมลของคุณ
                    pass: process.env.EMAIL_PASS  // รหัส 16 หลักที่ได้จาก Google
                }
            });

            await transporter.sendMail({
                from: '"Security System" <no-reply@security.com>',
                to: email,
                subject: `Your Verification Code: ${mfa}`,
                html: `<div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                        <h2>New Device Detected</h2>
                        <p>Please use this code to verify your identity:</p>
                        <h1 style="color: #3b82f6; letter-spacing: 5px;">${mfa}</h1>
                       </div>`
            });
        }

        const result = await client.query(
            "INSERT INTO login_risks (username, current_fingerprint, fingerprint_match, mfa_code, risk_level) VALUES ($1,$2,$3,$4,$5) RETURNING id",
            [username, fingerprint, fp_match, mfa, risk]
        );
        res.status(200).json({ risk_level: risk, logId: result.rows[0].id });
    } catch (e) { res.status(500).json({ error: e.message }); }
    finally { await client.end(); }
}