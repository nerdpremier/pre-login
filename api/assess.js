import pkg from 'pg';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');

    const client = new Client({ 
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {
        await client.connect();
        const { username, fingerprint } = req.body;

        // ดึงข้อมูล User
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW" });

        const { email, authorized_fingerprint } = userRes.rows[0];
        const fp_match = (authorized_fingerprint === fingerprint);
        let mfa = null; 
        let risk = "LOW";

        // กรณีเครื่องใหม่
        if (!fp_match && authorized_fingerprint !== null) {
            risk = "MEDIUM";
            mfa = Math.floor(100000 + Math.random() * 900000).toString();

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
            });

            await transporter.sendMail({
                from: `"Security System" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: `Verification Code: ${mfa}`,
                html: `<div style="font-family:sans-serif;padding:20px;background:#f8fafc;border-radius:12px;">
                        <h2 style="color:#1e293b;">Security Verification</h2>
                        <p>Your verification code is:</p>
                        <h1 style="color:#3b82f6;letter-spacing:10px;font-size:40px;">${mfa}</h1>
                       </div>`
            });
        }

        const result = await client.query(
            "INSERT INTO login_risks (username, current_fingerprint, fingerprint_match, mfa_code, risk_level) VALUES ($1,$2,$3,$4,$5) RETURNING id",
            [username, fingerprint, fp_match, mfa, risk]
        );

        res.status(200).json({ risk_level: risk, logId: result.rows[0].id });
    } catch (e) {
        res.status(500).json({ error: e.message });
    } finally {
        await client.end();
    }
}
