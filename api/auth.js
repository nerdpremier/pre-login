import pkg from 'pg';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    const { username, password, risk_level, logId, remember, fingerprint } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const user = (await client.query("SELECT * FROM users WHERE username = $1", [username])).rows[0];

        if (user && await bcrypt.compare(password, user.password_hash)) {
            if (risk_level === 'MEDIUM') {
                const code = Math.floor(100000 + Math.random() * 900000).toString();
                // บันทึกรหัส OTP
                await client.query("UPDATE login_risks SET mfa_code = $1 WHERE id = $2", [code, logId]);
                // ส่งเมล (Nodemailer)
                const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });
                await transporter.sendMail({ to: user.email, subject: 'Your OTP', text: `Code: ${code}` });
                return res.status(200).json({ mfa_required: true });
            }
            // ถ้า LOW
            if (remember) await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
            return res.status(200).json({ success: true });
        }
        res.status(401).json({ error: "Unauthorized" });
    } finally { await client.end(); }
}