import pkg from 'pg';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { username, fingerprint } = req.body;
        const user = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        
        if (user.rows.length === 0) return res.json({ risk_level: "LOW" });

        const { email, authorized_fingerprint } = user.rows[0];
        const fp_match = (authorized_fingerprint === fingerprint);
        let mfa = null; let risk = "LOW";

        if (!fp_match && authorized_fingerprint !== null) {
            risk = "MEDIUM";
            mfa = Math.floor(100000 + Math.random() * 900000).toString();

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
            });

            await transporter.sendMail({
                from: '"Security" <no-reply@security.com>',
                to: email,
                subject: `MFA Code: ${mfa}`,
                html: `<h1>Code: ${mfa}</h1>`
            });
        }

        const result = await client.query(
            "INSERT INTO login_risks (username, current_fingerprint, fingerprint_match, mfa_code, risk_level) VALUES ($1,$2,$3,$4,$5) RETURNING id",
            [username, fingerprint, fp_match, mfa, risk]
        );
        res.json({ risk_level: risk, logId: result.rows[0].id });
    } catch (e) { res.status(500).json({ error: e.message }); }
    finally { await client.end(); }
}