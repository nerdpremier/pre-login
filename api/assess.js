import pkg from 'pg';
import nodemailer from 'nodemailer';
const { Client } = pkg;

export default async function handler(req, res) {
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { username, fingerprint } = req.body;

        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        
        // ถ้าไม่เจอ User ให้บันทึกเป็น Unknown และจบงาน
        if (userRes.rows.length === 0) {
            await client.query("INSERT INTO login_risks (username, current_fingerprint, risk_level) VALUES ($1, $2, 'UNKNOWN')", [username, fingerprint]);
            return res.status(200).json({ risk_level: "LOW" });
        }

        const { email, authorized_fingerprint } = userRes.rows[0];
        const fp_match = (authorized_fingerprint === fingerprint);
        let mfa = null; 
        let risk = fp_match || authorized_fingerprint === null ? "LOW" : "MEDIUM";

        // ถ้าความเสี่ยงกลาง (เปลี่ยนเครื่อง) ให้สร้างรหัส MFA และส่งเมล
        if (risk === "MEDIUM") {
            mfa = Math.floor(100000 + Math.random() * 900000).toString();
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
            });
            await transporter.sendMail({
                from: `"Secure System" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: `Login Code: ${mfa}`,
                html: `<h1>Your Code: ${mfa}</h1>`
            });
        }

        // 📝 บันทึก Log ทุกครั้งลงฐานข้อมูล
        const logResult = await client.query(
            "INSERT INTO login_risks (username, current_fingerprint, mfa_code, risk_level) VALUES ($1, $2, $3, $4) RETURNING id",
            [username, fingerprint, mfa, risk]
        );

        res.status(200).json({ risk_level: risk, logId: logResult.rows[0].id });
    } catch (e) {
        res.status(500).json({ error: e.message });
    } finally {
        await client.end();
    }
}