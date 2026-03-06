import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {

    if (req.method !== 'POST') {
        return res.status(405).json({ error: "Method not allowed" });
    }

    const { logId, code } = req.body;

    if (!logId || !code) {
        return res.status(400).json({ error: "Missing parameters" });
    }

    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {
        await client.connect();

        // ตรวจสอบ MFA code
        const result = await client.query(
            `SELECT id, mfa_code, is_success, expires_at
             FROM login_risks
             WHERE id = $1`,
            [logId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Login session not found" });
        }

        const login = result.rows[0];

        // ตรวจสอบว่าถูกใช้แล้วหรือยัง
        if (login.is_success === true) {
            return res.status(400).json({ error: "MFA already verified" });
        }

        // ตรวจสอบหมดเวลา
        if (login.expires_at && new Date(login.expires_at) < new Date()) {
            return res.status(401).json({ error: "MFA code expired" });
        }

        // ตรวจสอบ code
        if (login.mfa_code !== code) {
            return res.status(401).json({ error: "Invalid code" });
        }

        // อัปเดตสถานะ login success
        await client.query(
            `UPDATE login_risks 
             SET is_success = TRUE,
                 updated_at = NOW()
             WHERE id = $1`,
            [logId]
        );

        return res.status(200).json({ success: true });

    } catch (err) {

        return res.status(500).json({ error: err.message });

    } finally {

        await client.end();

    }
}