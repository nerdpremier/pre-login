import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    const { logId, code } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        // 1. ตรวจสอบรหัสในฐานข้อมูล
        const result = await client.query(
            "SELECT * FROM login_risks WHERE id = $1 AND mfa_code = $2 AND created_at > NOW() - INTERVAL '10 minutes'",
            [logId, code]
        );

        if (result.rows.length > 0) {
            const username = result.rows[0].username;
            const fingerprint = result.rows[0].current_fingerprint;

            // 2. อัปเดตให้เครื่องนี้เป็นเครื่องที่ได้รับอนุญาต
            await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
            
            res.status(200).json({ success: true });
        } else {
            res.status(401).json({ error: "Invalid Code" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    } finally {
        await client.end();
    }
}