import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const { logId, code, remember } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();

        // 1. ตรวจสอบรหัส + ตรวจสอบเวลาหมดอายุ (5 นาที)
        const checkResult = await client.query(
            `SELECT username, current_fingerprint FROM login_risks 
             WHERE id = $1 AND mfa_code = $2 AND is_success = FALSE 
             AND updated_at > NOW() - INTERVAL '5 minutes'`,
            [logId, code]
        );

        if (checkResult.rows.length > 0) {
            const { username, current_fingerprint } = checkResult.rows[0];

            await client.query('BEGIN'); // เริ่ม Transaction

            // 2. อัปเดตสถานะล็อกอินว่าสำเร็จ และล้างรหัส OTP
            await client.query(
                "UPDATE login_risks SET is_success = TRUE, mfa_code = NULL WHERE id = $1",
                [logId]
            );

            // 3. บันทึกอุปกรณ์ที่เชื่อถือได้ (Authorized Device) เฉพาะเมื่อ User ยินยอม
            if (remember === "true" || remember === true) {
                await client.query(
                    "UPDATE users SET authorized_fingerprint = $1 WHERE username = $2",
                    [current_fingerprint, username]
                );
            }

            await client.query('COMMIT');
            return res.status(200).json({ success: true });
        } else {
            return res.status(401).json({ error: "รหัสผิดหรือหมดอายุ" });
        }
    } catch (err) {
        if (client) await client.query('ROLLBACK');
        return res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}