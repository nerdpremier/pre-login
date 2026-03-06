import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    
    const { logId, code, remember } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();

        // 1. ตรวจสอบรหัส MFA พร้อมเช็คเวลาหมดอายุ (ภายใน 5 นาทีหลังจากการส่งรหัส)
        // ใช้เงื่อนไข: updated_at > NOW() - INTERVAL '5 minutes'
        const result = await client.query(
            `SELECT username, current_fingerprint FROM login_risks 
             WHERE id = $1 
             AND mfa_code = $2 
             AND is_success = FALSE 
             AND updated_at > NOW() - INTERVAL '5 minutes'`, 
            [logId, code]
        );

        if (result.rows.length > 0) {
            const { username, current_fingerprint } = result.rows[0];

            // เริ่ม Transaction
            await client.query('BEGIN');

            // 2. ยืนยันสำเร็จ: อัปเดตสถานะ และล้างรหัส MFA ทิ้ง (ป้องกัน Replay Attack)
            await client.query(
                "UPDATE login_risks SET is_success = TRUE, mfa_code = NULL, updated_at = NOW() WHERE id = $1", 
                [logId]
            );

            // 3. จดจำอุปกรณ์ตามความต้องการของ User
            if (remember === true) {
                await client.query(
                    "UPDATE users SET authorized_fingerprint = $1 WHERE username = $2",
                    [current_fingerprint, username]
                );
            }

            await client.query('COMMIT');
            res.status(200).json({ success: true });
        } else {
            // หากไม่พบข้อมูล อาจเป็นเพราะรหัสผิด หรือรหัสหมดอายุเกิน 5 นาที
            res.status(401).json({ error: "รหัสยืนยันไม่ถูกต้อง หรือหมดอายุแล้ว (รหัสมีอายุ 5 นาที)" });
        }
    } catch (err) {
        if (client) await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}