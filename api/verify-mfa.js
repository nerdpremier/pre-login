import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    
    // รับค่า logId, code และ remember (ที่ส่งมาจากหน้าบ้าน)
    const { logId, code, remember } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();

        // 1. ตรวจสอบรหัส MFA และดึงข้อมูล username กับ fingerprint ที่บันทึกไว้ตอน assess
        const result = await client.query(
            "SELECT username, current_fingerprint FROM login_risks WHERE id = $1 AND mfa_code = $2", 
            [logId, code]
        );

        if (result.rows.length > 0) {
            const { username, current_fingerprint } = result.rows[0];

            // 2. ถ้า User เลือก "จดจำอุปกรณ์นี้" ให้บันทึก Fingerprint ลงตาราง users
            if (remember === true || remember === 'true') {
                await client.query(
                    "UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", 
                    [current_fingerprint, username]
                );
            }

            // 3. อัปเดตสถานะใน login_risks ว่าสำเร็จ และรีเซ็ตการนับ attempts
            await client.query(
                "UPDATE login_risks SET is_success = TRUE, attempts = 0, mfa_code = NULL WHERE id = $1", 
                [logId]
            );

            return res.status(200).json({ success: true });
        } else {
            // กรณีรหัสผิด
            return res.status(401).json({ error: "รหัสยืนยันไม่ถูกต้อง" });
        }
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}