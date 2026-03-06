import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const client = new Client({ 
        connectionString: process.env.DATABASE_URL, 
        ssl: { rejectUnauthorized: false } 
    });

    try {
        await client.connect();
        const { action, username, email, password, fingerprint } = req.body;

        // --- ระบบสมัครสมาชิก (REGISTER) ---
        if (action === 'register') {
            // 1. ตรวจสอบว่ามี User หรือ Email นี้ในระบบหรือยัง
            const checkUser = await client.query(
                "SELECT id FROM users WHERE username = $1 OR email = $2", 
                [username, email]
            );

            if (checkUser.rows.length > 0) {
                return res.status(400).json({ error: "Username or Email already taken" });
            }

            // 2. ถ้าไม่มี ให้บันทึกข้อมูลใหม่ลงไป
            // หมายเหตุ: ในโปรเจกต์จริงควรใช้ bcrypt.hash(password, 10) เพื่อความปลอดภัย
            await client.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
                [username, email, password] 
            );

            return res.status(201).json({ message: "Registration successful" });
        }

        // --- ระบบล็อกอิน (LOGIN) ---
        if (action === 'login') {
            const userRes = await client.query(
                "SELECT * FROM users WHERE username = $1 AND password_hash = $2",
                [username, password]
            );

            if (userRes.rows.length === 0) {
                return res.status(401).json({ error: "Invalid username or password" });
            }

            // ถ้าล็อกอินผ่าน และเป็นเครื่องใหม่ (Fingerprint ยังเป็น NULL) ให้บันทึกเครื่องแรกทันที
            if (!userRes.rows[0].authorized_fingerprint) {
                await client.query(
                    "UPDATE users SET authorized_fingerprint = $1 WHERE username = $2",
                    [fingerprint, username]
                );
            }

            return res.status(200).json({ message: "Login successful" });
        }

    } catch (e) {
        console.error("Auth Error:", e.message);
        return res.status(500).json({ error: "Server Database Error: " + e.message });
    } finally {
        await client.end();
    }
}