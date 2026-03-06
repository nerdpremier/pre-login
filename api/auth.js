import pkg from 'pg';
import bcrypt from 'bcryptjs'; // อย่าลืมเพิ่มใน package.json

const { Client } = pkg;

export default async function handler(req, res) {
    const { action, username, password } = req.body;
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {
        await client.connect();

        if (action === 'register') {
            // 1. ลงทะเบียน (Hash รหัสผ่านก่อนเก็บ)
            const hashedPassword = await bcrypt.hash(password, 10);
            await client.query(
                "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
                [username, hashedPassword]
            );
            return res.status(200).json({ message: "Register Success!" });

        } else if (action === 'login') {
            // 2. ตรวจสอบ Login
            const userRes = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            if (userRes.rows.length === 0) return res.status(401).json({ error: "User not found" });

            const validPassword = await bcrypt.compare(password, userRes.rows[0].password_hash);
            if (!validPassword) return res.status(401).json({ error: "Invalid password" });

            return res.status(200).json({ message: "Login Successful!", user: username });
        }

    } catch (err) {
        return res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}