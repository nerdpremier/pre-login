import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    const client = new Client({ 
        connectionString: process.env.DATABASE_URL, 
        ssl: { rejectUnauthorized: false } 
    });

    try {
        await client.connect();
        const { action, username, email, password } = req.body;

        if (action === 'register') {
            // เช็ค User ซ้ำแบบพื้นฐาน
            const check = await client.query("SELECT id FROM users WHERE username = $1", [username]);
            if (check.rows.length > 0) return res.status(400).json({ error: "User already exists" });

            await client.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
                [username, email, password]
            );
            return res.status(201).json({ message: "Registration successful" });
        }

        if (action === 'login') {
            const user = await client.query(
                "SELECT * FROM users WHERE username = $1 AND password_hash = $2",
                [username, password]
            );
            if (user.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

            return res.status(200).json({ message: "Login successful" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    } finally {
        await client.end();
    }
}