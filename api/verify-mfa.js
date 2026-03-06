import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const { logId, code } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const result = await client.query("SELECT * FROM login_risks WHERE id = $1 AND mfa_code = $2", [logId, code]);

        if (result.rows.length > 0) {
            await client.query("UPDATE login_risks SET is_success = TRUE WHERE id = $1", [logId]);
            res.status(200).json({ success: true });
        } else {
            res.status(401).json({ error: "Invalid Code" });
        }
    } catch (err) { res.status(500).json({ error: err.message }); } 
    finally { await client.end(); }
}