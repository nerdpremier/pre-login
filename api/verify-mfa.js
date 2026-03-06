import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    const { logId, code } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const result = await client.query("SELECT mfa_code FROM login_risks WHERE id = $1", [logId]);
        
        if (result.rows.length > 0 && result.rows[0].mfa_code === code) {
            await client.query("UPDATE login_risks SET is_success = TRUE WHERE id = $1", [logId]);
            res.status(200).json({ success: true });
        } else {
            res.status(401).json({ error: "Invalid code" });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
    finally { await client.end(); }
}