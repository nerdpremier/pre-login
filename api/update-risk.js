import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {

    if (req.method !== 'POST') return res.status(405).send();

    const { logId, success } = req.body;

    // FIX: ถ้าไม่มี logId ให้จบเลย
    if (!logId) return res.status(200).json({ success: true });

    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {

        await client.connect();
        await client.query("BEGIN"); // ADD: transaction

        // ADD: ตรวจว่า logId มีจริงไหม
        const check = await client.query(
            "SELECT id FROM login_risks WHERE id = $1",
            [logId]
        );

        if (check.rows.length === 0) {

            await client.query("COMMIT");

            return res.status(200).json({ success: true });

        }

        // ADD: ถ้า success ให้ล้าง mfa_code ป้องกัน replay
        if (success) {

            await client.query(
                `UPDATE login_risks 
                 SET is_success = $1,
                     mfa_code = NULL, 
                     updated_at = NOW()
                 WHERE id = $2`,
                [success, logId]
            );

        } else {

            // logic เดิม
            await client.query(
                `UPDATE login_risks 
                 SET is_success = $1,
                     updated_at = NOW()
                 WHERE id = $2`,
                [success, logId]
            );

        }

        await client.query("COMMIT"); // ADD

        res.status(200).json({ success: true });

    } catch (err) {

        await client.query("ROLLBACK"); // ADD

        console.error("update-risk error:", err); // ADD

        res.status(500).json({ error: err.message });

    } finally {

        await client.end();

    }
}