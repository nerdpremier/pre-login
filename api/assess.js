import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    
    const client = new Client({ 
        connectionString: process.env.DATABASE_URL, 
        ssl: { rejectUnauthorized: false } 
    });

    try {
        await client.connect();
        const { username, ip, location, device, fp_mismatch } = req.body;
        if (!username) return res.status(400).json({ error: "Missing username" });

        // --- [STEP 1] AUTO-CLEANUP: ลบ Log ที่เก่ากว่า 15 นาทีทิ้งทันที ---
        await client.query("DELETE FROM login_risks WHERE created_at < NOW() - INTERVAL '15 minutes'");

        // --- [STEP 2] COUNT RATE: นับจำนวนการลองใน 15 นาทีที่เหลืออยู่ ---
        const rateCheck = await client.query(
            "SELECT count(*) FROM login_risks WHERE username = $1", 
            [username]
        );
        const loginRate = parseInt(rateCheck.rows[0].count);

        // --- [STEP 3] RISK SCORE: คำนวณคะแนนแบบ Sensitive ---
        let score = 0.1; 
        
        // ถ้ากดซ้ำ 2-3 ครั้ง (Medium)
        if (loginRate >= 2 && loginRate < 4) score = 0.4; 
        // ถ้ากดซ้ำ 4 ครั้งขึ้นไป (High)
        else if (loginRate >= 4) score = 0.8;

        // ถ้าเครื่องไม่เคยเห็น (Mismatch) ให้บวกคะแนนเพิ่ม
        if (fp_mismatch) score += 0.4;

        // สรุประดับความเสี่ยง
        const level = score >= 0.8 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // --- [STEP 4] INSERT: บันทึก Log ใหม่ลงไป ---
        await client.query(
            `INSERT INTO login_risks (username, ip_address, network_location, device_info, fingerprint_mismatch, login_rate, risk_score, risk_level) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [username, ip, location, device, fp_mismatch, loginRate, score, level]
        );

        return res.status(200).json({ risk_level: level, attempts: loginRate + 1 });

    } catch (err) {
        return res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}