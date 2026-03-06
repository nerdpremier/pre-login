import pkg from "pg"

const { Client } = pkg

export default async function handler(req,res){

if(req.method !== "POST")
 return res.status(405).send()

const { logId,code,rememberDevice,fingerprint,username } = req.body

const client = new Client({
 connectionString:process.env.DATABASE_URL,
 ssl:{rejectUnauthorized:false}
})

try{

await client.connect()
await client.query("BEGIN")

const result = await client.query(`
SELECT * FROM login_risks
WHERE id=$1 AND mfa_code=$2
`,[logId,code])

if(result.rows.length === 0)
 return res.status(401).json({error:"Invalid MFA"})

// success login
await client.query(`
UPDATE login_risks
SET is_success=true,
mfa_code=NULL,
updated_at=NOW()
WHERE id=$1
`,[logId])

// remember device
if(rememberDevice){

await client.query(`
INSERT INTO trusted_devices(username,fingerprint)
VALUES($1,$2)
ON CONFLICT DO NOTHING
`,[username,fingerprint])

}

await client.query("COMMIT")

res.json({success:true})

}
catch(err){

await client.query("ROLLBACK")
res.status(500).json({error:err.message})

}
finally{
await client.end()
}

}