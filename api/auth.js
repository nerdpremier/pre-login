import pkg from "pg"
import bcrypt from "bcryptjs"
import nodemailer from "nodemailer"
import geoip from "geoip-lite"

const { Client } = pkg

export default async function handler(req,res){

if(req.method !== "POST")
 return res.status(405).send()

const { username,password,fingerprint,device } = req.body
const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress

const geo = geoip.lookup(ip)
const country = geo ? geo.country : "UNKNOWN"

const client = new Client({
 connectionString:process.env.DATABASE_URL,
 ssl:{rejectUnauthorized:false}
})

try{

await client.connect()
await client.query("BEGIN")

// brute force protection
const limit = await client.query(`
SELECT COUNT(*) FROM login_risks
WHERE username=$1
AND is_success=false
AND updated_at > NOW() - INTERVAL '10 minutes'
`,[username])

if(Number(limit.rows[0].count) >= 5)
 return res.status(429).json({error:"Too many attempts"})

// user
const user = await client.query(
"SELECT * FROM users WHERE username=$1",
[username]
)

if(user.rows.length === 0)
 return res.status(401).json({error:"Invalid credentials"})

// password check
const valid = await bcrypt.compare(
 password,
 user.rows[0].password_hash
)

if(!valid){

await client.query(`
INSERT INTO login_risks(username,ip_address,country,is_success)
VALUES($1,$2,$3,false)
`,[username,ip,country])

await client.query("COMMIT")
return res.status(401).json({error:"Invalid credentials"})
}

// trusted device
const trusted = await client.query(`
SELECT * FROM trusted_devices
WHERE username=$1 AND fingerprint=$2
`,[username,fingerprint])

let score = 0.1

if(trusted.rows.length === 0)
 score += 0.4

// last login
const last = await client.query(`
SELECT ip_address,country,updated_at
FROM login_risks
WHERE username=$1 AND is_success=true
ORDER BY updated_at DESC
LIMIT 1
`,[username])

let impossibleTravel=false

if(last.rows.length){

const lastCountry = last.rows[0].country
const lastTime = new Date(last.rows[0].updated_at)

const now = new Date()
const minutes = (now-lastTime)/60000

if(lastCountry !== country && minutes < 30){
 impossibleTravel=true
 score += 0.5
}

}

// risk level
const level =
score >=0.7 ? "HIGH" :
score >=0.4 ? "MEDIUM" :
"LOW"

// MFA only MEDIUM
let mfaCode = null

if(level === "MEDIUM"){

mfaCode = Math.floor(
100000 + Math.random()*900000
).toString()

const transporter = nodemailer.createTransport({
 service:"gmail",
 auth:{
  user:process.env.EMAIL_USER,
  pass:process.env.EMAIL_PASS
 }
})

await transporter.sendMail({
 from:`Security <${process.env.EMAIL_USER}>`,
 to:user.rows[0].email,
 subject:"Your MFA Code",
 html:`<h2>MFA Verification</h2><h1>${mfaCode}</h1>`
})

}

// block HIGH risk
if(level === "HIGH"){

await client.query(`
INSERT INTO login_risks
(username,ip_address,country,risk_score,risk_level,is_success)
VALUES($1,$2,$3,$4,$5,false)
`,[
 username,
 ip,
 country,
 score,
 level
])

await client.query("COMMIT")

return res.status(403).json({
error:"Login blocked (high risk)"
})

}

// log
const log = await client.query(`
INSERT INTO login_risks
(username,ip_address,country,device_info,current_fingerprint,
risk_score,risk_level,mfa_code,is_success)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,false)
RETURNING id
`,[
 username,
 ip,
 country,
 device,
 fingerprint,
 score,
 level,
 mfaCode
])

await client.query("COMMIT")

res.json({
 success:true,
 risk_level:level,
 logId:log.rows[0].id,
 require_mfa:level==="MEDIUM"
})

}
catch(err){

await client.query("ROLLBACK")
res.status(500).json({error:err.message})

}
finally{
await client.end()
}

}