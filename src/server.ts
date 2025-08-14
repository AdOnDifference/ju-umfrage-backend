import express from "express";
import helmet from "helmet";
import cors from "cors";
import { z } from "zod";
import requestIp from "request-ip";
import crypto from "crypto";
import { Pool } from "pg";

const {
  DATABASE_URL = "",
  PORT = "8080",
  CORS_ORIGIN = "*",
  IP_HASH_SALT = ""
} = process.env;

const app = express();
app.use(helmet());
app.use(express.json());
app.use(requestIp.mw());

const origins = CORS_ORIGIN.split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: origins.length ? origins : "*"
}));

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

const bodySchema = z.object({
  age_group: z.enum(["u18","18_24","25_34","35_49","50_64","65_plus"]),
  district: z.enum(["floersheim_mitte","wicker","weilbach","keramag_falkenberg"]),
  topics: z.array(z.enum([
    "verkehr_infrastruktur","oeffentlicher_nahverkehr","wohnen_bau","umwelt_gruen",
    "sport_freizeit","kultur_veranstaltungen","digitalisierung_internet",
    "sicherheit_ordnung","wirtschaft_einzelhandel","sonstiges"
  ])).min(1),
  other_topic: z.string().optional().nullable(),
  comment: z.string().optional().nullable(),
  wants_updates: z.boolean().default(false),
  email: z.string().email().optional().or(z.literal(""))
});

app.get("/v1/health", (_req, res) => res.json({ ok: true }));

app.post("/v1/survey", async (req, res) => {
  try {
    const data = bodySchema.parse(req.body);

    const ip = (req as any).clientIp || "";
    const ip_hash = ip && IP_HASH_SALT
      ? crypto.createHash("sha256").update(ip + IP_HASH_SALT).digest("hex")
      : null;

    const ua = req.headers["user-agent"] || null;

    const sql = `
      INSERT INTO survey_response
        (age_group, district, topics, other_topic, comment, wants_updates, email, user_agent, ip_hash)
      VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `;
    await pool.query(sql, [
      data.age_group,
      data.district,
      data.topics,
      data.other_topic || null,
      data.comment || null,
      data.wants_updates || false,
      data.email || null,
      ua,
      ip_hash
    ]);

    res.status(201).json({ ok: true });
  } catch (e: any) {
    console.error(e);
    res.status(400).json({ ok: false, error: e?.message || "invalid_request" });
  }
});

app.listen(Number(PORT), () => {
  console.log(`API on :${PORT}`);
});
