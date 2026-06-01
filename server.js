require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, req.body);
  next();
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const upload = multer({ storage: multer.memoryStorage() });

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "غير مصرح" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "رمز منتهي الصلاحية" });
  }
}

// ── تحويل الرقم الجزائري ──────────────────────────────
function toIntl(phone) {
  const clean = String(phone).replace(/\s|-/g, "");
  if (clean.startsWith("+213")) return clean;
  if (clean.startsWith("213")) return "+" + clean;
  if (clean.startsWith("0")) return "+213" + clean.slice(1);
  return "+213" + clean;
}

// ══════════════════════════════════════════════════════
//  HEALTH
// ══════════════════════════════════════════════════════
app.get("/health", (_, res) => res.json({
  status: "ok",
  service: "Chabane Logistique API",
  version: "4.0.0"
}));

// ══════════════════════════════════════════════════════
//  إرسال OTP
// ══════════════════════════════════════════════════════
app.post("/api/auth/send-otp", async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "رقم الهاتف مطلوب" });

    const intlPhone = toIntl(phone);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    // احذف القديم
    await supabase.from("otp_codes").delete().eq("phone", intlPhone);

    // أضف الجديد
    const { error } = await supabase.from("otp_codes").insert({
      phone: intlPhone,
      code: otp,
      expires_at: expires,
      attempts: 0,
    });

    if (error) {
      console.error("Insert error:", error);
      return res.status(500).json({ error: "خطأ في حفظ الرمز" });
    }

    console.log(`✅ OTP: ${intlPhone} => ${otp}`);

    // إرسال Twilio (اختياري)
    try {
      const twilio = require("twilio");
      const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
      await client.messages.create({
        from: `whatsapp:${process.env.TWILIO_WHATSAPP_NUMBER}`,
        to: `whatsapp:${intlPhone}`,
        body: `رمز Chabane Logistique: *${otp}*\nصالح 10 دقائق.`,
      });
    } catch (twilioErr) {
      console.log("Twilio not active:", twilioErr.message);
    }

    res.json({ success: true, otp, phone: intlPhone });
  } catch (e) {
    console.error("send-otp error:", e);
    res.status(500).json({ error: "خطأ في الخادم" });
  }
});

// ══════════════════════════════════════════════════════
//  التحقق من OTP
// ══════════════════════════════════════════════════════
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) return res.status(400).json({ error: "بيانات ناقصة" });

    const intlPhone = toIntl(phone);
    console.log(`🔍 Verify: phone=${intlPhone} otp=${otp}`);

    const { data: rows } = await supabase
      .from("otp_codes")
      .select("*")
      .eq("phone", intlPhone);

    console.log(`📋 Rows found:`, rows?.length, rows);

    if (!rows || rows.length === 0)
      return res.status(400).json({ error: "رمز غير موجود — أعد الإرسال" });

    const otpData = rows[0];

    if (new Date() > new Date(otpData.expires_at))
      return res.status(400).json({ error: "انتهت صلاحية الرمز" });

    if (otpData.code.toString().trim() !== otp.toString().trim())
      return res.status(400).json({ error: "رمز خاطئ" });

    // جلب أو إنشاء المستخدم
    let { data: user } = await supabase
      .from("users").select("*").eq("phone", intlPhone);

    if (!user || user.length === 0) {
      const { data: newUser } = await supabase
        .from("users")
        .insert({ phone: intlPhone, role: "client", status: "active" })
        .select();
      user = newUser;
    }

    const u = Array.isArray(user) ? user[0] : user;

    const token = jwt.sign(
      { userId: u.id, role: u.role, phone: intlPhone },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    await supabase.from("otp_codes").delete().eq("phone", intlPhone);

    res.json({
      token,
      user: { id: u.id, name: u.full_name || "", role: u.role }
    });
  } catch (e) {
    console.error("verify-otp error:", e);
    res.status(500).json({ error: "خطأ في الخادم: " + e.message });
  }
});

// ══════════════════════════════════════════════════════
//  تسجيل السائق
// ══════════════════════════════════════════════════════
app.post("/api/drivers/register", async (req, res) => {
  try {
    const { name, phone, vehicleType, plate } = req.body;
    const intlPhone = toIntl(phone);

    const { data: user, error } = await supabase.from("users").insert({
      phone: intlPhone,
      full_name: name,
      role: "driver",
      status: "pending",
    }).select().single();

    if (error) return res.status(400).json({ error: "الرقم مسجل مسبقاً" });

    await supabase.from("drivers").insert({
      user_id: user.id,
      vehicle_type: vehicleType,
      plate_number: plate,
      status: "pending",
    });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════
//  Admin — السائقون المنتظرون
// ══════════════════════════════════════════════════════
app.get("/api/admin/pending-drivers", auth, async (req, res) => {
  const { data } = await supabase
    .from("drivers")
    .select("*, users!inner(full_name, phone), driver_documents(doc_type, url, status)")
    .eq("status", "pending");
  res.json({ drivers: data || [] });
});

// قبول سائق
app.post("/api/admin/approve-driver/:id", auth, async (req, res) => {
  const { id } = req.params;
  await supabase.from("drivers").update({ status: "active" }).eq("id", id);
  res.json({ success: true });
});

// ══════════════════════════════════════════════════════
//  الطلبات
// ══════════════════════════════════════════════════════
app.post("/api/orders/estimate", async (req, res) => {
  try {
    const { fromCoords, toCoords, vehicleType, cargoType, isUrgent } = req.body;
    const R = 6371;
    const dL = (toCoords.lat - fromCoords.lat) * Math.PI / 180;
    const dO = (toCoords.lng - fromCoords.lng) * Math.PI / 180;
    const a = Math.sin(dL/2)**2 + Math.cos(fromCoords.lat*Math.PI/180)
            * Math.cos(toCoords.lat*Math.PI/180) * Math.sin(dO/2)**2;
    const s = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    const km = Math.round(s * (s < 100 ? 1.18 : 1.12));
    const scope = km >= 100 ? "national" : "local";

    const { data: tiers } = await supabase.from("pricing_tiers")
      .select("*").eq("scope", scope).lte("min_km", km).gte("max_km", km).limit(1);
    const { data: vm } = await supabase.from("vehicle_multipliers")
      .select("*").eq("vehicle_type", vehicleType || "master").single();
    const { data: cs } = await supabase.from("cargo_surcharges")
      .select("*").eq("cargo_type", cargoType || "standard").single();

    const tier = tiers?.[0];
    if (!tier) return res.status(400).json({ error: "لا توجد شريحة تسعير" });

    let price = tier.base_price + (km - tier.min_km) * tier.per_km;
    price = Math.round(price * (vm?.multiplier || 1));
    price += cs?.surcharge_flat || 0;
    if (isUrgent) price += Math.round(price * (scope === "national" ? 0.20 : 0.25));
    price = Math.max(price, scope === "national" ? (vm?.min_national || 3500) : (vm?.min_local || 400));
    price = Math.round(price / (scope === "national" ? 100 : 50)) * (scope === "national" ? 100 : 50);

    res.json({ distanceKm: km, totalPrice: price,
      driverEarning: Math.round(price * 0.85),
      platformFee: Math.round(price * 0.15), scope });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/orders", auth, async (req, res) => {
  try {
    const { fromCoords, fromAddress, toCoords, toAddress,
            vehicleType, cargoType, totalPrice, distanceKm, isUrgent } = req.body;

    const { data: order } = await supabase.from("orders").insert({
      client_id: req.user.userId,
      pickup_address: fromAddress, pickup_lat: fromCoords.lat, pickup_lng: fromCoords.lng,
      delivery_address: toAddress, delivery_lat: toCoords.lat, delivery_lng: toCoords.lng,
      vehicle_type: vehicleType, cargo_type: cargoType,
      total_price: totalPrice, distance_km: distanceKm,
      is_urgent: isUrgent, status: "searching", payment_method: "cash",
    }).select().single();

    io.emit("new_order", { orderId: order.id, from: fromAddress,
      to: toAddress, km: distanceKm, price: totalPrice });

    res.status(201).json({ order });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════
//  Socket.io
// ══════════════════════════════════════════════════════
io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);
  socket.on("driver:location", async ({ lat, lng, orderId }) => {
    socket.broadcast.emit("driver:location_update", { lat, lng, orderId });
  });
  socket.on("disconnect", () => console.log("Socket disconnected:", socket.id));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚐 Chabane Logistique — الخادم يعمل على المنفذ ${PORT}`);
});
