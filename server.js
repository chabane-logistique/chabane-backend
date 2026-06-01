require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const twilio = require("twilio");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const twilioClient = twilio(
  process.env.TWILIO_SID,
  process.env.TWILIO_TOKEN
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

function adminOnly(req, res, next) {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "للمشرفين فقط" });
  next();
}

app.post("/api/auth/send-otp", async (req, res) => {
  const { phone } = req.body;
  
  // تنظيف وتحويل الرقم
  const clean = phone.replace(/\s/g, "");
  const intlPhone = clean.startsWith("0") ? "+213" + clean.slice(1) : clean;

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = new Date(Date.now() + 10 * 60 * 1000);

  // احذف أي رمز قديم أولاً
  await supabase.from("otp_codes").delete().eq("phone", intlPhone);
  
  // أضف الجديد
  await supabase.from("otp_codes").insert({
    phone: intlPhone,
    code: otp,
    expires_at: expires.toISOString(),
    attempts: 0,
  });

  console.log(`✅ OTP saved: phone=${intlPhone} code=${otp}`);
  res.json({ success: true, otp, phone: intlPhone });
});
app.post("/api/auth/verify-otp", async (req, res) => {
  const { phone, otp } = req.body;
  
  const clean = phone.replace(/\s/g, "");
  const intlPhone = clean.startsWith("0") ? "+213" + clean.slice(1) : clean;

  console.log(`🔍 Verify: phone=${intlPhone} otp=${otp}`);

  // ابحث بدون .single()
  const { data: rows, error } = await supabase
    .from("otp_codes")
    .select("*")
    .eq("phone", intlPhone)
    .limit(1);

  console.log(`📋 Found:`, rows, `Error:`, error);

  if (!rows || rows.length === 0)
    return res.status(400).json({ error: "رمز غير موجود — اضغط إعادة الإرسال" });

  const otpData = rows[0];

  if (new Date() > new Date(otpData.expires_at))
    return res.status(400).json({ error: "انتهت صلاحية الرمز" });

  if (otpData.code !== otp.toString().trim())
    return res.status(400).json({ error: `رمز خاطئ` });

  // جلب أو إنشاء المستخدم
  let { data: user } = await supabase
    .from("users").select("*").eq("phone", intlPhone).single();

  if (!user) {
    const { data: newUser } = await supabase
      .from("users")
      .insert({ phone: intlPhone, role: "client", status: "active" })
      .select().single();
    user = newUser;
  }

  const token = jwt.sign(
    { userId: user.id, role: user.role, phone: intlPhone },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );

  await supabase.from("otp_codes").delete().eq("phone", intlPhone);
  
  res.json({ 
    token, 
    user: { id: user.id, name: user.full_name||"", role: user.role } 
  });
});
app.post("/api/drivers/register", async (req, res) => {
  const { name, phone, vehicleType, plate } = req.body;
  const intlPhone = phone.startsWith("0") ? "+213" + phone.slice(1) : phone;

  const { data: user, error } = await supabase.from("users").insert({
    phone: intlPhone, full_name: name, role: "driver", status: "pending",
  }).select().single();

  if (error) return res.status(400).json({ error: "الرقم مسجل مسبقاً" });

  await supabase.from("drivers").insert({
    user_id: user.id, vehicle_type: vehicleType,
    plate_number: plate, status: "pending",
  });

  res.json({ success: true });
});

app.get("/api/admin/pending-drivers", auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from("drivers")
    .select("*, users!inner(full_name, phone), driver_documents(doc_type, url, status)")
    .eq("status", "pending").order("created_at", { ascending: false });
  res.json({ drivers: data });
});

app.post("/api/admin/approve-driver/:driverId", auth, adminOnly, async (req, res) => {
  const { driverId } = req.params;
  const { data: driver } = await supabase.from("drivers")
    .update({ status: "active" }).eq("id", driverId)
    .select("*, users!inner(full_name, phone)").single();

  await supabase.from("users").update({ status: "active" }).eq("id", driver.user_id);
  io.to("admin_room").emit("driver_approved", { driverId });
  res.json({ success: true });
});

app.post("/api/orders/estimate", async (req, res) => {
  const { fromCoords, toCoords, vehicleType, cargoType, isUrgent } = req.body;
  const R = 6371;
  const dL = (toCoords.lat - fromCoords.lat) * Math.PI / 180;
  const dO = (toCoords.lng - fromCoords.lng) * Math.PI / 180;
  const a = Math.sin(dL/2)**2 + Math.cos(fromCoords.lat*Math.PI/180) *
            Math.cos(toCoords.lat*Math.PI/180) * Math.sin(dO/2)**2;
  const straight = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const km = Math.round(straight * (straight < 100 ? 1.18 : 1.12));
  const scope = km >= 100 ? "national" : "local";

  const { data: tiers } = await supabase.from("pricing_tiers")
    .select("*").eq("scope", scope).lte("min_km", km).gte("max_km", km).limit(1);
  const { data: vm } = await supabase.from("vehicle_multipliers")
    .select("*").eq("vehicle_type", vehicleType).single();
  const { data: cs } = await supabase.from("cargo_surcharges")
    .select("*").eq("cargo_type", cargoType || "standard").single();

  const tier = tiers?.[0];
  let price = tier.base_price + (km - tier.min_km) * tier.per_km;
  price = Math.round(price * vm.multiplier);
  price += cs?.surcharge_flat || 0;
  if (isUrgent) price += Math.round(price * (scope === "national" ? 0.20 : 0.25));
  price = Math.max(price, scope === "national" ? vm.min_national : vm.min_local);
  price = Math.round(price / (scope === "national" ? 100 : 50)) * (scope === "national" ? 100 : 50);

  res.json({ distanceKm: km, totalPrice: price,
    driverEarning: Math.round(price * 0.85),
    platformFee: Math.round(price * 0.15), scope });
});

app.post("/api/orders", auth, async (req, res) => {
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

  io.to(`drivers_${vehicleType}`).emit("new_order", {
    orderId: order.id, from: fromAddress, to: toAddress,
    km: distanceKm, price: totalPrice, isUrgent,
  });

  res.status(201).json({ order });
});

app.get("/health", (_, res) => res.json({
  status: "ok", service: "Chabane Logistique API", version: "4.0.0"
}));

const sessions = new Map();

io.on("connection", (socket) => {
  const token = socket.handshake.auth.token;
  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    sessions.set(socket.user.userId, socket.id);
    if (socket.user.role === "driver") {
      socket.join("drivers_master");
      socket.join("drivers_fourgon");
      socket.join("drivers_kamion");
    }
    if (socket.user.role === "admin") socket.join("admin_room");
  } catch {}

  socket.on("driver:location", async ({ lat, lng, orderId }) => {
    await supabase.from("drivers")
      .update({ current_lat: lat, current_lng: lng, last_location_at: new Date() })
      .eq("user_id", socket.user?.userId);
    if (orderId) {
      const { data: order } = await supabase.from("orders")
        .select("client_id").eq("id", orderId).single();
      const cs = sessions.get(order?.client_id);
      if (cs) io.to(cs).emit("driver:location_update", { lat, lng });
    }
  });

  socket.on("message:send", async ({ orderId, text }) => {
    const DZ = /0[5-7][0-9]{8}|\+213[5-7][0-9]{8}/g;
    const safe = DZ.test(text) ? text.replace(DZ, "***") : text;
    const { data: msg } = await supabase.from("messages").insert({
      order_id: orderId, sender_id: socket.user?.userId,
      sender_role: socket.user?.role, text: safe,
    }).select().single();
    const { data: order } = await supabase.from("orders")
      .select("client_id, driver_id").eq("id", orderId).single();
    const tid = socket.user?.role === "driver" ? order.client_id : order.driver_id;
    const ts = sessions.get(tid);
    if (ts) io.to(ts).emit("message:received", msg);
  });

  socket.on("disconnect", () => {
    if (socket.user) sessions.delete(socket.user.userId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚐 Chabane Logistique — الخادم يعمل على المنفذ ${PORT}`);
});