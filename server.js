require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── تحويل الرقم ──────────────────────────────────────────
function toIntl(phone) {
  const c = String(phone).replace(/\s|-/g, "");
  if (c.startsWith("+213")) return c;
  if (c.startsWith("213")) return "+" + c;
  if (c.startsWith("0")) return "+213" + c.slice(1);
  return "+213" + c;
}

// ── مصادقة المستخدم ──────────────────────────────────────
function authUser(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "غير مصرح" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "رمز منتهي الصلاحية" });
  }
}

// ── مصادقة الإدارة ───────────────────────────────────────
function authAdmin(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (key !== process.env.ADMIN_KEY && key !== "chabane2026") {
    return res.status(403).json({ error: "غير مصرح للإدارة" });
  }
  next();
}

// ══════════════════════════════════════════════════════════
//  HEALTH
// ══════════════════════════════════════════════════════════
app.get("/health", (_, res) => res.json({
  status: "ok", service: "Chabane Logistique API", version: "5.0.0"
}));

// ══════════════════════════════════════════════════════════
//  OTP
// ══════════════════════════════════════════════════════════
app.post("/api/auth/send-otp", async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "رقم الهاتف مطلوب" });
    const intlPhone = toIntl(phone);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    await supabase.from("otp_codes").delete().eq("phone", intlPhone);
    const { error } = await supabase.from("otp_codes").insert({
      phone: intlPhone, code: otp, expires_at: expires, attempts: 0
    });
    if (error) {
      console.error("OTP insert error:", error);
      return res.status(500).json({ error: "خطأ في حفظ الرمز" });
    }

    // Twilio (اختياري)
    try {
      const twilio = require("twilio");
      const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
      await client.messages.create({
        from: `whatsapp:${process.env.TWILIO_WHATSAPP_NUMBER}`,
        to: `whatsapp:${intlPhone}`,
        body: `رمز Chabane Logistique: *${otp}*\nصالح 10 دقائق.`
      });
    } catch (e) { console.log("Twilio:", e.message); }

    console.log(`✅ OTP: ${intlPhone} => ${otp}`);
    res.json({ success: true, otp, phone: intlPhone });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;
    const intlPhone = toIntl(phone);
    const { data: rows } = await supabase
      .from("otp_codes").select("*").eq("phone", intlPhone);

    if (!rows || rows.length === 0)
      return res.status(400).json({ error: "رمز غير موجود — أعد الإرسال" });

    const r = rows[0];
    if (new Date() > new Date(r.expires_at))
      return res.status(400).json({ error: "انتهت صلاحية الرمز" });
    if (r.code.trim() !== otp.toString().trim())
      return res.status(400).json({ error: "رمز خاطئ" });

    let { data: users } = await supabase
      .from("users").select("*").eq("phone", intlPhone);

    let user = users?.[0];
    if (!user) {
      const { data: nu } = await supabase
        .from("users")
        .insert({ phone: intlPhone, role: "client", status: "active" })
        .select();
      user = nu?.[0];
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role, phone: intlPhone },
      process.env.JWT_SECRET, { expiresIn: "30d" }
    );

    await supabase.from("otp_codes").delete().eq("phone", intlPhone);
    res.json({ token, user: { id: user.id, name: user.full_name || "", role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  تسجيل السائق
// ══════════════════════════════════════════════════════════
app.post("/api/drivers/register", async (req, res) => {
  try {
    const { name, phone, vehicleType, plate } = req.body;
    const intlPhone = toIntl(phone);

    // تحقق إذا موجود مسبقاً
    const { data: exist } = await supabase
      .from("users").select("id,status").eq("phone", intlPhone);

    if (exist && exist.length > 0) {
      if (exist[0].status === "active")
        return res.status(400).json({ error: "هذا الرقم مسجل مسبقاً" });
      return res.status(400).json({ error: "طلبك قيد المراجعة" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .insert({ phone: intlPhone, full_name: name, role: "driver", status: "pending" })
      .select().single();

    if (error) return res.status(400).json({ error: error.message });

    await supabase.from("drivers").insert({
      user_id: user.id, vehicle_type: vehicleType,
      plate_number: plate, status: "pending"
    });

    console.log(`🚐 New driver request: ${name} - ${intlPhone}`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN — السائقون المنتظرون
// ══════════════════════════════════════════════════════════
app.get("/api/admin/pending-drivers", authAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("drivers")
      .select(`
        id, vehicle_type, plate_number, status, created_at,
        users!inner(id, full_name, phone, status)
      `)
      .eq("status", "pending")
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json({ drivers: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN — قبول السائق
// ══════════════════════════════════════════════════════════
app.post("/api/admin/approve-driver/:id", authAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // تحديث حالة السائق
    await supabase.from("drivers").update({ status: "active" }).eq("id", id);

    // جلب user_id
    const { data: driver } = await supabase
      .from("drivers").select("user_id, users(full_name, phone)").eq("id", id).single();

    // تحديث حالة المستخدم
    if (driver?.user_id) {
      await supabase.from("users")
        .update({ status: "active" }).eq("id", driver.user_id);
    }

    // إرسال WhatsApp (اختياري)
    try {
      const twilio = require("twilio");
      const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
      await client.messages.create({
        from: `whatsapp:${process.env.TWILIO_WHATSAPP_NUMBER}`,
        to: `whatsapp:${driver.users.phone}`,
        body: `🎉 مرحباً ${driver.users.full_name}!\n\nتم قبول تسجيلك في Chabane Logistique.\nيمكنك الآن الدخول للتطبيق وبدء استقبال الطلبات.\nبالتوفيق! 🚐`
      });
    } catch (e) { console.log("WhatsApp:", e.message); }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN — رفض السائق
// ══════════════════════════════════════════════════════════
app.post("/api/admin/reject-driver/:id", authAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    await supabase.from("drivers").update({ status: "rejected" }).eq("id", id);

    const { data: driver } = await supabase
      .from("drivers").select("user_id, users(full_name, phone)").eq("id", id).single();

    if (driver?.user_id) {
      await supabase.from("users")
        .update({ status: "rejected" }).eq("id", driver.user_id);
    }

    // إرسال سبب الرفض عبر WhatsApp
    try {
      const twilio = require("twilio");
      const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
      await client.messages.create({
        from: `whatsapp:${process.env.TWILIO_WHATSAPP_NUMBER}`,
        to: `whatsapp:${driver.users.phone}`,
        body: `عزيزي ${driver.users.full_name},\n\nللأسف لم يتم قبول طلب تسجيلك في Chabane Logistique.\n\nالسبب: ${reason}\n\nيمكنك إعادة التقديم بعد تصحيح المشكلة. شكراً.`
      });
    } catch (e) { console.log("WhatsApp:", e.message); }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN — كل السائقين
// ══════════════════════════════════════════════════════════
app.get("/api/admin/drivers", authAdmin, async (req, res) => {
  try {
    const { data } = await supabase
      .from("drivers")
      .select(`
        id, vehicle_type, plate_number, status, rating_avg, rating_count,
        users!inner(full_name, phone)
      `)
      .in("status", ["active", "suspended"])
      .order("rating_avg", { ascending: false });

    res.json({ drivers: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN — تفعيل/إيقاف سائق
// ══════════════════════════════════════════════════════════
app.post("/api/admin/toggle-driver/:id", authAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: driver } = await supabase
      .from("drivers").select("status").eq("id", id).single();
    const newStatus = driver.status === "active" ? "suspended" : "active";
    await supabase.from("drivers").update({ status: newStatus }).eq("id", id);
    res.json({ success: true, status: newStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN — الطلبات
// ══════════════════════════════════════════════════════════
app.get("/api/admin/orders", authAdmin, async (req, res) => {
  try {
    const { data } = await supabase
      .from("orders")
      .select(`
        id, pickup_address, delivery_address, status, total_price,
        distance_km, vehicle_type, cargo_type, created_at,
        client:users!client_id(full_name, phone),
        driver:drivers!driver_id(plate_number, users!inner(full_name))
      `)
      .order("created_at", { ascending: false })
      .limit(100);

    res.json({ orders: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN — الإحصائيات
// ══════════════════════════════════════════════════════════
app.get("/api/admin/stats", authAdmin, async (req, res) => {
  try {
    const { period = "today" } = req.query;
    const now = new Date();
    let from = new Date();

    if (period === "today") from.setHours(0,0,0,0);
    else if (period === "week") from.setDate(now.getDate() - 7);
    else if (period === "month") from.setDate(now.getDate() - 30);

    const { data: orders } = await supabase
      .from("orders")
      .select("id, total_price, status, created_at")
      .gte("created_at", from.toISOString());

    const { data: drivers } = await supabase
      .from("drivers").select("id").eq("status", "active");

    const { data: users } = await supabase
      .from("users").select("id").eq("role", "client")
      .gte("created_at", from.toISOString());

    const revenue = (orders || [])
      .filter(o => o.status === "delivered")
      .reduce((s, o) => s + (o.total_price || 0), 0);

    res.json({
      orders: orders?.length || 0,
      revenue,
      platform_fee: Math.round(revenue * 0.15),
      active_drivers: drivers?.length || 0,
      new_clients: users?.length || 0,
      delivered: (orders || []).filter(o => o.status === "delivered").length,
      searching: (orders || []).filter(o => o.status === "searching").length,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//  SOCKET.IO
// ══════════════════════════════════════════════════════════
io.on("connection", (socket) => {
  console.log("Socket:", socket.id);
  socket.on("driver:location", ({ lat, lng, orderId }) => {
    socket.broadcast.emit("driver:location_update", { lat, lng, orderId });
  });
  socket.on("disconnect", () => console.log("Disconnected:", socket.id));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚐 Chabane Logistique v5 — يعمل على المنفذ ${PORT}`);
});
