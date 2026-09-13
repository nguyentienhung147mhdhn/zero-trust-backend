require("dotenv").config();
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const rateLimit = require("express-rate-limit");
const { requireAuth, requireRole } = require("./middleware");

//Trả về giới hạn 5 lần/15 phút
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: {
    message: "Phát hiện spam request! IP của bạn đã bị khóa tạm thời. Vui lòng thử lại sau 15 phút.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const prisma = new PrismaClient();
const app = express();
app.use(cors());
app.use(express.json());

// Lấy IP chuẩn xác
const getClientIp = (req) => {
  let rawIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  let clientIp = rawIp ? rawIp.split(",")[0].trim() : "Unknown";
  return clientIp === "::1" ? "127.0.0.1" : clientIp;
};

// API ĐĂNG NHẬP
app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { username, password, mfaCode } = req.body;

    const user = await prisma.user.findUnique({
      where: { username: username },
    });

    if (!user) return res.status(401).json({ message: "Tài khoản không tồn tại!" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: "Sai mật khẩu!" });

    if (!user.is_mfa_active || !user.mfa_secret) {
      return res.status(403).json({
        message: "Hệ thống Zero Trust yêu cầu tài khoản phải hoàn tất thiết lập MFA. Từ chối truy cập!",
      });
    }

    if (!mfaCode) return res.status(400).json({ message: "Vui lòng nhập mã bảo mật MFA (6 số)!" });

    const isMfaValid = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: "base32",
      token: mfaCode,
      window: 1, 
    });

    if (!isMfaValid) return res.status(401).json({ message: "Mã MFA không chính xác hoặc đã hết hạn!" });

    const clientIp = getClientIp(req);

    if (user.last_login_ip && user.last_login_ip !== clientIp) {
      return res.status(403).json({
        message: `Cảnh báo bảo mật Zero Trust: Phát hiện đăng nhập từ IP lạ (${clientIp})! Truy cập bị từ chối.`,
      });
    }

    await prisma.user.update({
      where: { username: user.username },
      data: { last_login_ip: clientIp },
    });

    //Bơm IP và Role vào JWT để Middleware giám sát liên tục và RBAC
    const token = jwt.sign(
      { 
        username: user.username,
        loginIp: clientIp,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.json({
      message: "Đăng nhập 2 bước thành công!",
      token: token,
      role: user.role,
    });
  } catch (error) {
    res.status(500).json({ message: "Lỗi hệ thống máy chủ" });
  }
});

// API TẠO MÃ QR MFA
app.post("/mfa/setup", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await prisma.user.findUnique({ where: { username: username } });
    if (!user) return res.status(401).json({ message: "Tài khoản không tồn tại!" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: "Sai mật khẩu, từ chối cấp mã QR!" });

    if (user.is_mfa_active) {
      return res.status(403).json({ message: "Tài khoản đã thiết lập MFA! Không thể tạo lại mã QR." });
    }

    const secret = speakeasy.generateSecret({ name: `ZTA_Demo_${username}` });

    //CHỈ LƯU SECRET, CHƯA BẬT is_mfa_active
    await prisma.user.update({
      where: { username: username },
      data: { mfa_secret: secret.base32 },
    });

    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) return res.status(500).json({ message: "Lỗi tạo ảnh QR" });
      res.json({
        secret: secret.base32,
        qrCode: data_url,
        message: "Tạo mã QR thành công! Vui lòng quét và xác thực để kích hoạt.",
      });
    });
  } catch (error) {
    res.status(500).json({ message: "Lỗi hệ thống khi thiết lập MFA" });
  }
});

app.post("/mfa/verify", async (req, res) => {
  const { username, mfaCode } = req.body;

  const user = await prisma.user.findUnique({ where: { username: username } });
  if (!user || !user.mfa_secret) return res.status(400).json({ message: "Chưa cài đặt MFA!" });

  const verified = speakeasy.totp.verify({
    secret: user.mfa_secret,
    encoding: "base32",
    token: mfaCode,
  });

  if (verified) {
    await prisma.user.update({
      where: { username: username },
      data: { is_mfa_active: true }, // Lúc này mới kích hoạt
    });
    res.json({ message: "Xác nhận MFA thành công! Đã bật bảo mật 2 lớp." });
  } else {
    res.status(400).json({ message: "Mã xác thực không đúng!" });
  }
});

// API DASHBOARD
app.get("/api/dashboard", requireAuth, (req, res) => {
  res.json({
    message: "Thành công! Chào mừng bạn đến với vùng dữ liệu bảo mật Zero Trust.",
    user: req.user, 
  });
});

//Bảo vệ endpoint nguy hiểm + RBAC
app.get("/reset-demo", requireAuth, requireRole(["ADMIN"]), async (req, res) => {
  try {
    if (process.env.NODE_ENV !== "development") {
      return res.status(403).json({ message: "Tính năng này chỉ khả dụng ở môi trường Development." });
    }

    await prisma.user.update({
      where: { username: "admin_hung" },
      data: {
        is_mfa_active: false,
        mfa_secret: null,
        last_login_ip: null,
      },
    });
    res.send("Tài khoản admin_hung đã sẵn sàng để trình diễn quét QR.");
  } catch (error) {
    res.status(500).send("Lỗi reset");
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server Backend Zero Trust đang chạy tại http://localhost:${PORT}`);
});