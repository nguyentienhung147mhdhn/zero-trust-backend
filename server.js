require("dotenv").config();
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const rateLimit = require("express-rate-limit");

// Cấu hình khóa IP nếu spam quá 5 lần trong 15 phút
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Khung thời gian: 15 phút
  max: 5, // Tối đa 5 request từ cùng 1 IP
  message: {
    message:
      "Phát hiện spam request! IP của bạn đã bị khóa tạm thời. Vui lòng thử lại sau 15 phút.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const prisma = new PrismaClient();
const app = express();

// Middleware: Cho phép Express đọc dữ liệu người dùng gửi lên dưới dạng JSON
app.use(express.json());

// ==========================================
// API ĐĂNG NHẬP (Xác thực 2 bước & Cấp JWT)
// ==========================================
app.post("/login", loginLimiter, async (req, res) => {
  try {
    // 1. Nhận thông tin gửi lên (Yêu cầu thêm mfaCode)
    const { username, password, mfaCode } = req.body;

    // 2. TÌM NGƯỜI DÙNG
    const user = await prisma.user.findUnique({
      where: { username: username },
    });

    if (!user) {
      return res.status(401).json({ message: "Tài khoản không tồn tại!" });
    }

    // 3. XÁC THỰC BƯỚC 1: KIỂM TRA MẬT KHẨU
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Sai mật khẩu!" });
    }

    // 4. XÁC THỰC BƯỚC 2: KIỂM TRA MÃ MFA (6 số)
    if (user.is_mfa_active) {
      if (!mfaCode) {
        return res
          .status(400)
          .json({ message: "Vui lòng nhập mã bảo mật MFA (6 số)!" });
      }

      const isMfaValid = speakeasy.totp.verify({
        secret: user.mfa_secret,
        encoding: "base32",
        token: mfaCode,
        window: 1, // Cho phép sai số thời gian 30 giây
      });

      if (!isMfaValid) {
        return res
          .status(401)
          .json({ message: "Mã MFA không chính xác hoặc đã hết hạn!" });
      }
    }

    let rawIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    let clientIp = rawIp ? rawIp.split(",")[0].trim() : "Unknown";

    if (clientIp === "::1") {
      clientIp = "127.0.0.1";
    }

    await prisma.user.update({
      where: { username: user.username },
      data: { last_login_ip: clientIp },
    });

    // 5. CẤP THẺ THÔNG HÀNH (Sau khi qua đủ 2 ải)
    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET, // Đọc khóa từ file .env
      { expiresIn: "1h" },
    );

    res.json({
      message: "Đăng nhập 2 bước thành công!",
      token: token,
      role: user.role,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Lỗi hệ thống máy chủ" });
  }
});

// ==========================================
// API TẠO MÃ QR MFA (Bảo mật 2 lớp) - Đã cập nhật lưu DB
// ==========================================
app.post("/mfa/setup", async (req, res) => {
  const { username } = req.body;
  const secret = speakeasy.generateSecret({ name: "Zero Trust" });

  await prisma.user.update({
    where: { username: username },
    data: {
      mfa_secret: secret.base32,
      is_mfa_active: false,
    },
  });

  QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
    res.json({ secret: secret.base32, qrCodeImage: data_url });
  });
});

app.post("/mfa/verify", async (req, res) => {
  const { username, mfaCode } = req.body;

  const user = await prisma.user.findUnique({ where: { username: username } });
  if (!user || !user.mfa_secret) {
    return res.status(400).json({ message: "Chưa cài đặt MFA!" });
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfa_secret,
    encoding: "base32",
    token: mfaCode,
  });

  if (verified) {
    await prisma.user.update({
      where: { username: username },
      data: { is_mfa_active: true },
    });
    res.json({ message: "Xác nhận MFA thành công! Đã bật bảo mật 2 lớp." });
  } else {
    res.status(400).json({ message: "Mã xác thực không đúng!" });
  }
});

// ==========================================
// KHỞI ĐỘNG SERVER
// ==========================================
const PORT = 3000;
app.listen(PORT, () => {
  console.log(
    `🚀 Server Backend Zero Trust đang chạy tại http://localhost:${PORT}`,
  );
});
