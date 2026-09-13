require("dotenv").config();
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const cors = require("cors");

const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const rateLimit = require("express-rate-limit");

const { requireAuth } = require("./middleware");

// Cấu hình khóa IP nếu spam quá 15 lần trong 5 phút
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // Khung thời gian: 5 phút
  max: 15, // Tối đa 15 request từ cùng 1 IP
  message: {
    message:
      "Phát hiện spam request! IP của bạn đã bị khóa tạm thời. Vui lòng thử lại sau 5 phút.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const prisma = new PrismaClient();
const app = express();

app.use(cors()); // Mở khóa cho Frontend gọi vào

// Middleware: Cho phép Express đọc dữ liệu người dùng gửi lên dưới dạng JSON
app.use(express.json());

// ==========================================
// API ĐĂNG NHẬP (Xác thực 2 bước & Cấp JWT)
// ==========================================
app.post("/login", loginLimiter, async (req, res) => {
  try {
    // 1. Nhận thông tin gửi lên
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

    // ==========================================
    // 4. XÁC THỰC BƯỚC 2: KIỂM TRA MÃ MFA (ĐÃ SIẾT CHẶT CHO ZERO TRUST)
    // ==========================================

    // 4.1 Bắt buộc tài khoản phải được setup MFA trong Database
    if (!user.is_mfa_active || !user.mfa_secret) {
      return res.status(403).json({
        message:
          "Hệ thống Zero Trust yêu cầu tài khoản phải bật MFA. Từ chối truy cập!",
      });
    }

    // 4.2 Bắt buộc Frontend phải gửi mã lên (Chặn gửi rỗng)
    if (!mfaCode) {
      return res
        .status(400)
        .json({ message: "Vui lòng nhập mã bảo mật MFA (6 số)!" });
    }

    // 4.3 Xác thực mã với thư viện speakeasy
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
    // ==========================================

    // Lấy IP người dùng
    let rawIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    let clientIp = rawIp ? rawIp.split(",")[0].trim() : "Unknown";

    if (clientIp === "::1") {
      clientIp = "127.0.0.1";
    }

    // ==========================================
    // 4.5 XÁC THỰC BƯỚC 3 (ZERO TRUST): KIỂM TRA VỊ TRÍ IP
    // ==========================================
    if (user.last_login_ip && user.last_login_ip !== clientIp) {
      return res.status(403).json({
        message:
          "Cảnh báo bảo mật Zero Trust: Phát hiện đăng nhập từ IP lạ (" +
          clientIp +
          ")! Truy cập bị từ chối.",
      });
    }

    // Cập nhật lại IP vào Database
    await prisma.user.update({
      where: { username: user.username },
      data: { last_login_ip: clientIp },
    });

    // 5. CẤP THẺ THÔNG HÀNH
    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
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

app.get("/generate-mfa", async (req, res) => {
  try {
    // 1. Tạo một secret key ngẫu nhiên
    const secret = speakeasy.generateSecret({
      name: "ZTA_Demo_Hung", // Tên sẽ hiển thị trên app Google Authenticator
    });

    // 2. Biến nó thành hình ảnh QR Code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // 3. Trả về cho Frontend
    res.json({
      secret: secret.base32, // (Chuỗi này để bạn lưu tạm vào DB nếu muốn)
      qrCode: qrCodeUrl, // (Chuỗi Base64 chứa hình ảnh QR)
    });
  } catch (error) {
    res.status(500).json({ message: "Lỗi tạo QR Code" });
  }
});

// ==========================================
// API TẠO MÃ QR MFA (Bảo mật 2 lớp) - Đã cập nhật lưu DB
// ==========================================
app.post("/mfa/setup", async (req, res) => {
  try {
    // 1. Phải yêu cầu cả mật khẩu để xác thực quyền chủ tài khoản
    const { username, password } = req.body;

    // 2. TÌM NGƯỜI DÙNG VÀ KIỂM TRA MẬT KHẨU
    const user = await prisma.user.findUnique({
      where: { username: username },
    });

    if (!user) {
      return res.status(401).json({ message: "Tài khoản không tồn tại!" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ message: "Sai mật khẩu, từ chối cấp mã QR!" });
    }

    // ==========================================
    // VÁ LỖ HỔNG: CHẶN GHI ĐÈ MFA
    // ==========================================
    if (user.is_mfa_active) {
      return res.status(403).json({
        message:
          "Tài khoản đã thiết lập MFA! Không thể tạo lại mã QR. Nếu mất thiết bị, vui lòng liên hệ Admin.",
      });
    }

    // 3. TẠO SECRET CODE
    const secret = speakeasy.generateSecret({ name: `ZTA_Demo_${username}` });

    // 4. LƯU VÀO DATABASE VÀ KÍCH HOẠT MFA
    await prisma.user.update({
      where: { username: username },
      data: {
        mfa_secret: secret.base32,
        is_mfa_active: true, // Phải để true thì API /login mới cho qua
      },
    });

    // 5. TẠO ẢNH QR VÀ TRẢ VỀ FRONTEND
    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) {
        return res.status(500).json({ message: "Lỗi tạo ảnh QR" });
      }

      // Trả về biến "qrCode" để khớp 100% với file script.js ở Frontend
      res.json({
        secret: secret.base32,
        qrCode: data_url,
        message: "Tạo mã QR thành công!",
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Lỗi hệ thống khi thiết lập MFA" });
  }
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

// ==========================================
// API DASHBOARD (Vùng bảo mật Zero Trust)
// ==========================================
app.get("/api/dashboard", requireAuth, (req, res) => {
  res.json({
    message:
      "Thành công! Chào mừng bạn đến với vùng dữ liệu bảo mật Zero Trust.",
    user: req.user, // Hiển thị thông tin user được giải mã từ Token
  });
});

app.listen(PORT, () => {
  console.log(
    `🚀 Server Backend Zero Trust đang chạy tại http://localhost:${PORT}`,
  );
});

app.get("/reset-demo", async (req, res) => {
  try {
    await prisma.user.update({
      where: { username: "admin_hung" },
      data: {
        is_mfa_active: false,
        mfa_secret: null,
        last_login_ip: null,
      },
    });
    res.send(
      "Đã dọn dẹp Database! Tài khoản admin_hung đã sẵn sàng để trình diễn quét QR.",
    );
  } catch (error) {
    res.status(500).send("Lỗi reset");
  }
});
