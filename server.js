const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const prisma = new PrismaClient();
const app = express();

// Middleware: Cho phép Express đọc dữ liệu người dùng gửi lên dưới dạng JSON
app.use(express.json());

// ==========================================
// API ĐĂNG NHẬP (Xác thực 2 bước & Cấp JWT)
// ==========================================
app.post("/login", async (req, res) => {
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
    if (!user.mfa_secret) {
      return res
        .status(400)
        .json({ message: "Tài khoản chưa cài đặt bảo mật MFA!" });
    }

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

    // 5. CẤP THẺ THÔNG HÀNH (Sau khi qua đủ 2 ải)
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET || "CHIA_KHOA_BIMAT_CUA_NHOM",
      { expiresIn: "15m" }, // Rút ngắn xuống 15 phút cho đúng chuẩn Zero Trust
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
  try {
    // Lấy tên tài khoản muốn cài đặt MFA từ dữ liệu gửi lên
    const { username } = req.body;

    // 1. Dùng speakeasy sinh ra một khóa bí mật ngẫu nhiên
    const secret = speakeasy.generateSecret({
      name: "ZeroTrust_Hung_Backend",
    });

    // 2. Lưu khóa bí mật này vào Database cho tài khoản vừa nhập
    await prisma.user.update({
      where: { username: username },
      data: { mfa_secret: secret.base32 },
    });

    // 3. Dùng thư viện qrcode biến cái khóa đó thành hình ảnh QR
    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) {
        return res.status(500).json({ message: "Lỗi tạo mã QR" });
      }

      res.json({
        message: "Cài đặt MFA thành công! Quét mã này bằng ứng dụng.",
        secret: secret.base32, // Vẫn trả về để test
        qrCodeImage: data_url,
      });
    });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: "Lỗi hệ thống hoặc Tài khoản không tồn tại" });
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
