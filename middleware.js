const jwt = require("jsonwebtoken");

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Từ chối truy cập: Không tìm thấy Token!" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // ZERO TRUST POLICY ENGINE (Kiểm tra ngữ cảnh)

    // 1. Kiểm tra Ngữ cảnh Thời gian (8h00 - 17h00)
    const currentHour = new Date().getHours();
    if (currentHour < 8 || currentHour >= 17) {
      return res.status(403).json({
        message:
          "Cảnh báo (403 Forbidden): Hệ thống chỉ cho phép truy cập trong giờ hành chính (8h00 - 17h00)",
      });
    }

    // 2. Kiểm tra Ngữ cảnh Mạng (So sánh IP)
    // Lấy IP thực tế của request hiện tại
    const currentIp =
      req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    // Kịch bản: Hưng nhét IP lúc login vào trong Payload của JWT (tên biến là loginIp)
    // Nếu IP hiện tại khác với IP lúc sinh Token -> Bị trộm Token đổi máy -> CHẶN
    if (decoded.loginIp && currentIp !== decoded.loginIp) {
      return res.status(403).json({
        message:
          "Cảnh báo (403 Forbidden): Địa chỉ IP bị thay đổi bất thường. Vui lòng đăng nhập lại",
      });
    }

    // Nếu qua được các cổng check ngữ cảnh, cho phép truy cập tính năng
    next();
  } catch (error) {
    return res.status(401).json({ message: "Token sai hoặc đã hết hạn" });
  }
};

module.exports = { requireAuth };
