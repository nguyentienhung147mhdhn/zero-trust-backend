const jwt = require("jsonwebtoken");

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Từ chối truy cập: Không tìm thấy Token!" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // 1. Kiểm tra Ngữ cảnh Thời gian
    const currentHour = new Date().getHours();
    if (currentHour < 8 || currentHour >= 17) {
      return res.status(403).json({
        message: "Cảnh báo (403): Hệ thống chỉ cho phép truy cập trong giờ hành chính (8h00 - 17h00)",
      });
    }

    // 2. Kiểm tra Ngữ cảnh Mạng (Giám sát phiên liên tục)
    let rawIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    let currentIp = rawIp ? rawIp.split(",")[0].trim() : "Unknown";
    if (currentIp === "::1") currentIp = "127.0.0.1";

    if (decoded.loginIp && currentIp !== decoded.loginIp) {
      return res.status(403).json({
        message: "Cảnh báo (403): Mạng bị thay đổi (Token Hijacking). Vui lòng đăng nhập lại!",
      });
    }

    next();
  } catch (error) {
    return res.status(401).json({ message: "Token sai hoặc đã hết hạn" });
  }
};

//RBAC - Role Based Access Control (Đặc quyền tối thiểu)
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: "Cảnh báo (403): Không đủ đặc quyền truy cập tài nguyên này (RBAC)!" 
      });
    }
    next();
  };
};

module.exports = { requireAuth, requireRole };