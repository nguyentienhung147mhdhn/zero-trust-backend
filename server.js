require('dotenv').config();
const express = require('express');

// Tạo một ứng dụng web
const app = express();

// Cho phép ứng dụng nhận dữ liệu dạng JSON
app.use(express.json());

// Khi có người truy cập trang chủ (đường dẫn '/'), gửi dòng chữ chào mừng
app.get('/', (req, res) => {
  res.send('Xin chào! Server Zero Trust đã chạy thành công!');
});

// Lắng nghe ở cổng 3000
app.listen(3000, () => {
  console.log('Server đang mở cửa đón khách ở địa chỉ: http://localhost:3000');
});