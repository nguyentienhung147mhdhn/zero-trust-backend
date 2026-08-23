# Dự Án Zero Trust Backend

## 1. Yêu cầu hệ thống
* Node.js
* PostgreSQL (Cần tạo sẵn database tên `zero_trust_db`)

## 2. Hướng dẫn chạy dự án lần đầu
1. Mở Terminal, tải code về: `git clone https://github.com/nguyentienhung147mhdhn/zero-trust-backend.git`
2. Cài đặt các thư viện cần thiết: `npm install`
3. Tạo file `.env` ở thư mục gốc và dán chuỗi kết nối DB vào (liên hệ Hưng để lấy mã).
4. Đồng bộ cấu trúc DB: `npx prisma db push`
5. Khởi động server: `npm start`

## 3. Quy tắc sử dụng Git cho nhóm
* **KHÔNG** đẩy code trực tiếp lên nhánh `main`.
* Khi nhận việc, luôn tạo nhánh mới: `git checkout -b feature/ten-tinh-nang-cua-ban`
* Làm xong, đẩy code lên nhánh cá nhân đó và báo cho team ráp nối.