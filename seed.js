const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");

const prisma = new PrismaClient();

async function main() {
  // Dọn sạch bảng con (các phiên đăng nhập) trước
  await prisma.deviceSession.deleteMany();
  // Dọn sạch bảng User trước khi đổ dữ liệu mới
  await prisma.user.deleteMany();
  
  // Mã hóa mật khẩu '123456' trước khi lưu
  const hashedPassword = await bcrypt.hash("123456", 10);

  // 1. Tạo tài khoản Admin (để gọi được reset-demo)
  const admin = await prisma.user.create({
    data: {
      username: "admin_test",
      password: hashedPassword,
      role: "admin", 
    },
  });

  // 2. Tạo tài khoản Hacker (để test ZTA, chống IP lạ, gọi thử reset-demo bằng role user)
  const hacker = await prisma.user.create({
    data: {
      username: "hacker_test",
      password: hashedPassword,
      role: "user", 
    },
  });

  console.log("Đã tạo thành công các tài khoản:");
  console.log(`- ${admin.username} (Role: ${admin.role})`);
  console.log(`- ${hacker.username} (Role: ${hacker.role})`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });