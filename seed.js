const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");

const prisma = new PrismaClient();

async function main() {
  // Mã hóa mật khẩu '123456' trước khi lưu
  const hashedPassword = await bcrypt.hash("123456", 10);

  // Tạo tài khoản mẫu
  const user = await prisma.user.create({
    data: {
      username: "admin_hung",
      password: hashedPassword,
      role: "ADMIN", // Phân quyền là ADMIN
    },
  });

  console.log("Đã tạo thành công tài khoản:", user.username);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
