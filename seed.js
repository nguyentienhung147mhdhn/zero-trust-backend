const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");

const prisma = new PrismaClient();

async function main() {
  console.log("Bắt đầu thêm dữ liệu mẫu vào Database...");
  const hashedPassword = await bcrypt.hash("123456", 10);

  // 1. Tài khoản Admin
  const admin = await prisma.user.upsert({
    where: { username: "admin_Viet" },
    update: {},
    create: {
      username: "admin_Viet",
      password: hashedPassword,
      role: "ADMIN",
      is_mfa_active: false,
    },
  });

  // 2. Tài khoản User bình thường
  const user = await prisma.user.upsert({
    where: { username: "user_normal" },
    update: {},
    create: {
      username: "user_normal",
      password: hashedPassword,
      role: "USER",
      is_mfa_active: false,
    },
  });

  // 3. Tài khoản Hacker (Dùng test Brute-force & Thuật toán Trust)
  const hacker = await prisma.user.upsert({
    where: { username: "hacker_test" },
    update: {},
    create: {
      username: "hacker_test",
      password: hashedPassword,
      role: "HACKER",
      is_mfa_active: false,
    },
  });

  console.log("Đã tạo 3 tài khoản thành công");
  console.log(`- ${admin.username} | Role: ${admin.role}`);
  console.log(`- ${user.username} | Role: ${user.role}`);
  console.log(`- ${hacker.username} | Role: ${hacker.role}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });