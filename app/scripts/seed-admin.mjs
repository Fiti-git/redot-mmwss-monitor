/**
 * Seed the first admin user. Plain JS so it runs in the production image
 * without needing tsx (which is a devDependency, stripped by Next standalone).
 *
 * Reads MMWSS_ADMIN_EMAIL, MMWSS_ADMIN_NAME, MMWSS_ADMIN_PASSWORD from env.
 * Idempotent — updates the row if email already exists.
 *
 * Run: docker compose run --rm app node scripts/seed-admin.mjs
 */
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const email = (process.env.MMWSS_ADMIN_EMAIL || "").toLowerCase().trim();
  const name = process.env.MMWSS_ADMIN_NAME || "Admin";
  const password = process.env.MMWSS_ADMIN_PASSWORD || "";

  if (!email || !password) {
    console.error("MMWSS_ADMIN_EMAIL and MMWSS_ADMIN_PASSWORD must be set");
    process.exit(2);
  }
  if (password.length < 12) {
    console.error("Password must be at least 12 characters");
    process.exit(3);
  }

  const hash = await bcrypt.hash(password, 12);

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    await prisma.user.update({
      where: { email },
      data: { name, passwordHash: hash, role: "admin", isActive: true },
    });
    console.log(`Updated admin user: ${email}`);
  } else {
    await prisma.user.create({
      data: { email, name, passwordHash: hash, role: "admin", isActive: true },
    });
    console.log(`Created admin user: ${email}`);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
