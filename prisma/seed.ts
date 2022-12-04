import { PrismaClient } from "@prisma/client";
export const prisma = new PrismaClient();

(async function main() {
    try {
     console.log('Start Prisma');
    } catch(e) {
      await prisma.$disconnect();
      console.error(e);
      process.exit(1);
    } finally {
      await prisma.$disconnect();
    }
  })();