import { PrismaClient } from '@prisma/client';
import app from './app';

const prisma = new PrismaClient();
const PORT = process.env.PORT;

async function bootstrap() {
  app.listen(PORT, () => {
    console.log(`Server is running on Port ${PORT}`);
  });
}

bootstrap()
  .catch((err) => {
    throw err;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
