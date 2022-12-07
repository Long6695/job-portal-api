import { PrismaClient } from '@prisma/client';
import app from './app';
import dotenv from 'dotenv';
dotenv.config();
import config from 'config';
const prisma = new PrismaClient();

async function bootstrap() {
  app.listen(config.get<number>('port'), () => {
    console.log(`Server is running on Port ${config.get<number>('port')}`);
  });
}

bootstrap()
  .catch((err) => {
    throw err;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
