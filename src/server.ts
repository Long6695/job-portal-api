import { PrismaClient } from '@prisma/client';
import { Response } from 'express';
import app from './app';
import redisClient from './utils/connectRedis';

const prisma = new PrismaClient();
const PORT = process.env.PORT;

async function bootstrap() {
  app.get('/', async (_, res: Response) => {
    const message = await redisClient.get('test');
    res.status(200).json({
      message,
    });
  });
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
