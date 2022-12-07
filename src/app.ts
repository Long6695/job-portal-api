import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, {NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import redisClient from 'utils/connectRedis';
import routes from 'routes/index';
import AppError from 'utils/AppError';
import validateEnv from 'utils/validateEnv';
import config from 'config';
require('middlewares/passport');
validateEnv();

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: [config.get<string>('origin')],
    credentials: true,
  })
);
if (config.get<string>('nodeEnv') === 'development') app.use(morgan('dev'));

app.get('/', async (_, res: Response) => {
  const message = await redisClient.get('test');
  res.status(200).json({
    message,
  });
});

const baseApiVersion = '/api/v1';

app.use(baseApiVersion, routes);

app.all('*', (req: Request, res: Response, next: NextFunction) => {
  next(new AppError(404, `Route ${req.originalUrl} not found`));
});

// // GLOBAL ERROR HANDLER
app.use((err: any, req: Request, res: Response) => {
  res.status(err.status || 500);
  res.json({ error: err });
});



export default app;
