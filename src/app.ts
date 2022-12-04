import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import passport from 'passport';
import authRoutes from 'routes/auth.routes';
import userRoutes from 'routes/user.routes';
import AppError from 'utils/AppError';
import redisClient from 'utils/connectRedis';
require('middlewares/passport');

const app = express();
app.use(express.json());
app.use(morgan('tiny'));
app.use(helmet());
app.use(cors());
app.use(cookieParser());

app.get('/', async (_, res: Response) => {
  const message = await redisClient.get('test');
  res.status(200).json({
    message,
  });
});

app.use('/api/auth', authRoutes);
app.use('/api/user', passport.authenticate('jwt', { session: false }), userRoutes);

// app.all('*', (req: Request, res: Response, next: NextFunction) => {
//   next(new AppError(404, `Route ${req.originalUrl} not found`));
// });

// // GLOBAL ERROR HANDLER
app.use((err: any, req: Request, res: Response) => {
  res.status(err.status || 500);
  res.json({ error: err });
});



export default app;
