import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';

const app = express();
app.use(express.json());
app.use(morgan('tiny'));
app.use(helmet());
app.use(cors());
app.use(cookieParser());

export default app;
