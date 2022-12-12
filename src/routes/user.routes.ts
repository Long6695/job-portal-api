import { UserControllers } from 'controllers/user.controller';
import express from 'express';

const router = express.Router();
const userCtl = new UserControllers();

router.get('/me', userCtl.getMeHandler);

export default router;
