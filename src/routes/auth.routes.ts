import express from 'express';
import { validate } from '../middlewares/validate';
import { AuthController } from '../controllers/auth.controllers';
import passport from 'passport';
import { createUserSchema, loginUserSchema } from 'schemas/user.schemas';

const router = express.Router();
const authCtl = new AuthController();

router.post('/signup', validate(createUserSchema), authCtl.registerUserHandler);
router.post('/login', validate(loginUserSchema), authCtl.signinUserHandler);
router.get('/refresh', passport.authenticate('jwt', { session: false }), authCtl.refreshAccessTokenHandler);
router.post('/logout', authCtl.logoutUserHandler);

export default router;
