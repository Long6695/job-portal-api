import express from 'express';
import { validate } from '../middlewares/validate';
import { AuthController } from '../controllers/auth.controllers';
import { registerUserSchemas, signinUserSchemas } from '../schemas/auth.schemas';
import passport from 'passport';

const router = express.Router();
const authCtl = new AuthController();

router.post('/signup', validate(registerUserSchemas), authCtl.registerUserHandler);
router.post(
  '/login',
  validate(signinUserSchemas),
  passport.authenticate('login', { session: false }),
  authCtl.signinUserHandler,
);
router.get('/refresh', passport.authenticate('jwt', { session: false }), authCtl.refreshAccessTokenHandler);
router.post('/logout', authCtl.logoutUserHandler);

export default router;
