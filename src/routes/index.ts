import express from 'express';
import passport from 'passport';
import authRoutes from 'routes/auth.routes';
import userRoutes from 'routes/user.routes';
const router = express.Router();

router.use('/auth', authRoutes);
router.use('/user', passport.authenticate('jwt', { session: false }), userRoutes);

export default router;
