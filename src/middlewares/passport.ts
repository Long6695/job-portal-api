import passport from 'passport';
import passportLocal from 'passport-local';
import { createUser, findUniqueUser } from 'services/user.services';
import bcrypt from 'bcryptjs';
import passportJwt from 'passport-jwt';
import { accessTokenPublicKey } from 'utils/jwt';

const jwtStrategy = passportJwt.Strategy;
const extractJwt = passportJwt.ExtractJwt;
const localStrategy = passportLocal.Strategy;

passport.use(
  'jwt',
  new jwtStrategy(
    {
      secretOrKey: accessTokenPublicKey,
      jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
      algorithms: ["RS256"]
    },
    async (payload, done) => {
      try {
        const user = await findUniqueUser({ email: payload.email });
        if (!user) {
          return done(null, false);
        }
        return done(null, user);
      } catch (error) {
        done(error);
      }
    },
  ),
);

passport.use(
  'signup',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email, password, done) => {
      try {
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = await createUser({ email: email.toLowerCase(), password: hashedPassword });
        return done(null, user);
      } catch (error) {
        done(error);
      }
    },
  ),
);

passport.use(
  'login',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email, password, done) => {
      try {
        const user = await findUniqueUser({ email });
        if (!user) {
          return done(null, false, { message: 'Invalid email or password.' });
        }
        if (!user.verify) {
          return done(null, false, { message: 'Your account is not verified.' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
          return done(null, false, { message: 'Invalid email or password.' });
        }

        return done(null, user, { message: 'Logged in Successfully' });
      } catch (error) {
        done(error);
      }
    },
  ),
);
