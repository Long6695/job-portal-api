import { CookieOptions, NextFunction, Request, Response } from 'express';
import { omit } from 'lodash';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import AppError from 'utils/AppError';
import { excludedFields, findUniqueAndUpdateUser, findUniqueUser } from 'services/user.services';
import passport from 'passport';
import { RegisterUserInput, LoginUserInput, VerifyEmailInput } from 'schemas/user.schemas';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from 'utils/jwt';
import config from 'config';
import redisClient from 'utils/connectRedis';

export class AuthController {
  constructor() {
    this.registerUserHandler = this.registerUserHandler.bind(this);
    this.signinUserHandler = this.signinUserHandler.bind(this);
    this.logoutUserHandler = this.logoutUserHandler.bind(this);
    this.refreshAccessTokenHandler = this.refreshAccessTokenHandler.bind(this);
  }

  cookiesOptions(expiresIn: number = config.get<number>('accessTokenExpiresIn')): CookieOptions {
    const baseOptions: CookieOptions = {
      expires: new Date(Date.now() + expiresIn * 60 * 1000),
      maxAge: expiresIn * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax',
      domain: config.get<string>('frontendBaseUrl'),
      secure: false,
    };
    if (expiresIn !== config.get<number>('accessTokenExpiresIn')) {
      return {
        ...baseOptions,
        path: '/refresh',
      };
    }
    return baseOptions;
  }

  async registerUserHandler(
    req: Request<Record<string, unknown>, Record<string, unknown>, RegisterUserInput>,
    res: Response,
    next: NextFunction,
  ) {
    try {
      passport.authenticate('signup', async (error, user) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            return res.status(400).json({
              status: 'fail',
              message: 'Email already exist, please use another email address',
            });
          }
        }
        return res.status(200).json({
          status: 'success',
          data: {
            user: omit(user, excludedFields),
          },
        });
      })(req, res, next);
    } catch (error) {
      next(error);
    }
  }

  async signinUserHandler(
    req: Request<Record<string, unknown>, Record<string, unknown>, LoginUserInput>,
    res: Response,
    next: NextFunction,
  ) {
    try {
      passport.authenticate('login', async (err, user, info) => {
        if (err || !user) {
          return next(new AppError(401, info.message));
        }
        const { email } = user;
        req.login(user, { session: false }, async (err) => {
          if (err) return next(err);

          const access_token = signAccessToken(
            { email },
            {
              expiresIn: `${config.get<number>('accessTokenExpiresIn')}m`,
            },
          );

          const refresh_token = signRefreshToken(
            { email },
            {
              expiresIn: `${config.get<number>('refreshTokenExpiresIn')}m`,
            },
          );

          await redisClient.set(`${email}`, refresh_token, {
            EX: config.get<number>('redisCacheExpiresIn') * 60,
          });

          res.cookie('access_token', access_token, this.cookiesOptions(config.get<number>('accessTokenExpiresIn')));
          res.cookie('refresh_token', refresh_token, this.cookiesOptions(config.get<number>('refreshTokenExpiresIn')));
          res.setHeader('Authorization', access_token);
          res.status(200).json({
            status: 'success',
            message: 'Login successfully',
          });
        });
      })(req, res, next);
    } catch (error) {
      next(new AppError(401, 'Login fail. Try again!'));
    }
  }
  // async verifyUser(req: Request, res: Response, next: NextFunction) {}

  async refreshAccessTokenHandler(req: Request, res: Response, next: NextFunction) {
    try {
      const refresh_token = req.cookies.refresh_token;

      const message = 'Could not refresh access token';

      if (!refresh_token) {
        return next(new AppError(403, message));
      }

      // Validate refresh token
      const decoded = verifyRefreshToken(refresh_token) as { email: string };

      if (!decoded) {
        return next(new AppError(403, message));
      }

      // Check if user still exist
      const user = await findUniqueUser({ email: decoded.email });

      if (!user) {
        return next(new AppError(403, message));
      }

      // Sign new access token
      const access_token = signAccessToken(
        { email: decoded.email },
        {
          expiresIn: `${config.get<number>('accessTokenExpiresIn')}m`,
        },
      );

      const new_refresh_token = signRefreshToken(
        { email: decoded.email },
        {
          expiresIn: `${config.get<number>('refreshTokenExpiresIn')}m`,
        },
      );

      await redisClient.set(`${decoded.email}`, new_refresh_token, {
        EX: config.get<number>('redisCacheExpiresIn') * 60,
      });

      // 4. Add Cookies
      res.cookie('access_token', access_token, this.cookiesOptions(config.get<number>('accessTokenExpiresIn')));

      res.cookie('refresh_token', new_refresh_token, this.cookiesOptions(config.get<number>('refreshTokenExpiresIn')));

      // 5. Send response
      res.status(200).json({
        status: 'success',
        message: 'Refresh token successfully',
      });
    } catch (err) {
      next(err);
    }
  }
  private logout(res: Response) {
    res.cookie('access_token', '', { maxAge: -1 });
    res.cookie('refresh_token', '', { maxAge: -1 });
  }

  async logoutUserHandler(req: Request, res: Response, next: NextFunction) {
    try {
      passport.authenticate('jwt', async (err, user) => {
        if (err || !user) return next(err);
        const session = await redisClient.get(`${user.email}`);
        if (!session) {
          return res.status(401).json({
            status: 'error',
            message: 'Unauthenticated',
          });
        }
        await redisClient.del(`${user.email}`);
        this.logout(res);
        res.status(200).json({
          status: 'success',
          message: 'Logout',
        });
      })(req, res, next);
    } catch (err) {
      next(err);
    }
  }

  async verifyEmailHandler(req: Request<VerifyEmailInput>, res: Response, next: NextFunction) {
    try {
      const verificationCode = req.params.verificationCode;

      const user = await findUniqueAndUpdateUser(
        { verificationCode },
        { verify: true, verificationCode: null },
        { email: true },
      );

      if (!user) {
        return next(new AppError(401, 'Could not verify email'));
      }

      res.status(200).json({
        status: 'success',
        message: 'Email verified successfully',
      });
    } catch (err: any) {
      if (err.code === 'P2025') {
        return res.status(403).json({
          status: 'fail',
          message: `Verification code is invalid or user doesn't exist`,
        });
      }
      next(err);
    }
  }
}
