import { NextFunction, Request, Response } from 'express';
import { omit } from 'lodash';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import AppError from 'utils/AppError';
import { IRegisterUserSchemas, ISignInUserSchemas } from 'schemas/auth.schemas';
import { excludedFields, findUniqueUser } from 'services/user.services';
import { signJWT, verifyJWT } from 'utils/jwt';
import passport from 'passport';
import { User } from '@prisma/client';

export class AuthController {
  constructor() {
    this.registerUserHandler = this.registerUserHandler.bind(this);
    this.signinUserHandler = this.signinUserHandler.bind(this);
    this.logoutUserHandler = this.logoutUserHandler.bind(this);
  }

  async registerUserHandler(
    req: Request<Record<string, unknown>, Record<string, unknown>, IRegisterUserSchemas>,
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
    req: Request<Record<string, unknown>, Record<string, unknown>, ISignInUserSchemas>,
    res: Response,
    next: NextFunction,
  ) {
    try {
      if (req.user) {
        const { email } = req.user as User;
        req.login(req.user, { session: false }, async (err) => {
          if (err) return next(err);

          const access_token = signJWT({ email }, 'ACCESS_TOKEN', {
            expiresIn: '15m',
          });

          const refresh_token = signJWT({ email }, 'REFRESH_TOKEN', {
            expiresIn: '60m',
          });

          res.cookie('access_token', access_token, {
            expires: new Date(Date.now() + 15 * 60 * 1000),
            maxAge: 15 * 60 * 1000,
            httpOnly: true,
            sameSite: 'lax',
            domain: process.env.FRONTEND_BASE_URL,
            secure: false,
          });
          res.cookie('refresh_token', refresh_token, {
            expires: new Date(Date.now() + 60 * 60 * 1000),
            maxAge: 60 * 60 * 1000,
            httpOnly: true,
            domain: process.env.FRONTEND_BASE_URL,
            path: '/refresh',
            secure: false,
          });

          res.status(200).json({
            status: 'success',
            message: 'Login successfully',
          });
        });
      }
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
      const decoded = verifyJWT(refresh_token, 'REFRESH_TOKEN') as { email: string };

      if (!decoded) {
        return next(new AppError(403, message));
      }

      // Check if user still exist
      const user = await findUniqueUser({ email: decoded.email });

      if (!user) {
        return next(new AppError(403, message));
      }

      // Sign new access token
      const access_token = signJWT({ email: decoded.email }, 'ACCESS_TOKEN', {
        expiresIn: `15m`,
      });

      const new_refresh_token = signJWT({ email: decoded.email }, 'ACCESS_TOKEN', {
        expiresIn: `60m`,
      });

      // 4. Add Cookies
      res.cookie('access_token', access_token, {
        expires: new Date(Date.now() + 15 * 60 * 1000),
        maxAge: 15 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax',
        domain: process.env.FRONTEND_BASE_URL,
        secure: false,
      });

      res.cookie('refresh_token', new_refresh_token, {
        expires: new Date(Date.now() + 60 * 60 * 1000),
        maxAge: 60 * 60 * 1000,
        httpOnly: true,
        domain: process.env.FRONTEND_BASE_URL,
        path: '/refresh',
        secure: false,
      });

      // 5. Send response
      res.status(200).json({
        status: 'success',
        message: 'refresh token successfully',
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
      this.logout(res);

      res.status(200).json({
        status: 'success',
        message: 'Logout',
      });
    } catch (err) {
      next(err);
    }
  }
}
