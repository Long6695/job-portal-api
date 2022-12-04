import { User } from '@prisma/client';
import { NextFunction, Request, Response } from 'express';
import { omit } from 'lodash';
import passport from 'passport';
import { excludedFields, findUniqueAndUpdateUser, findUniqueUser } from 'services/user.services';
import AppError from 'utils/AppError';

export class UserControllers {
  constructor() {
    this.getMeHandler = this.getMeHandler.bind(this);
  }
  async getMeHandler(req: Request, res: Response, next: NextFunction) {
    try {
      const { user } = req;
      res.status(200).json({
        status: 'success',
        data: {
          user: omit(user, excludedFields),
        },
      });
    } catch (err) {
      next(err);
    }
  }

  async verifyUser(req: Request, res: Response, next: NextFunction) {
    try {
      passport.authenticate('jwt', async (err, user) => {
        if (err || !user) {
          return next(err);
        }
        const updatedUser = await findUniqueAndUpdateUser(
          { email: user.email },
          {
            verify: true,
          },
        );
        res.status(201).json({
          status: 'success',
          message: 'Update user successfully!',
          data: {
            user: omit(updatedUser, excludedFields),
          },
        });
      })(req, res, next);
    } catch (error) {
      next(error);
    }
  }
}
