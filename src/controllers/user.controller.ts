import { NextFunction, Request, Response } from 'express';
import { omit } from 'lodash';
import { excludedFields } from 'services/user.services';

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
}
