import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import AppError from 'utils/AppError';

export const validate = (schema: Joi.ObjectSchema) => (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error } = schema.validate(req.body);
    if (error) {
      return next(new AppError(400, error.details[0].message));
    }
    next();
  } catch (error) {
    next(error);
  }
};
