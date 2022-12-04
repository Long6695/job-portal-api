import Joi from 'joi';

export const registerUserSchemas: Joi.ObjectSchema<IRegisterUserSchemas> = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  passwordConfirm: Joi.ref('password'),
}).with('password', 'passwordConfirm');

export const signinUserSchemas: Joi.ObjectSchema<ISignInUserSchemas> = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
}).with('email', 'password');

export interface IRegisterUserSchemas {
  email: string;
  password: string;
  passwordConfirm: string;
}

export type ISignInUserSchemas = Omit<IRegisterUserSchemas, 'passwordConfirm'>;
