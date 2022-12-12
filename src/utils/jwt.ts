import config from 'config';
import jwt, { SignOptions } from 'jsonwebtoken';
import fs from 'fs';

export const accessTokenPrivateKey = fs.readFileSync(config.get<string>('accessTokenPrivateKeyPath'), {
  encoding: 'utf8',
});
export const refreshTokenPrivateKey = fs.readFileSync(config.get<string>('refreshTokenPrivateKeyPath'), {
  encoding: 'utf8',
});
export const accessTokenPublicKey = fs.readFileSync(config.get<string>('accessTokenPublicKeyPath'), {
  encoding: 'utf8',
});
export const refreshTokenPublicKey = fs.readFileSync(config.get<string>('refreshTokenPublicKeyPath'), {
  encoding: 'utf8',
});

export const signAccessToken = (payload: Record<string, unknown>, options?: SignOptions) => {
  return jwt.sign(payload, accessTokenPrivateKey, {
    expiresIn: `${config.get<number>('accessTokenExpiresIn')}m`,
    ...(options && options),
    algorithm: 'RS256',
  });
};

export const signRefreshToken = (payload: Record<string, unknown>, options?: SignOptions) => {
  return jwt.sign(payload, refreshTokenPrivateKey, {
    expiresIn: `${config.get<number>('refreshTokenExpiresIn')}m`,
    ...(options && options),
    algorithm: 'RS256',
  });
};

export const verifyAccessToken = (token: string, options?: SignOptions) => {
  return jwt.verify(token, accessTokenPublicKey, {
    ...(options && options),
    algorithms: ['RS256'],
  });
};

export const verifyRefreshToken = (token: string, options?: SignOptions) => {
  return jwt.verify(token, refreshTokenPublicKey, {
    ...(options && options),
    algorithms: ['RS256'],
  });
};
