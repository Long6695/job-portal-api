import jwt, { SignOptions } from 'jsonwebtoken';
export const signJWT = (
  payload: Record<string, unknown>,
  keyName: 'ACCESS_TOKEN' | 'REFRESH_TOKEN',
  options?: SignOptions,
) => {
  const key = process.env[keyName] || process.env['ACCESS_TOKEN'];
  if (!key) return;
  return jwt.sign(payload, key, {
    ...(options && options),
    algorithm: 'HS256',
  });
};

export const verifyJWT = (token: string, keyName: 'ACCESS_TOKEN' | 'REFRESH_TOKEN', options?: SignOptions) => {
  const key = process.env[keyName] || process.env['ACCESS_TOKEN'];
  if (!key) return;
  const decode = jwt.verify(token, key, {
    ...(options && options),
  });
  return decode;
};
