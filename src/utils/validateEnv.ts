import { cleanEnv, port, str } from 'envalid';

const validateEnv = () => {
  cleanEnv(process.env, {
    NODE_ENV: str(),
    PORT: port(),
    POSTGRES_HOST: str(),
    POSTGRES_PORT: port(),
    POSTGRES_USER: str(),
    POSTGRES_PASSWORD: str(),
    POSTGRES_DB: str(),
    ACCESS_TOKEN_PRIVATE_KEY_PATH: str(),
    ACCESS_TOKEN_PUBLIC_KEY_PATH: str(),
    REFRESH_TOKEN_PRIVATE_KEY_PATH: str(),
    REFRESH_TOKEN_PUBLIC_KEY_PATH: str(),
    FRONTEND_BASE_URL: str(),
    DATABASE_URL: str(),
  });
};

export default validateEnv;