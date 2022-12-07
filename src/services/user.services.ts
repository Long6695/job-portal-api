import { Prisma, PrismaClient, User } from '@prisma/client';

const prisma = new PrismaClient();

export const excludedFields = ['password', 'verified', 'verificationCode'];

export const createUser = async (input: Prisma.UserCreateInput) => {
  return (await prisma.user.create({ data: input })) as User;
};

export const findUniqueUser = async (where: Prisma.UserWhereUniqueInput, select?: Prisma.UserSelect) => {
  return (await prisma.user.findUnique({ where, select })) as User;
};

export const findUniqueAndUpdateUser = async (
  where: Prisma.UserWhereUniqueInput,
  data: Prisma.UserUpdateInput,
  select?: Prisma.UserSelect,
) => {
  return (await prisma.user.update({ where, data, select })) as User;
};
