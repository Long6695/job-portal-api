import {PrismaClient} from '@prisma/client';
export const prisma = new PrismaClient();

(async function main() {
  try {
    const user = await prisma.user.create({
      data: {
        name: 'admin',
        email: 'admin@jobportal.com',
        password: '123123',
        passwordConfirm: '123123',
        verify: true,
        role: 'ADMIN',
        profile: {
          create: {
            firstName: 'admin',
            lastName: 'admin',
            bio: 'Hi i am Long',
            birthDate: '1995-11-28T14:34:59.708Z',
          },
        },
      },
    },
    );
    console.log('Create 1 user: ', user);
  } catch (e) {
    await prisma.$disconnect();
    console.error(e);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
})();
