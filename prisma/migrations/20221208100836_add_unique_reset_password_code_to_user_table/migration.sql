/*
  Warnings:

  - A unique constraint covering the columns `[resetPasswordCode]` on the table `User` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[email,verificationCode,resetPasswordCode]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "User_email_verificationCode_idx";

-- DropIndex
DROP INDEX "User_email_verificationCode_key";

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "resetPasswordCode" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "User_resetPasswordCode_key" ON "User"("resetPasswordCode");

-- CreateIndex
CREATE INDEX "User_email_verificationCode_resetPasswordCode_idx" ON "User"("email", "verificationCode", "resetPasswordCode");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_verificationCode_resetPasswordCode_key" ON "User"("email", "verificationCode", "resetPasswordCode");
