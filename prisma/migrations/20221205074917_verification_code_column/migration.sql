/*
  Warnings:

  - A unique constraint covering the columns `[email,verificationCode]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "User" ADD COLUMN     "verificationCode" TEXT;

-- CreateIndex
CREATE INDEX "User_email_verificationCode_idx" ON "User"("email", "verificationCode");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_verificationCode_key" ON "User"("email", "verificationCode");
