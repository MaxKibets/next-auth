"use server";

import { redirect } from 'next/navigation';

import { createUser } from '@/lib/user';
import { hashUserPassword } from '@/lib/hash';  
import { createAuthSession, destroySession } from '@/lib/auth';
import { getUserByEmail } from '@/lib/user';
import { verifyPassword } from '@/lib/hash';

const signup = async (prevState, formData) => {
  const email = formData.get('email');
  const password = formData.get('password');

  const errors = {};

  if (!email.includes('@')) {
    errors.email = 'Please enter a valid email address';
  }

  if (password.trim().length < 8) {
    errors.password = 'Password must be at least 8 characters';
  }

  if (Object.keys(errors).length > 0) {
    return {errors};
  }

  const hashedPassword = hashUserPassword(password);

  try {
    const userId = createUser(email, hashedPassword);

    await createAuthSession(userId);
    redirect("/training");
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      errors.email = 'Email address already in use';

      return {errors};
    }

    throw error;
  }
};

const login = async (prevState, formData) => {
  const email = formData.get('email');
  const password = formData.get('password');

  const existingUser = getUserByEmail(email);

  if (!existingUser) {
    return {errors: {email: 'No user with that email address'}};
  }

  const isValidPassword = verifyPassword(existingUser.password, password);

  if (!isValidPassword) {
    return {errors: {password: 'Incorrect password'}};
  }

  await createAuthSession(existingUser.id);
  redirect("/training");
}

export const auth = (mode, prevState, formData) => {
  if (mode === 'login') {
    return login(prevState, formData);
  }

  return signup(prevState, formData);
};

export const logout = async () => {
  await destroySession();

  redirect("/");
};
