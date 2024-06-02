import * as bcrypt from 'bcryptjs';

/**
 * Hashes a plain text string using bcrypt.
 * @param {string} plainText - The plain text string to be hashed.
 * @returns {Promise<string>} The hashed string.
 */
export const hashPlainText = (plainText: string): Promise<string> => {
  const saltOrRounds = 10;
  return bcrypt.hash(plainText, saltOrRounds);
};

/**
 * Compares a plain text string with a hashed string using bcrypt.
 * @param {string} plainText - The plain text string to compare.
 * @param {string} hashedText - The hashed string to compare.
 * @returns {Promise<boolean>} Whether the plain text matches the hashed string.
 */
export const compareWithHash = (
  plainText: string,
  hashedText: string,
): Promise<boolean> => bcrypt.compare(plainText, hashedText);

export const randomString = (length: number): string => {
  const chars =
    '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let result = '';
  for (let i = length; i > 0; --i) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
};
