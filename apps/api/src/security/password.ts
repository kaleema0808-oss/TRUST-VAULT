import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const saltBytes = 16;
const keyBytes = 64;
const cost = 32768;

function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyBytes, { N: cost, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(saltBytes);
  const derivedKey = await deriveKey(password, salt);
  return `scrypt$${cost}$${salt.toString("hex")}$${derivedKey.toString("hex")}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const [algorithm, costText, saltHex, keyHex] = storedHash.split("$");
  if (algorithm !== "scrypt" || costText !== String(cost) || !saltHex || !keyHex) return false;
  if (!/^[a-f0-9]{32}$/i.test(saltHex) || !/^[a-f0-9]{128}$/i.test(keyHex)) return false;

  const expected = Buffer.from(keyHex, "hex");
  const actual = await deriveKey(password, Buffer.from(saltHex, "hex"));
  return timingSafeEqual(actual, expected);
}
