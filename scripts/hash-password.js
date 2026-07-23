const crypto = require('crypto');

const password = process.argv[2];
if (!password || password.length < 10) {
  console.error('Usage: npm run server-control:hash -- "password-at-least-10-characters"');
  process.exitCode = 1;
} else {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  console.log(`scrypt$16384$8$1$${salt.toString('hex')}$${key.toString('hex')}`);
}
