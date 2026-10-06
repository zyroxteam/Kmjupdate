/**
 * First-run admin setup: node setup.js
 * Prompts for username + password (hidden input), stores bcrypt hash.
 * Refuses to run if an admin already exists.
 */
const readline = require('readline');
const bcrypt = require('bcryptjs');
const db = require('./db');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask(q, hidden) {
  return new Promise((resolve) => {
    if (!hidden) return rl.question(q, resolve);
    // Hidden password input.
    const stdin = process.stdin;
    let pw = '';
    process.stdout.write(q);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (ch) => {
      if (ch === '\n' || ch === '\r' || ch === '\u0004') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(pw);
      } else if (ch === '\u0003') {
        process.exit(1);
      } else if (ch === '\u007f') {
        pw = pw.slice(0, -1);
      } else {
        pw += ch;
      }
    };
    stdin.on('data', onData);
  });
}

(async () => {
  try {
    const count = db.prepare('SELECT COUNT(*) AS c FROM admins').get().c;
    if (count > 0) {
      console.log('An admin already exists. Setup is disabled.');
      process.exit(0);
    }
    console.log('=== KMJ TIPS — create the first admin ===');
    const username = (await ask('Username (3-32 chars): ')).trim();
    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
      console.log('Invalid username.'); process.exit(1);
    }
    const pw1 = await ask('Password (min 8 chars): ', true);
    const pw2 = await ask('Repeat password: ', true);
    if (pw1 !== pw2) { console.log('Passwords do not match.'); process.exit(1); }
    if (pw1.length < 8 || pw1.length > 128) { console.log('Password must be 8-128 chars.'); process.exit(1); }

    db.prepare('INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)')
      .run(username, bcrypt.hashSync(pw1, 12), Date.now());
    console.log('Admin "' + username + '" created. Start the server with: npm start');
    process.exit(0);
  } catch (e) {
    console.error('Setup failed:', e.message);
    process.exit(1);
  } finally {
    rl.close();
  }
})();
