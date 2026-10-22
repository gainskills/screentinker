'use strict';

// Access records go to the console (journald / docker logs keep working unchanged).
// Security events go ONLY to the file named by SECURITY_LOG, and only
// authenticationFailure() writes there, from validated fields. No console or other
// untrusted text can reach that file, so nothing needs escaping globally.
const fs = require('node:fs');
const net = require('node:net');
const writeStdout = line => process.stdout.write(line);
// Unset SECURITY_LOG = no security file (fail2ban is opt-in). Appends reopen the path each
// time, so logrotate's rename/create rotation works without copytruncate.
const writeSecurityLog = line => {
  const file = process.env.SECURITY_LOG;
  if (file) fs.appendFile(file, line, { mode: 0o640 }, () => { /* best effort */ });
};
const AUTH_METHOD = Object.freeze({ PASSWORD: 'password', TOTP: 'totp' });

function clientAddress(value) {
  if (typeof value !== 'string') return null;
  const ip = value.replace(/^::ffff:/i, '');
  // Zone identifiers and arbitrary header text do not belong in ban commands.
  return net.isIP(ip) && /^[\da-f:.]+$/i.test(ip) ? ip : null;
}

function authenticationFailure(ip, method, { write = writeSecurityLog } = {}) {
  const address = clientAddress(ip);
  if (!address || !Object.values(AUTH_METHOD).includes(method)) return;
  try {
    write(`${new Date().toISOString()} [security] auth_failure ip=${address} method=${method}\n`);
  } catch (_) { /* observability must not change the authentication outcome */ }
}

function accessLogger({ getClientIp, write = writeStdout } = {}) {
  return (req, res, next) => {
    const started = process.hrtime.bigint();
    let ip = '-';
    try { ip = clientAddress(getClientIp?.(req)) || clientAddress(req.socket?.remoteAddress) || '-'; } catch (_) {}
    let recorded = false;
    const record = () => {
      if (recorded) return;
      recorded = true;
      try {
        const aborted = !res.writableFinished;
        const data = {
          ip,
          method: String(req.method || '').slice(0, 20),
          // Only a router's declared template: raw URLs can contain hook secrets,
          // viewing keys, preview tokens, reset links and credentials in queries.
          // baseUrl is the router mount path ('/api/auth'); route.path alone drops it.
          route: typeof req.route?.path === 'string' ? `${typeof req.baseUrl === 'string' ? req.baseUrl : ''}${req.route.path}` : '-',
          status: aborted ? 499 : res.statusCode,
          duration_ms: Math.round(Number(process.hrtime.bigint() - started) / 1e6),
          aborted,
        };
        write(`${new Date().toISOString()} [access] ${JSON.stringify(data)}\n`);
      } catch (_) { /* a completed HTTP response must not become an uncaught exception */ }
    };
    res.once('finish', record);
    res.once('close', record);
    next();
  };
}

module.exports = { accessLogger, authenticationFailure, AUTH_METHOD };
