/**
 * TOTP — Time-based One-Time Password (RFC 6238).
 * Pure-JS implementation using built-in Node crypto. No external dependencies.
 *
 * Compatible with Google Authenticator, Authy, 1Password, Microsoft Authenticator,
 * and any other RFC-6238 compliant TOTP app.
 */
const crypto = require('crypto');

// ── Base32 (RFC 4648) ────────────────────────────────────────
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encode a Buffer to a base32 string (no padding). */
function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

/** Decode a base32 string (case-insensitive, padding-tolerant) to a Buffer. */
function base32Decode(s) {
  const clean = (s || '').toUpperCase().replace(/=+$/,'').replace(/\s/g,'');
  let bits = 0, value = 0;
  const out = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = B32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) throw new Error('Invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// ── HOTP / TOTP core ─────────────────────────────────────────
/** Compute HOTP (counter-based) per RFC 4226. */
function hotp(secretBuf, counter, digits = 6) {
  const counterBuf = Buffer.alloc(8);
  // Big-endian 64-bit counter — only fits up to ~2^53 in JS Number, plenty for time counters
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secretBuf).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) <<  8) |
     (hmac[offset + 3] & 0xff);
  const mod = 10 ** digits;
  return String(code % mod).padStart(digits, '0');
}

/** Compute TOTP for the current 30-second window. */
function totp(secretBase32, opts = {}) {
  const step = opts.step || 30;
  const t = Math.floor((opts.time || Date.now()) / 1000 / step);
  return hotp(base32Decode(secretBase32), t, opts.digits || 6);
}

/**
 * Verify a user-supplied TOTP token against the secret.
 * Allows ±1 time-step drift (about ±30 seconds) to handle clock skew.
 */
function verifyTotp(secretBase32, token, opts = {}) {
  if (!secretBase32 || !token) return false;
  const cleaned = String(token).replace(/\s/g,'');
  if (!/^\d{6}$/.test(cleaned)) return false;
  const step = opts.step || 30;
  const window = opts.window != null ? opts.window : 1;
  const secretBuf = base32Decode(secretBase32);
  const t = Math.floor(Date.now() / 1000 / step);
  for (let i = -window; i <= window; i++) {
    if (hotp(secretBuf, t + i) === cleaned) return true;
  }
  return false;
}

/** Generate a fresh TOTP secret (160-bit recommended by RFC). */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/**
 * Build a provisioning URI suitable for rendering as a QR code.
 * issuer = label shown in the authenticator app (e.g. "CJA-OPS")
 * accountName = user identifier (e.g. "kyle@cja-ops")
 */
function provisioningUri(secretBase32, accountName, issuer) {
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = {
  totp, verifyTotp, generateSecret, provisioningUri,
  base32Encode, base32Decode,
};
