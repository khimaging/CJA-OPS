const jwt = require('jsonwebtoken');
require('dotenv').config();

const SECRET  = process.env.JWT_SECRET;
const EXPIRES = process.env.JWT_EXPIRES_IN || '8h';

if (!SECRET) throw new Error('JWT_SECRET is not set');

/**
 * Sign a JWT for a logged-in team member.
 * Payload contains the minimum needed to re-identify the user.
 */
function signToken(member) {
  return jwt.sign(
    { sub: member.id, name: member.name, role: member.auth_role },
    SECRET,
    { expiresIn: EXPIRES }
  );
}

/**
 * Verify a JWT and return its decoded payload.
 * Throws if invalid or expired.
 */
function verifyToken(token) {
  return jwt.verify(token, SECRET);
}

/**
 * Express middleware — requires a valid Bearer token.
 * Attaches decoded payload to req.user.
 */
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/**
 * Express middleware — requires admin role.
 * Must be used after requireAuth.
 */
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

/**
 * Express middleware — requires admin or class_a role (can delete).
 * Must be used after requireAuth.
 */
function requireCanDelete(req, res, next) {
  if (req.user?.role !== 'admin' && req.user?.role !== 'class_a') {
    return res.status(403).json({ error: 'Deleting records requires Admin or Class A access' });
  }
  next();
}

module.exports = { signToken, verifyToken, requireAuth, requireAdmin, requireCanDelete };
