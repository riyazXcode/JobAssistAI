import jwt from 'jsonwebtoken';

const JWT_ISSUER = process.env.JWT_ISSUER || 'jobassistai';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'jobassistai-client';

export function signAccess(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '15m',
    audience: JWT_AUDIENCE,
    issuer: JWT_ISSUER,
  });
}

export function signRefresh(payload) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: '7d',
    audience: JWT_AUDIENCE,
    issuer: JWT_ISSUER,
  });
}

export function authMiddleware(req, res, next) {
  const token = req.cookies?.accessToken;
  if (!token) return res.sendStatus(401);
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, {
      audience: JWT_AUDIENCE,
      issuer: JWT_ISSUER,
    });
    next();
  } catch {
    res.sendStatus(401);
  }
}
