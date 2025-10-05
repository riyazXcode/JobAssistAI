import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { User } from '../models/User.js';
import { registerSchema, loginSchema } from '../validation/user.js';
import { signAccess, signRefresh, authMiddleware } from '../auth/auth.js';
import crypto from 'node:crypto';

const router = express.Router();

router.post('/register', (req, res, next) => {
  req.app.authLimiter(req, res, next);
}, async (req, res) => {
  const { error, value } = registerSchema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) return res.status(400).json({ error: 'Invalid input' });

  const { email, password } = value;
  const exists = await User.findOne({ email }).lean();
  if (exists) return res.status(409).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 12);
  const user = await User.create({ email, passwordHash });
  res.status(201).json({ id: user._id });
});

router.post('/login', (req, res, next) => {
  req.app.authLimiter(req, res, next);
}, async (req, res) => {
  const { error, value } = loginSchema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) return res.status(400).json({ error: 'Invalid credentials' });

  const { email, password } = value;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const refreshId = crypto.randomUUID();
  user.refreshId = refreshId;
  await user.save();
  const accessToken = signAccess({ sub: user._id, role: user.role, rid: refreshId });
  const refreshToken = signRefresh({ sub: user._id, rid: refreshId });
  const secure = process.env.NODE_ENV === 'production';

  res.cookie('accessToken', accessToken, { httpOnly: true, secure, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
  res.cookie('refreshToken', refreshToken, { httpOnly: true, secure, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });

  res.json({ ok: true });
});

router.post('/refresh', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.sendStatus(401);
  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      audience: process.env.JWT_AUDIENCE || 'jobassistai-client',
      issuer: process.env.JWT_ISSUER || 'jobassistai',
    });
    const user = await User.findById(payload.sub);
    if (!user || !user.refreshId || user.refreshId !== payload.rid) return res.sendStatus(401);
    const newRefreshId = crypto.randomUUID();
    user.refreshId = newRefreshId;
    await user.save();
    const accessToken = signAccess({ sub: payload.sub, rid: newRefreshId });
    const newRefreshToken = signRefresh({ sub: payload.sub, rid: newRefreshId });
    const secure = process.env.NODE_ENV === 'production';
    res.cookie('accessToken', accessToken, { httpOnly: true, secure, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', newRefreshToken, { httpOnly: true, secure, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ ok: true });
  } catch {
    res.sendStatus(401);
  }
});

router.post('/logout', authMiddleware, (req, res, next) => {
  req.app.authLimiter(req, res, next);
}, (req, res, next) => req.app.csrfProtection(req, res, next), async (req, res) => {
  const secure = process.env.NODE_ENV === 'production';
  await User.findByIdAndUpdate(req.user.sub, { $unset: { refreshId: "" } });
  res.clearCookie('accessToken', { httpOnly: true, secure, sameSite: 'lax' });
  res.clearCookie('refreshToken', { httpOnly: true, secure, sameSite: 'lax' });
  res.json({ ok: true });
});

export default router;
