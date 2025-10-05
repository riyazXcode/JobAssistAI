import express from 'express';
import { User } from '../models/User.js';
import { authMiddleware } from '../auth/auth.js';

const router = express.Router();

router.use((req, res, next) => req.app.apiLimiter(req, res, next));

router.get('/profile', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.sub).select('email role createdAt').lean();
  res.json(user);
});

export default router;
