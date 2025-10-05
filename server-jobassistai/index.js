import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';

import { applySecurityMiddleware } from './src/middleware/security.js';
import { connectDB } from './src/db/connection.js';
import authRoutes from './src/routes/auth.js';
import apiRoutes from './src/routes/api.js';
import { errorHandler } from './src/middleware/errorHandler.js';

const PORT = Number(process.env.PORT || 4000);
const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');

const requiredEnvs = ['MONGO_URI', 'JWT_SECRET', 'JWT_REFRESH_SECRET', 'FRONTEND_ORIGIN'];
const missing = requiredEnvs.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

await connectDB();

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

applySecurityMiddleware(app);

app.get('/csrf', app.csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get('/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.use('/api/auth', authRoutes);
app.use('/api', apiRoutes);

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use(errorHandler);

app.listen(PORT, () => console.log(`API running on http://localhost:${PORT} (env: ${process.env.NODE_ENV})`));
