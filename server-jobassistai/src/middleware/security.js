import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import csrf from 'csurf';
import morgan from 'morgan';
import mongoSanitize from 'mongo-sanitize';
import crypto from 'node:crypto';

export function applySecurityMiddleware(app) {
  const isProd = process.env.NODE_ENV === 'production';

  app.use(
    helmet({
      contentSecurityPolicy: isProd
        ? {
            useDefaults: true,
            directives: {
              "default-src": ["'self'"],
              "script-src": ["'self'"],
              "style-src": ["'self'", "'unsafe-inline'"],
              "img-src": ["'self'", 'data:'],
              "font-src": ["'self'", 'data:'],
              "connect-src": ["'self'"],
              "frame-ancestors": ["'none'"],
              "object-src": ["'none'"],
              "base-uri": ["'self'"],
            },
          }
        : false,
      hsts: isProd,
      frameguard: { action: 'deny' },
      referrerPolicy: { policy: 'no-referrer' },
      xssFilter: true,
      noSniff: true,
    })
  );

  const FRONTEND_ORIGIN =
    process.env.NODE_ENV === 'production'
      ? process.env.FRONTEND_ORIGIN || 'https://yourapp.com'
      : process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

  app.use(
    cors({
      origin: FRONTEND_ORIGIN,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    })
  );

  const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use(globalLimiter);

  app.authLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.apiLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.heavyOperationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.csrfProtection = csrf({
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: isProd,
    },
  });

  app.use((req, res, next) => {
    const requestId = req.headers['x-request-id'] || crypto.randomUUID();
    req.id = requestId;
    res.setHeader('X-Request-Id', requestId);
    next();
  });

  morgan.token('id', (req) => req.id);
  app.use(
    morgan(':id :method :url :status :res[content-length] - :response-time ms')
  );

  app.use((req, _res, next) => {
    if (req.body) req.body = mongoSanitize(req.body);
    if (req.query) req.query = mongoSanitize(req.query);
    if (req.params) req.params = mongoSanitize(req.params);
    next();
  });
}
