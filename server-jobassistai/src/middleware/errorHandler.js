export function errorHandler(err, req, res, next) {
    if (process.env.NODE_ENV !== 'production') {
      console.error(err);
    }
    res.status(500).json({ error: 'Server error' });
  }
  