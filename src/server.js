const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const { problem } = require('./utils/htmltrustProtocol');
const { assertConfigured } = require('./utils/apiKeys');

// Fail fast on a misconfigured production deployment rather than at the first
// request that happens to need the missing secret.
assertConfigured();

// Database connection
const connectDB = require('./config/db');
connectDB();

// Initialize Express app
const app = express();

// Security headers. The demo UI at / pulls Bootstrap and crypto-js from
// jsdelivr and carries one inline <style> block, so those two sources are
// allowed and nothing else is. The API responses are JSON, so the remaining
// directives are as tight as the static page permits.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'none'"],
        'script-src': ["'self'", 'https://cdn.jsdelivr.net'],
        'style-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
        'connect-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'"],
        'base-uri': ["'none'"],
        'form-action': ["'none'"],
        'frame-ancestors': ["'none'"],
        'object-src': ["'none'"],
      },
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    referrerPolicy: { policy: 'no-referrer' },
  })
);

// Middleware
app.use(cors());

// Capture the raw body: RFC 9421 Content-Digest verification
// (middleware/httpSignature.js) has to hash the bytes that were actually
// received, not a re-serialization of the parsed object.
app.use(
  express.json({
    limit: process.env.MAX_REQUEST_BODY || '256kb',
    // Canonical directory resources use vendor JSON media types such as
    // application/htmltrust-content+json. Keep application/json accepted for
    // compatibility with the pre-v1 API surface.
    type: ['application/json', 'application/*+json'],
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

/**
 * Rate limits (draft §9.9: "Directories SHOULD apply rate limits per IP, per
 * submitter key, and per content hash, and SHOULD signal exhaustion with 429
 * Too Many Requests and a Retry-After header").
 *
 * NOTE ON PROXIES: these limit by `req.ip`. Behind a reverse proxy every
 * request appears to come from the proxy unless Express is told to trust it.
 * Set TRUST_PROXY to the number of proxy hops in front of this server (see
 * https://expressjs.com/en/guide/behind-proxies.html); leaving it unset is
 * correct for a directly-exposed server and is the safe default, because
 * trusting an untrusted X-Forwarded-For lets a caller forge a fresh identity
 * per request and bypass every limit below.
 */
if (process.env.TRUST_PROXY) {
  const hops = Number(process.env.TRUST_PROXY);
  app.set('trust proxy', Number.isFinite(hops) ? hops : process.env.TRUST_PROXY);
}

const limitResponse = (req, res) => {
  res.set('Retry-After', '60');
  return problem(
    res,
    429,
    'Too many requests',
    'The request rate limit for this endpoint has been exceeded; retry after the interval in the Retry-After header',
    { type: 'https://htmltrust.org/errors/rate-limited' }
  );
};

const limiter = (windowMs, limit) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    handler: limitResponse,
    // The conformance suite drives hundreds of requests from one address in
    // seconds; limits stay on in test but with headroom.
    skip: () => process.env.DISABLE_RATE_LIMIT === '1',
  });

// Global limiter: covers every route including public reads.
app.use(limiter(60 * 1000, Number(process.env.RATE_LIMIT_GLOBAL || 600)));

// Credential-checking routes are the ones worth brute-forcing.
const authLimiter = limiter(60 * 1000, Number(process.env.RATE_LIMIT_AUTH || 30));

// Routes that mutate reputation or add records are the ones worth flooding.
const writeLimiter = limiter(60 * 1000, Number(process.env.RATE_LIMIT_WRITE || 60));
const { negotiate } = require('./middleware/contentNegotiation');

// Canonical HTMLTrust v1 directory surface. POST requests use the exact
// RFC 9421 profile and never fall back to a shared API key.
const { requireActorSignature } = require('./middleware/httpSignature');
const {
  getContentRecordV1,
  listContentEndorsements,
  submitContentV1,
} = require('./controllers/contentController');
const {
  createEndorsement,
} = require('./controllers/endorsementController');
const {
  getKeyDocument,
  getSignerReputation,
} = require('./controllers/directoryController');

app.post(
  '/content',
  writeLimiter,
  negotiate('application/htmltrust-content+json', { cacheControl: 'no-store', requestBody: true }),
  requireActorSignature({ strictV1: true }),
  submitContentV1,
);
app.get(
  '/content/:contentHash/endorsements',
  negotiate('application/htmltrust-endorsement+json'),
  listContentEndorsements,
);
app.get(
  '/content/:contentHash',
  negotiate('application/htmltrust-content+json'),
  getContentRecordV1,
);
app.post(
  '/endorsements',
  writeLimiter,
  negotiate('application/htmltrust-endorsement+json', { cacheControl: 'no-store', requestBody: true }),
  requireActorSignature({ strictV1: true }),
  createEndorsement,
);
app.get('/keys/:id', negotiate('application/htmltrust-key+json'), getKeyDocument);
app.get(
  '/signers/:id/reputation',
  negotiate('application/json'),
  getSignerReputation,
);

// Explicit pre-v1 compatibility surface used by the demo UI and the original
// conformance runner. These routes retain their documented API-key fallback.
app.use('/api/authors', authLimiter, require('./routes/authors'));
app.use('/api/content', writeLimiter, require('./routes/content'));
app.use('/api/claims', require('./routes/claims'));
app.use('/api/directory', writeLimiter, require('./routes/directory'));
app.use('/api/votes', writeLimiter, require('./routes/votes'));
app.use('/api/endorsements', writeLimiter, require('./routes/endorsements'));
app.use('/api/keys', require('./routes/keys'));
app.use('/api/signers', require('./routes/signers'));

const { discovery } = require('./controllers/directoryController');
app.get(
  '/.well-known/htmltrust',
  negotiate('application/htmltrust-directory+json', { cacheControl: 'public, max-age=3600, must-revalidate' }),
  discovery,
);
app.get(
  '/api/.well-known/htmltrust',
  negotiate('application/htmltrust-directory+json', { cacheControl: 'public, max-age=3600, must-revalidate' }),
  discovery,
);

app.use(express.static(path.join(__dirname, 'public')));

// Default route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware. Errors are reported in the problem-details
// format draft §9.9 requires, and the internal message is never echoed: the
// default is production behaviour, and only an explicit NODE_ENV=development
// opts into detail (see detailFor()).
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return problem(res, 413, 'Payload too large', 'The request body exceeds the accepted size');
  }
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
    return problem(res, 400, 'Malformed request', 'The request body is not valid JSON');
  }
  console.error(err.stack || err);
  return problem(
    res,
    500,
    'Internal server error',
    process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong on the server'
  );
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
