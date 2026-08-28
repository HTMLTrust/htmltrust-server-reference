const { problem } = require('../utils/htmltrustProtocol');

/**
 * Apply the HTTP semantics shared by the canonical directory endpoints.
 *
 * The draft permits application/json as a compatibility representation, but
 * a client that explicitly asks for another representation must receive 406
 * rather than silently getting JSON. Public reads are cacheable and Express
 * supplies an ETag when the response is serialized; Cache-Control and Vary
 * make those validators usable by shared caches.
 */
const negotiate = (responseType, {
  cacheControl = 'public, max-age=60, must-revalidate',
  requestBody = false,
} = {}) => (req, res, next) => {
  res.vary('Accept');

  const selectedType = req.accepts([responseType, 'application/json']);
  if (!selectedType) {
    return problem(
      res,
      406,
      'Not acceptable',
      `The endpoint can return ${responseType} or application/json`,
      {
        type: 'https://htmltrust.org/errors/not-acceptable',
        accepted: [responseType, 'application/json'],
      },
    );
  }

  req.htmltrustResponseType = selectedType;

  if (requestBody) {
    const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/json' && !contentType.endsWith('+json')) {
      return problem(
        res,
        415,
        'Unsupported media type',
        'Canonical directory submissions require an application/json representation',
        {
          type: 'https://htmltrust.org/errors/unsupported-media-type',
          accepted: ['application/json', 'application/*+json'],
        },
      );
    }
  }

  res.set('Cache-Control', cacheControl);
  return next();
};

const negotiatedType = (req, fallback) => req.htmltrustResponseType || fallback;

module.exports = { negotiate, negotiatedType };
