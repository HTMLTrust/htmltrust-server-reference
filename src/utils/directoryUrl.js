const directoryBaseUrl = (req, env = process.env) => {
  const configured = env.DIRECTORY_BASE_URL;
  if (configured) {
    const url = new URL(configured);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('DIRECTORY_BASE_URL must use http or https');
    }
    return url.href.replace(/\/$/, '');
  }

  // The request-origin fallback keeps local development and the conformance
  // runner on HTTP. Deployments serving canonical key URLs must set an
  // explicit HTTPS DIRECTORY_BASE_URL.
  return `${req.protocol}://${req.get('host')}`;
};

const directoryKeyUrl = (req, keyId, env = process.env) =>
  `${directoryBaseUrl(req, env)}/keys/${encodeURIComponent(String(keyId))}`;

const publicKeyId = (key) => String(key.publicId || key._id);

module.exports = { directoryBaseUrl, directoryKeyUrl, publicKeyId };
