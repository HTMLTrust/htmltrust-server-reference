const directoryBaseUrl = (req, env = process.env) => {
  const configured = env.DIRECTORY_BASE_URL;
  if (configured) {
    const url = new URL(configured);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('DIRECTORY_BASE_URL must use http or https');
    }
    if (env.NODE_ENV === 'production' && url.protocol !== 'https:') {
      throw new Error('DIRECTORY_BASE_URL must use https in production');
    }
    return url.href.replace(/\/$/, '');
  }

  if (env.NODE_ENV === 'production') {
    throw new Error('DIRECTORY_BASE_URL must be set in production');
  }

  // The request-origin fallback keeps local development and the conformance
  // runner on HTTP. Deployments serving canonical key URLs must set an
  // explicit HTTPS DIRECTORY_BASE_URL.
  return `${req.protocol}://${req.get('host')}`;
};

const directoryKeyUrl = (req, keyId, env = process.env) =>
  `${directoryBaseUrl(req, env)}/keys/${encodeURIComponent(String(keyId))}`;

const publicKeyId = (key) => String(key.publicId || key._id);

const assertDirectoryBaseUrl = (env = process.env) => {
  if (env.NODE_ENV !== 'production') return;
  directoryBaseUrl(null, env);
};

module.exports = { assertDirectoryBaseUrl, directoryBaseUrl, directoryKeyUrl, publicKeyId };
