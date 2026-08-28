const directoryBaseUrl = (req, env = process.env) => {
  const configured = env.DIRECTORY_BASE_URL;
  if (configured) {
    const url = new URL(configured);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('DIRECTORY_BASE_URL must use http or https');
    }
    return url.href.replace(/\/$/, '');
  }

  return `${req.protocol}://${req.get('host')}`;
};

const directoryKeyUrl = (req, keyId, env = process.env) =>
  `${directoryBaseUrl(req, env)}/keys/${encodeURIComponent(String(keyId))}`;

module.exports = { directoryBaseUrl, directoryKeyUrl };
