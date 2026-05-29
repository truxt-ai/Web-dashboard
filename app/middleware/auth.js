// WIP: JWT authentication middleware.
// Token validation against the secret store is not yet wired up — see issue #31.
// Currently only parses the Authorization header and attaches a decoded payload.

const AUTH_HEADER = 'authorization';

function parseBearer(header) {
  if (!header || !header.toLowerCase().startsWith('bearer ')) return null;
  return header.slice(7).trim();
}

// TODO(auth): replace stub decode with real jwt.verify() once secret store is ready
function stubDecode(token) {
  if (!token) return null;
  return { sub: 'unknown', token };
}

function authMiddleware(req, res, next) {
  const token = parseBearer(req.headers[AUTH_HEADER]);
  req.user = stubDecode(token);
  // TODO(auth): return 401 when token is missing/invalid once validation is in place
  next();
}

module.exports = { authMiddleware, parseBearer };
