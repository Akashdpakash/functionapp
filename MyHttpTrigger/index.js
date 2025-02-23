const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config();

const users = new Map();

const authenticateToken = (req) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return { status: 401, body: { error: 'Access token required here' } };
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    return { user };
  } catch (err) {
    return { status: 403, body: { error: 'Invalid or expired token' } };
  }
};

module.exports = async function (context, req) {
  if (req.method === 'POST' && req.url === '/api/register') {
    const { username, password } = req.body;

    if (!username || !password) {
      context.res = { status: 400, body: { error: 'Username and password are required' } };
      return;
    }

    if (users.has(username)) {
      context.res = { status: 400, body: { error: 'Username already exists' } };
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.set(username, { username, password: hashedPassword });

    context.res = { status: 201, body: { message: 'User registered successfully' } };
  } else if (req.method === 'POST' && req.url === '/api/login') {
    const { username, password } = req.body;

    if (!username || !password) {
      context.res = { status: 400, body: { error: 'Username and password are required' } };
      return;
    }

    const user = users.get(username);

    if (!user) {
      context.res = { status: 401, body: { error: 'Invalid credentials' } };
      return;
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      context.res = { status: 401, body: { error: 'Invalid credentials' } };
      return;
    }

    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    context.res = { body: { token } };
  } else if (req.method === 'GET' && req.url === '/api/protected') {
    const result = authenticateToken(req);

    if (result.status) {
      context.res = result;
      return;
    }

    context.res = { body: { message: 'This is a protected route', user: result.user } };
  } else {
    context.res = { status: 404, body: { error: 'Route not found' } };
  }
};