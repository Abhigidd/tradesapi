const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const bodyParser = require('body-parser');

const app = express();
app.use(express.json());

app.use(bodyParser.json());
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ message: 'Invalid JSON payload' });
  }
  next();
});

const JWT_SECRET = 'secrettoken'; 
let users = [];
let trades = [
  {
    id: 1,
    type: 'buy',
    user_id: 1,
    symbol: 'AAPL',
    shares: 50,
    price: 150,
    timestamp: Date.now(),
  },
  {
    id: 2,
    type: 'sell',
    user_id: 2,
    symbol: 'GOOGL',
    shares: 20,
    price: 2800,
    timestamp: Date.now(),
  },
];

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('Authorization header:', authHeader);
  console.log('Token:', token);

  if (!token) {
    return res.status(401).json({ message: 'Token missing or not provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err);
      return res.status(403).json({ message: 'Token is invalid or expired' });
    }

    req.user = user;
    next();
  });
};

app.post('/signup',
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    const user = { id: users.length + 1, email, password: hashedPassword };
    users.push(user);
    res.status(201).json({ message: 'User created successfully' });
  }
);

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const accessToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '10m' });

  res.json({ accessToken });
});

app.post('/trades', authenticateToken,
  body('type').isIn(['buy', 'sell']),
  body('user_id').isInt(),
  body('symbol').isString(),
  body('shares').isInt({ min: 1, max: 100 }),
  body('price').isFloat({ min: 0.01 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { type, user_id, symbol, shares, price } = req.body;
    const newTrade = {
      id: trades.length ? trades[trades.length - 1].id + 1 : 1,
      type,
      user_id,
      symbol,
      shares,
      price,
      timestamp: Date.now(),
    };

    trades.push(newTrade);
    res.status(201).json(newTrade);
  }
);

app.get('/trades', authenticateToken, (req, res) => {
  const { type, user_id } = req.query;
  let result = trades;  // Initialize result with all trades

  if (type) result = result.filter((trade) => trade.type === type);
  if (user_id) result = result.filter((trade) => trade.user_id === parseInt(user_id));

  res.status(200).json(result);
});

app.get('/trades/:id', authenticateToken, (req, res) => {
  const trade = trades.find((t) => t.id === parseInt(req.params.id));
  if (!trade) return res.status(404).json({ message: 'Trade not found' });

  res.status(200).json(trade);
});

app.post('/trades', authenticateToken, (req, res) => {
  res.status(400).json({ message: 'Read-only mode. Creation is not allowed.' });
});

app.put('/trades/:id', authenticateToken, (req, res) => {
  res.status(400).json({ message: 'Read-only mode. Modification is not allowed.' });
});

app.patch('/trades/:id', authenticateToken, (req, res) => {
  res.status(400).json({ message: 'Read-only mode. Modification is not allowed.' });
});

app.delete('/trades/:id', authenticateToken, (req, res) => {
  res.status(400).json({ message: 'Read-only mode. Deletion is not allowed.' });
});

app.post('/logout', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Logged out successfully' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
