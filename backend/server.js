// Imports & Setup
const axios = require('axios');
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const AutoIncrement = require('mongoose-sequence')(mongoose);
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  _id: Number,
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' },
  status: { type: String, enum: ['new', 'active'], default: 'new' },
  isDeleted: { type: Boolean, default: false }
}, { _id: false, timestamps: true });

userSchema.plugin(AutoIncrement, { id: 'user_seq', inc_field: '_id' });
const User = mongoose.model('User', userSchema);

// Auth Middleware
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied: no token' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Role Middleware
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: insufficient permissions' });
    }
    next();
  };
};

// Routes

// Register
app.post('/register', [
  body('username').isLength({ min: 3 }),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('firstName').notEmpty(),
  body('lastName').notEmpty(),
  body('role').optional().isIn(['user', 'admin', 'moderator'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password, firstName, lastName, role } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ error: 'Username already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword, firstName, lastName, role });
  await user.save();
  res.status(201).json({ message: 'User registered', user });
});

// Login
app.post('/login', [
  body('username').notEmpty(),
  body('password').notEmpty()
], async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, isDeleted: false });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});
// Add this route to your backend after the login route (around line 105)


// Get All Users (Role-Based)

app.get('/users', authenticate, async (req, res) => {
  try {
    const { id, role } = req.user;
    let query = { isDeleted: false };

    if (role === 'user') {
      query.status = 'active';
      query._id = { $ne: id };
    }

    const users = await User.find(query).lean();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});




// Get Deleted Users (Admin Only)
app.get('/users/deleted', authenticate, authorize('admin'), async (req, res) => {
  const users = await User.find({ isDeleted: true });
  res.json(users);
});

// Get User by ID
app.get('/users/:id', authenticate, async (req, res) => {
  const requestedId = parseInt(req.params.id);
  const isAdminOrMod = ['admin', 'moderator'].includes(req.user.role);

  if (!isAdminOrMod && req.user.id !== requestedId) {
    return res.status(403).json({ error: 'Forbidden: you can only view your own profile' });
  }

  try {
    const user = await User.findOne({ _id: requestedId, isDeleted: false }).lean();
    if (!user) return res.status(404).json({ error: 'User not found or deleted' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});



// Update Any User (Admin Only)
app.put('/users/:id', authenticate, authorize('admin'), [
  body('username').optional().isLength({ min: 3 }),
  body('email').optional().isEmail(),
  body('firstName').optional().notEmpty(),
  body('lastName').optional().notEmpty(),
  body('role').optional().isIn(['user', 'admin', 'moderator'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const user = await User.findOneAndUpdate(
      { _id: req.params.id, isDeleted: false },
      req.body,
      { new: true, runValidators: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found or deleted' });
    res.json({ message: 'User updated successfully', user });
  } catch (err) {
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Soft Delete User
app.delete('/users/:id', authenticate, authorize('admin'), async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, { isDeleted: true }, { new: true });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'User soft deleted', user });
});

// Activate User
app.patch('/users/:id/status', authenticate, async (req, res) => {
  const user = await User.findOneAndUpdate(
    { _id: req.params.id, status: 'new' },
    { status: 'active' },
    { new: true }
  );
  if (!user) return res.status(404).json({ error: 'User not found or already active' });
  res.json({ message: 'User activated', user });
});
// SSRF Vulnerable Route
app.get('/api/fetch-data', authenticate, async (req, res) => {
    const { url } = req.query;

    if (!url) {
        return res.status(400).json({ error: 'URL parameter is required' });
    }

    try {
        // VULNERABILITY: The server fetches any URL provided by the user without validation
        const response = await axios.get(url);
        res.json({
            status: "Success",
            data: response.data
        });
    } catch (err) {
        res.status(500).json({ 
            error: 'SSRF Fetch Error', 
            message: err.message 
        });
    }
});
// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));

