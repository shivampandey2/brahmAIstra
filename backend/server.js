// server.js - BrahmAIstra Hackathon Secure Backend
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const { body, param, query, validationResult } = require('express-validator');
const winston = require('winston');
const crypto = require('crypto');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Validate required environment variables
const requiredEnvVars = [
  'JWT_SECRET',
  'MONGODB_URI',
  'NODE_ENV'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Security Configuration
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
const JWT_EXPIRY = '15m';
const MAX_REQUEST_SIZE = '10mb';

// Logging Configuration
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'brahmastra-api' },
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Security middleware stack
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));

app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: MAX_REQUEST_SIZE }));
app.use(express.urlencoded({ extended: true, limit: MAX_REQUEST_SIZE }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
  process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
  ['http://localhost:3000'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);

// Request logging
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  },
  skip: (req) => req.path === '/api/health'
}));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  logger.info('✅ MongoDB connected securely');
}).catch(err => {
  logger.error('❌ MongoDB connection failed', { error: err.message });
  process.exit(1);
});

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9_-]+$/
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  role: {
    type: String,
    enum: ['moderator', 'judge', 'participant'],
    default: 'participant'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  }
}, {
  timestamps: true
});

// Password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, BCRYPT_ROUNDS);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Prompt Schema
const promptSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    minlength: 5,
    maxlength: 200
  },
  description: {
    type: String,
    required: true,
    trim: true,
    minlength: 20,
    maxlength: 5000
  },
  author: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  email: {
    type: String,
    trim: true,
    lowercase: true
  },
  category: {
    type: String,
    required: true,
    enum: [
      'Development Tools', 'Healthcare', 'Smart Cities', 'Education',
      'Finance', 'Entertainment', 'Environment', 'Security', 'Other'
    ]
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  submitterIP: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

const Prompt = mongoose.model('Prompt', promptSchema);

// Score Schema
const scoreSchema = new mongoose.Schema({
  promptId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Prompt',
    required: true
  },
  judgeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  score: {
    type: Number,
    required: true,
    min: 1,
    max: 10
  },
  feedback: {
    type: String,
    trim: true,
    maxlength: 2000
  }
}, {
  timestamps: true
});

scoreSchema.index({ promptId: 1, judgeId: 1 }, { unique: true });
const Score = mongoose.model('Score', scoreSchema);

// Validation middleware
const validateInput = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array().map(err => ({
          field: err.param,
          message: err.msg
        }))
      });
    }
    next();
  };
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.access_token || 
                 (req.headers.authorization && req.headers.authorization.split(' ')[1]);

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Authorization middleware
const authorize = (roles) => {
  return async (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Seed default users
const seedUsers = async () => {
  try {
    const userCount = await User.countDocuments();
    if (userCount > 0) return;

    const defaultUsers = [
      {
        username: 'admin',
        email: 'admin@brahmastra.com',
        password: 'admin123!',
        name: 'Admin User',
        role: 'moderator'
      },
      {
        username: 'judge1',
        email: 'judge1@brahmastra.com',
        password: 'judge123!',
        name: 'Judge Smith',
        role: 'judge'
      },
      {
        username: 'judge2',
        email: 'judge2@brahmastra.com',
        password: 'judge123!',
        name: 'Judge Wilson',
        role: 'judge'
      }
    ];

    await User.insertMany(defaultUsers);
    logger.info('✅ Default users created');
  } catch (error) {
    logger.error('❌ Failed to seed users', { error: error.message });
  }
};

// Initialize database
seedUsers();

// Health check
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Authentication routes
app.post('/api/auth/login',
  validateInput([
    body('username').isLength({ min: 3, max: 30 }).trim(),
    body('password').isLength({ min: 8, max: 128 })
  ]),
  async (req, res) => {
    try {
      const { username, password } = req.body;

      const user = await User.findOne({ username }).select('+password');
      
      if (!user || !(await user.comparePassword(password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      if (!user.isActive) {
        return res.status(401).json({ error: 'Account is inactive' });
      }

      const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
      );

      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      };

      res.cookie('access_token', token, cookieOptions);

      res.json({
        message: 'Login successful',
        user: {
          id: user._id,
          username: user.username,
          role: user.role,
          name: user.name
        }
      });

    } catch (error) {
      logger.error('Login error', { error: error.message });
      res.status(500).json({ error: 'Authentication failed' });
    }
  }
);

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    res.clearCookie('access_token');
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error', { error: error.message });
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Prompt routes
app.get('/api/prompts', async (req, res) => {
  try {
    const { status, category } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (category && category !== 'all') filter.category = category;

    const prompts = await Prompt.find(filter)
      .select('-submitterIP')
      .sort({ createdAt: -1 })
      .lean();

    const promptIds = prompts.map(p => p._id);
    const scores = await Score.find({ promptId: { $in: promptIds } }).lean();

    const promptsWithScores = prompts.map(prompt => {
      const promptScores = scores.filter(s => s.promptId.toString() === prompt._id.toString());
      const scoreValues = promptScores.map(s => s.score);
      const avgScore = scoreValues.length > 0 ? 
        Math.round((scoreValues.reduce((a, b) => a + b, 0) / scoreValues.length) * 10) / 10 : 0;

      return {
        ...prompt,
        id: prompt._id,
        _id: undefined,
        avgScore,
        reviewCount: scoreValues.length
      };
    });

    res.json(promptsWithScores);
  } catch (error) {
    logger.error('Get prompts error', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch prompts' });
  }
});

app.post('/api/prompts',
  validateInput([
    body('title').isLength({ min: 5, max: 200 }).trim(),
    body('description').isLength({ min: 20, max: 5000 }).trim(),
    body('author').isLength({ min: 2, max: 100 }).trim(),
    body('email').optional().isEmail(),
    body('category').isIn([
      'Development Tools', 'Healthcare', 'Smart Cities', 'Education',
      'Finance', 'Entertainment', 'Environment', 'Security', 'Other'
    ])
  ]),
  async (req, res) => {
    try {
      const { title, description, author, email, category } = req.body;

      const newPrompt = new Prompt({
        title: title.trim(),
        description: description.trim(),
        author: author.trim(),
        email: email || null,
        category: category || 'Other',
        submitterIP: req.ip
      });

      await newPrompt.save();

      res.status(201).json({
        message: 'Prompt submitted successfully',
        id: newPrompt._id
      });

    } catch (error) {
      logger.error('Submit prompt error', { error: error.message });
      res.status(500).json({ error: 'Failed to submit prompt' });
    }
  }
);

// Admin routes
app.get('/api/admin/prompts/pending',
  authenticateToken,
  authorize(['moderator']),
  async (req, res) => {
    try {
      const pendingPrompts = await Prompt.find({ status: 'pending' })
        .select('-submitterIP')
        .sort({ createdAt: -1 })
        .lean();

      res.json(pendingPrompts.map(prompt => ({
        ...prompt,
        id: prompt._id,
        _id: undefined
      })));
    } catch (error) {
      logger.error('Get pending prompts error', { error: error.message });
      res.status(500).json({ error: 'Failed to fetch pending prompts' });
    }
  }
);

app.patch('/api/admin/prompts/:id/approve',
  authenticateToken,
  authorize(['moderator']),
  validateInput([param('id').isMongoId()]),
  async (req, res) => {
    try {
      const promptId = req.params.id;

      const prompt = await Prompt.findById(promptId);
      if (!prompt) {
        return res.status(404).json({ error: 'Prompt not found' });
      }

      if (prompt.status !== 'pending') {
        return res.status(400).json({ error: 'Prompt is not pending approval' });
      }

      await Prompt.findByIdAndUpdate(promptId, {
        status: 'approved',
        approvedBy: req.user._id
      });

      res.json({ message: 'Prompt approved successfully' });

    } catch (error) {
      logger.error('Approve prompt error', { error: error.message });
      res.status(500).json({ error: 'Failed to approve prompt' });
    }
  }
);

app.patch('/api/admin/prompts/:id/reject',
  authenticateToken,
  authorize(['
