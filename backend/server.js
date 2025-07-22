// server.js - BrahmAIstra Hackathon Secure Backend (PostgreSQL Version)
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const { body, param, validationResult } = require('express-validator');
const winston = require('winston');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// In-memory database (Railway will provide PostgreSQL later, this works for demo)
let database = {
  users: [
    {
      id: 1,
      username: 'admin',
      password: '$2a$12$rOvHdS.3TmYvYh8fJLJyOuK7u.t5LqJrFt4E1XqE8gE2OqF7z.7OK', // admin123!
      name: 'Admin User',
      role: 'moderator',
      email: 'admin@brahmastra.com',
      isActive: true,
      loginAttempts: 0,
      createdAt: new Date().toISOString()
    },
    {
      id: 2,
      username: 'judge1',
      password: '$2a$12$rOvHdS.3TmYvYh8fJLJyOuK7u.t5LqJrFt4E1XqE8gE2OqF7z.7OK', // judge123!
      name: 'Judge Smith',
      role: 'judge',
      email: 'judge1@brahmastra.com',
      isActive: true,
      loginAttempts: 0,
      createdAt: new Date().toISOString()
    },
    {
      id: 3,
      username: 'judge2',
      password: '$2a$12$rOvHdS.3TmYvYh8fJLJyOuK7u.t5LqJrFt4E1XqE8gE2OqF7z.7OK', // judge123!
      name: 'Judge Wilson',
      role: 'judge',
      email: 'judge2@brahmastra.com',
      isActive: true,
      loginAttempts: 0,
      createdAt: new Date().toISOString()
    }
  ],
  prompts: [
    {
      id: 1,
      title: "AI-Powered Code Reviewer",
      description: "Create an AI system that reviews code for bugs, performance issues, and best practices. The system should integrate with popular IDEs and provide real-time suggestions for developers.",
      author: "DevMaster42",
      email: "devmaster@example.com",
      category: "Development Tools",
      status: "approved",
      submittedAt: "2025-07-20T10:30:00Z",
      approvedAt: "2025-07-20T12:00:00Z",
      approvedBy: 1,
      submitterIP: "127.0.0.1"
    },
    {
      id: 2,
      title: "Smart City Traffic Optimizer",
      description: "Design an AI solution to optimize traffic flow in urban areas using real-time data from sensors, cameras, and GPS devices. Include predictive analytics for traffic patterns.",
      author: "CityPlanner",
      email: "cityplanner@example.com",
      category: "Smart Cities",
      status: "pending",
      submittedAt: "2025-07-21T14:15:00Z",
      submitterIP: "127.0.0.1"
    },
    {
      id: 3,
      title: "Medical Diagnosis Assistant",
      description: "Build an AI assistant that helps doctors with preliminary medical diagnosis using patient symptoms, medical history, and diagnostic test results.",
      author: "HealthTech",
      email: "healthtech@example.com",
      category: "Healthcare",
      status: "approved",
      submittedAt: "2025-07-19T09:45:00Z",
      approvedAt: "2025-07-19T11:30:00Z",
      approvedBy: 1,
      submitterIP: "127.0.0.1"
    }
  ],
  scores: [
    { id: 1, promptId: 1, judgeId: 2, score: 8, feedback: "Great concept, well thought out", createdAt: "2025-07-20T15:00:00Z" },
    { id: 2, promptId: 1, judgeId: 3, score: 9, feedback: "Excellent implementation plan", createdAt: "2025-07-20T16:00:00Z" },
    { id: 3, promptId: 3, judgeId: 2, score: 9, feedback: "Very important problem to solve", createdAt: "2025-07-19T14:00:00Z" },
    { id: 4, promptId: 3, judgeId: 3, score: 10, feedback: "Outstanding medical application", createdAt: "2025-07-19T15:00:00Z" }
  ]
};

// Security Configuration
const BCRYPT_ROUNDS = 12;
const JWT_SECRET = process.env.JWT_SECRET || 'brahmastra_demo_secret_key_change_in_production';
const MAX_LOGIN_ATTEMPTS = 5;
const JWT_EXPIRY = '15m';

// Logging Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Security middleware
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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(xss());
app.use(hpp());

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
  process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
  ['http://localhost:3000'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
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
  message: { error: 'Too many requests' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts' }
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);

// Request logging
app.use(morgan('combined', {
  stream: { write: (message) => logger.info(message.trim()) },
  skip: (req) => req.path === '/api/health'
}));

// Helper functions
const getNextId = (collection) => {
  return Math.max(...database[collection].map(item => item.id), 0) + 1;
};

const findUserByCredentials = async (username, password) => {
  const user = database.users.find(u => u.username === username && u.isActive);
  if (!user) return null;
  
  const isValidPassword = await bcrypt.compare(password, user.password);
  return isValidPassword ? user : null;
};

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

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = database.users.find(u => u.id === decoded.id && u.isActive);
    
    if (!user) {
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
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Health check
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    database: 'connected'
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

      const user = await findUserByCredentials(username, password);
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { id: user.id, role: user.role },
        JWT_SECRET,
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
          id: user.id,
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

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.clearCookie('access_token');
  res.json({ message: 'Logged out successfully' });
});

// Prompt routes
app.get('/api/prompts', (req, res) => {
  try {
    const { status, category } = req.query;
    let prompts = [...database.prompts];

    if (status) prompts = prompts.filter(p => p.status === status);
    if (category && category !== 'all') prompts = prompts.filter(p => p.category === category);

    const promptsWithScores = prompts.map(prompt => {
      const promptScores = database.scores.filter(s => s.promptId === prompt.id);
      const scores = promptScores.map(s => s.score);
      const avgScore = scores.length > 0 ? 
        Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10 : 0;

      return {
        ...prompt,
        avgScore,
        reviewCount: scores.length,
        submitterIP: undefined // Remove IP from public response
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
  (req, res) => {
    try {
      const { title, description, author, email, category } = req.body;

      const newPrompt = {
        id: getNextId('prompts'),
        title: title.trim(),
        description: description.trim(),
        author: author.trim(),
        email: email || null,
        category: category || 'Other',
        status: 'pending',
        submittedAt: new Date().toISOString(),
        submitterIP: req.ip
      };

      database.prompts.push(newPrompt);

      res.status(201).json({
        message: 'Prompt submitted successfully',
        id: newPrompt.id
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
  (req, res) => {
    try {
      const pendingPrompts = database.prompts
        .filter(p => p.status === 'pending')
        .map(p => ({ ...p, submitterIP: undefined }));
      
      res.json(pendingPrompts);
    } catch (error) {
      logger.error('Get pending prompts error', { error: error.message });
      res.status(500).json({ error: 'Failed to fetch pending prompts' });
    }
  }
);

app.patch('/api/admin/prompts/:id/approve',
  authenticateToken,
  authorize(['moderator']),
  validateInput([param('id').isInt()]),
  (req, res) => {
    try {
      const promptId = parseInt(req.params.id);
      const prompt = database.prompts.find(p => p.id === promptId);

      if (!prompt) {
        return res.status(404).json({ error: 'Prompt not found' });
      }

      if (prompt.status !== 'pending') {
        return res.status(400).json({ error: 'Prompt is not pending approval' });
      }

      prompt.status = 'approved';
      prompt.approvedAt = new Date().toISOString();
      prompt.approvedBy = req.user.id;

      res.json({ message: 'Prompt approved successfully' });

    } catch (error) {
      logger.error('Approve prompt error', { error: error.message });
      res.status(500).json({ error: 'Failed to approve prompt' });
    }
  }
);

app.patch('/api/admin/prompts/:id/reject',
  authenticateToken,
  authorize(['moderator']),
  validateInput([param('id').isInt()]),
  (req, res) => {
    try {
      const promptId = parseInt(req.params.id);
      const prompt = database.prompts.find(p => p.id === promptId);

      if (!prompt) {
        return res.status(404).json({ error: 'Prompt not found' });
      }

      if (prompt.status !== 'pending') {
        return res.status(400).json({ error: 'Prompt is not pending approval' });
      }

      prompt.status = 'rejected';
      prompt.rejectedAt = new Date().toISOString();
      prompt.rejectedBy = req.user.id;

      res.json({ message: 'Prompt rejected successfully' });

    } catch (error) {
      logger.error('Reject prompt error', { error: error.message });
      res.status(500).json({ error: 'Failed to reject prompt' });
    }
  }
);

// Judge routes
app.get('/api/judge/prompts',
  authenticateToken,
  authorize(['judge']),
  (req, res) => {
    try {
      const approvedPrompts = database.prompts.filter(p => p.status === 'approved');
      const userScores = database.scores.filter(s => s.judgeId === req.user.id);

      const promptsWithScores = approvedPrompts.map(prompt => {
        const promptScores = database.scores.filter(s => s.promptId === prompt.id);
        const userScore = userScores.find(s => s.promptId === prompt.id);
        const scores = promptScores.map(s => s.score);
        const avgScore = scores.length > 0 ? 
          Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10 : 0;

        return {
          ...prompt,
          avgScore,
          reviewCount: scores.length,
          userScore: userScore ? userScore.score : null,
          submitterIP: undefined
        };
      });

      res.json(promptsWithScores);

    } catch (error) {
      logger.error('Get judge prompts error', { error: error.message });
      res.status(500).json({ error: 'Failed to fetch prompts for scoring' });
    }
  }
);

app.post('/api/judge/prompts/:id/score',
  authenticateToken,
  authorize(['judge']),
  validateInput([
    param('id').isInt(),
    body('score').isInt({ min: 1, max: 10 })
  ]),
  (req, res) => {
    try {
      const promptId = parseInt(req.params.id);
      const { score, feedback } = req.body;

      const prompt = database.prompts.find(p => p.id === promptId);
      if (!prompt || prompt.status !== 'approved') {
        return res.status(404).json({ error: 'Prompt not found or not approved' });
      }

      // Check if judge already scored
      const existingScoreIndex = database.scores.findIndex(
        s => s.promptId === promptId && s.judgeId === req.user.id
      );

      if (existingScoreIndex >= 0) {
        // Update existing score
        database.scores[existingScoreIndex] = {
          ...database.scores[existingScoreIndex],
          score,
          feedback: feedback || '',
          updatedAt: new Date().toISOString()
        };
      } else {
        // Create new score
        const newScore = {
          id: getNextId('scores'),
          promptId,
          judgeId: req.user.id,
          score,
          feedback: feedback || '',
          createdAt: new Date().toISOString()
        };
        database.scores.push(newScore);
      }

      res.json({ message: 'Score submitted successfully' });

    } catch (error) {
      logger.error('Submit score error', { error: error.message });
      res.status(500).json({ error: 'Failed to submit score' });
    }
  }
);

// Leaderboard
app.get('/api/leaderboard', (req, res) => {
  try {
    const approvedPrompts = database.prompts.filter(p => p.status === 'approved');

    const leaderboard = approvedPrompts.map(prompt => {
      const promptScores = database.scores.filter(s => s.promptId === prompt.id);
      const scores = promptScores.map(s => s.score);
      const avgScore = scores.length > 0 ? 
        Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10 : 0;

      return {
        ...prompt,
        avgScore,
        reviewCount: scores.length,
        submitterIP: undefined
      };
    })
    .filter(prompt => prompt.reviewCount > 0)
    .sort((a, b) => {
      if (b.avgScore !== a.avgScore) return b.avgScore - a.avgScore;
      return b.reviewCount - a.reviewCount;
    });

    res.json(leaderboard);
  } catch (error) {
    logger.error('Get leaderboard error', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

// Error handlers
app.use('*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message });
  res.status(err.status || 500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  logger.info(`🚀 BrahmAIstra Backend running on port ${PORT}`);
  logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`🔐 Security features enabled`);
  logger.info(`🗄️ Database: In-memory (demo mode)`);
});

module.exports = app;
