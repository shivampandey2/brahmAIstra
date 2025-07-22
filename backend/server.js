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
const JWT_SECRET = process.en
