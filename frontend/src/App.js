import React, { useState, useEffect, useContext, createContext, useCallback } from 'react';
import { 
  Home, Send, Shield, Gavel, Trophy, LogIn, Star, CheckCircle, XCircle, 
  ArrowRight, Sparkles, Zap, Crown, User, AlertCircle
} from 'lucide-react';
import DOMPurify from 'dompurify';

// Security Configuration
const SECURITY_CONFIG = {
  MAX_INPUT_LENGTH: {
    title: 200,
    description: 5000,
    author: 100
  },
  ALLOWED_CATEGORIES: [
    'Development Tools', 'Healthcare', 'Smart Cities', 'Education',
    'Finance', 'Entertainment', 'Environment', 'Security', 'Other'
  ],
  VALIDATION_PATTERNS: {
    title: /^[a-zA-Z0-9\s\-_.,!?()]+$/,
    author: /^[a-zA-Z0-9\s\-_']+$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  }
};

// Secure API Client
class SecureAPIClient {
  constructor(baseURL = process.env.REACT_APP_API_URL || '/api') {
    this.baseURL = baseURL;
  }

  async secureRequest(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    
    const config = {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      if (response.ok) {
        const data = await response.json();
        return this.sanitizeResponse(data);
      }

      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP ${response.status}`);

    } catch (error) {
      console.error(`API Error [${endpoint}]:`, error);
      throw error;
    }
  }

  sanitizeResponse(data) {
    if (typeof data === 'string') {
      return DOMPurify.sanitize(data);
    }

    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeResponse(item));
    }

    if (data && typeof data === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitizeResponse(value);
      }
      return sanitized;
    }

    return data;
  }

  validateInput(data, field) {
    const value = data[field];
    
    if (!value && field !== 'email') {
      return `${field} is required`;
    }

    if (value && value.length > SECURITY_CONFIG.MAX_INPUT_LENGTH[field]) {
      return `${field} exceeds maximum length`;
    }

    if (SECURITY_CONFIG.VALIDATION_PATTERNS[field] && value && !SECURITY_CONFIG.VALIDATION_PATTERNS[field].test(value)) {
      return `${field} contains invalid characters`;
    }

    if (field === 'email' && value && !SECURITY_CONFIG.VALIDATION_PATTERNS.em
