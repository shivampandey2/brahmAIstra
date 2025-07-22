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

    if (field === 'email' && value && !SECURITY_CONFIG.VALIDATION_PATTERNS.email.test(value)) {
      return 'Invalid email format';
    }

    if (field === 'category' && !SECURITY_CONFIG.ALLOWED_CATEGORIES.includes(value)) {
      return 'Invalid category';
    }

    return null;
  }

  async login(credentials) {
    return await this.secureRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  }

  async logout() {
    return await this.secureRequest('/auth/logout', { method: 'POST' });
  }

  async getPrompts(filters = {}) {
    const queryParams = new URLSearchParams();
    if (filters.status) queryParams.append('status', filters.status);
    if (filters.category) queryParams.append('category', filters.category);
    
    const queryString = queryParams.toString();
    return await this.secureRequest(`/prompts${queryString ? `?${queryString}` : ''}`);
  }

  async submitPrompt(promptData) {
    return await this.secureRequest('/prompts', {
      method: 'POST',
      body: JSON.stringify(promptData),
    });
  }

  async getPendingPrompts() {
    return await this.secureRequest('/admin/prompts/pending');
  }

  async approvePrompt(id) {
    return await this.secureRequest(`/admin/prompts/${encodeURIComponent(id)}/approve`, {
      method: 'PATCH',
    });
  }

  async rejectPrompt(id) {
    return await this.secureRequest(`/admin/prompts/${encodeURIComponent(id)}/reject`, {
      method: 'PATCH',
    });
  }

  async getJudgePrompts() {
    return await this.secureRequest('/judge/prompts');
  }

  async submitScore(promptId, scoreData) {
    return await this.secureRequest(`/judge/prompts/${encodeURIComponent(promptId)}/score`, {
      method: 'POST',
      body: JSON.stringify(scoreData),
    });
  }

  async getLeaderboard() {
    return await this.secureRequest('/leaderboard');
  }
}

// Fountain Pen Logo Component
const FountainPenLogo = ({ size = 128 }) => (
  <div className="relative" style={{ width: size, height: size }}>
    <svg width={size} height={size} viewBox="0 0 200 200" className="relative z-10">
      <defs>
        <linearGradient id="penGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#f97316" />
          <stop offset="30%" stopColor="#ec4899" />
          <stop offset="60%" stopColor="#8b5cf6" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
        <linearGradient id="swirl1" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
          <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.6" />
          <stop offset="100%" stopColor="#ec4899" stopOpacity="0.4" />
        </linearGradient>
      </defs>
      
      <path 
        d="M50 100 Q 80 60, 120 80 T 170 70" 
        stroke="url(#swirl1)" 
        strokeWidth="3" 
        fill="none"
        className="animate-pulse"
      />
      <path 
        d="M40 120 Q 70 150, 110 130 T 160 140" 
        stroke="url(#swirl1)" 
        strokeWidth="2.5" 
        fill="none"
        className="animate-pulse"
      />
      
      <rect 
        x="80" y="95" 
        width="60" height="10" 
        rx="5" 
        fill="url(#penGradient)" 
        transform="rotate(45 100 100)"
      />
      
      <polygon 
        points="75,100 85,95 85,105" 
        fill="url(#penGradient)" 
        transform="rotate(45 100 100)"
      />
      
      <circle cx="82" cy="82" r="3" fill="#06b6d4" />
    </svg>
    
    <div 
      className="absolute inset-0 bg-gradient-to-br from-orange-400 via-pink-500 to-cyan-400 rounded-full blur-xl opacity-50 animate-pulse"
      style={{
        width: size * 0.8,
        height: size * 0.8,
        left: size * 0.1,
        top: size * 0.1
      }}
    />
  </div>
);

// API Context
const APIContext = createContext();

const APIProvider = ({ children }) => {
  const [api] = useState(() => new SecureAPIClient());
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleError = useCallback((error, context = '') => {
    console.error(`API Error ${context}:`, error);
    const userFriendlyMessage = error.message.includes('Authentication') 
      ? 'Please log in again' 
      : 'Something went wrong. Please try again.';
    
    setError(userFriendlyMessage);
    setTimeout(() => setError(null), 5000);
  }, []);

  const login = useCallback(async (credentials) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await api.login(credentials);
      setUser(response.user);
      return response;
    } catch (error) {
      handleError(error, 'login');
      throw error;
    } finally {
      setLoading(false);
    }
  }, [api, handleError]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
      setUser(null);
    } catch (error) {
      handleError(error, 'logout');
    }
  }, [api, handleError]);

  return (
    <APIContext.Provider value={{
      api,
      user,
      loading,
      error,
      login,
      logout,
      isAuthenticated: !!user,
      isModerator: user?.role === 'moderator',
      isJudge: user?.role === 'judge'
    }}>
      {children}
    </APIContext.Provider>
  );
};

const useAPI = () => {
  const context = useContext(APIContext);
  if (!context) {
    throw new Error('useAPI must be used within an APIProvider');
  }
  return context;
};

// Secure Input Component
const SecureInput = ({ 
  type = 'text', 
  value, 
  onChange, 
  maxLength,
  required,
  placeholder,
  className = '',
  ...props 
}) => {
  const [error, setError] = useState('');

  const handleChange = (e) => {
    let inputValue = e.target.value;
    inputValue = DOMPurify.sanitize(inputValue, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    onChange(inputValue);
  };

  return (
    <div className="mb-4">
      <input
        type={type}
        value={value}
        onChange={handleChange}
        placeholder={placeholder}
        maxLength={maxLength}
        required={required}
        className={`w-full px-4 py-3 bg-black/50 border border-cyan-500/30 rounded-lg focus:ring-2 focus:ring-cyan-400 focus:border-transparent text-white placeholder-gray-400 backdrop-blur-sm transition-all ${className}`}
        {...props}
      />
      {error && (
        <div className="flex items-center mt-2 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 mr-1" />
          {error}
        </div>
      )}
    </div>
  );
};

// Main Dashboard Component
const BrahmAIstraHackathonDashboard = () => {
  const { api, user, login, logout, isAuthenticated, isModerator, isJudge, error } = useAPI();
  const [currentRoute, setCurrentRoute] = useState('/');
  const [prompts, setPrompts] = useState([]);
  const [loading, setLoading] = useState(false);

  const routes = {
    '/': { title: 'Home', icon: Home },
    '/submit': { title: 'Submit Prompt', icon: Send },
    '/moderator': { title: 'Moderator Panel', icon: Shield },
    '/judge': { title: 'Judge Panel', icon: Gavel },
    '/leaderboard': { title: 'Leaderboard', icon: Trophy },
    '/login': { title: 'Login', icon: LogIn }
  };

  const navigateTo = useCallback((route) => {
    const allowedRoutes = ['/', '/submit', '/moderator', '/judge', '/leaderboard', '/login'];
    if (allowedRoutes.includes(route)) {
      setCurrentRoute(route);
    }
  }, []);

  const fetchPrompts = useCallback(async (filters = {}) => {
    try {
      setLoading(true);
      const response = await api.getPrompts(filters);
      setPrompts(Array.isArray(response) ? response : []);
    } catch (error) {
      console.error('Failed to fetch prompts:', error);
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    fetchPrompts();
  }, [fetchPrompts]);

  // Navigation Component
  const Navigation = () => (
    <nav className="bg-black border-b border-pink-500/30 text-white p-4 shadow-2xl">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <FountainPenLogo size={40} />
          <h1 className="text-2xl font-black bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wider">
            BrahmAIstra Hackathon
          </h1>
        </div>
        
        <div className="flex items-center space-x-1">
          {Object.entries(routes).map(([path, route]) => {
            const Icon = route.icon;
            return (
              <button
                key={path}
                onClick={() => navigateTo(path)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all border font-semibold ${
                  currentRoute === path 
                    ? 'bg-gradient-to-r from-orange-400/20 via-pink-500/20 to-cyan-400/20 text-pink-300 border-pink-500/50 shadow-lg shadow-pink-500/20' 
                    : 'hover:bg-gradient-to-r hover:from-orange-400/10 hover:via-pink-500/10 hover:to-cyan-400/10 border-transparent hover:border-pink-500/30 text-gray-300 hover:text-white'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="hidden md:inline font-semibold">{route.title}</span>
              </button>
            );
          })}
        </div>

        {user && (
          <div className="flex items-center space-x-4">
            <span className="text-sm text-pink-300 font-medium">Welcome, {user.name}</span>
            <button 
              onClick={logout}
              className="bg-gradient-to-r from-red-500 via-pink-500 to-orange-500 hover:from-red-600 hover:via-pink-600 hover:to-orange-600 px-4 py-2 rounded-lg text-sm transition-all font-bold shadow-lg shadow-pink-500/20 text-white"
            >
              Logout
            </button>
          </div>
        )}
      </div>
    </nav>
  );

  // Home Page
  const HomePage = () => (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute top-20 left-20 w-96 h-96 bg-gradient-to-r from-orange-400/20 via-pink-500/20 to-purple-600/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 right-20 w-96 h-96 bg-gradient-to-r from-cyan-400/20 via-blue-500/20 to-teal-400/20 rounded-full blur-3xl animate-pulse delay-1000"></div>
      </div>
      
      <div className="container mx-auto px-4 py-16 relative z-10">
        <div className="text-center">
          <div className="flex justify-center mb-8">
            <FountainPenLogo size={160} />
          </div>
          
          <div className="mb-6">
            <div className="text-4xl text-white mb-4 font-bold">Coming</div>
            <div className="text-4xl text-white mb-6 font-bold">Soon !</div>
          </div>
          
          <h1 className="text-6xl font-black mb-4 bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wide">
            BRAHM-AI-STRA
          </h1>
          
          <div className="text-lg text-gray-300 italic mb-4 font-light">Innovation Starts, Where Hesitation Ends !</div>
          
          <p className="text-xl mb-4 text-white font-bold tracking-wide">GET READY TO WITNESS YOUR OWN BRILLIANCE.</p>
          
          <div className="text-lg text-gray-300 mb-12 font-semibold tracking-wider">3 MONTHS | 3 TEAMS EVERY MONTH | 30 MIN OF GAME-CHANGING THINKING</div>
          
          <div className="max-w-4xl mx-auto mb-12">
            <p className="text-xl mb-8 leading-relaxed text-gray-300 font-light">
              Unleash the power of artificial intelligence! Join the most innovative hackathon where brilliant minds 
              compete to create groundbreaking AI solutions that will shape the future.
            </p>
            
            <div className="grid md:grid-cols-3 gap-8 mb-12">
              <div className="bg-gradient-to-br from-orange-400/10 via-pink-500/10 to-purple-600/10 backdrop-blur-lg rounded-xl p-6 border border-pink-500/20 hover:border-pink-500/40 transition-all hover:shadow-xl hover:shadow-pink-500/20">
                <Crown className="w-12 h-12 text-orange-400 mb-4 mx-auto" />
                <h3 className="text-xl font-bold mb-2 text-pink-300">Epic Prizes</h3>
                <p className="text-gray-400 font-light">Win amazing rewards and recognition from industry leaders</p>
              </div>
              
              <div className="bg-gradient-to-br from-pink-500/10 via-purple-600/10 to-cyan-400/10 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20 hover:border-purple-500/40 transition-all hover:shadow-xl hover:shadow-purple-500/20">
                <Zap className="w-12 h-12 text-pink-400 mb-4 mx-auto" />
                <h3 className="text-xl font-bold mb-2 text-purple-300">Innovation</h3>
                <p className="text-gray-400 font-light">Push the boundaries of what's possible with AI technology</p>
              </div>
              
              <div className="bg-gradient-to-br from-purple-600/10 via-cyan-400/10 to-teal-400/10 backdrop-blur-lg rounded-xl p-6 border border-cyan-400/20 hover:border-cyan-400/40 transition-all hover:shadow-xl hover:shadow-cyan-400/20">
                <User className="w-12 h-12 text-cyan-400 mb-4 mx-auto" />
                <h3 className="text-xl font-bold mb-2 text-cyan-300">Community</h3>
                <p className="text-gray-400 font-light">Connect with like-minded developers and AI enthusiasts</p>
              </div>
            </div>
          </div>
          
          <div className="space-x-6">
            <button 
              onClick={() => navigateTo('/submit')}
              className="bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 text-black px-8 py-4 rounded-full font-black text-lg hover:shadow-xl hover:shadow-pink-500/30 transition-all transform hover:scale-105 tracking-wide"
            >
              Submit Your Prompt <ArrowRight className="inline w-5 h-5 ml-2" />
            </button>
            
            <button 
              onClick={() => navigateTo('/leaderboard')}
              className="bg-transparent border-2 border-pink-400 text-pink-400 px-8 py-4 rounded-full font-black text-lg hover:bg-pink-400/10 hover:shadow-xl hover:shadow-pink-400/30 transition-all tracking-wide"
            >
              View Leaderboard
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  // Submit Page
  const SubmitPage = () => {
    const [formData, setFormData] = useState({
      title: '',
      description: '',
      author: '',
      email: '',
      category: 'Other'
    });

    const handleSubmitPrompt = async (e) => {
      e.preventDefault();
      try {
        setLoading(true);
        await api.submitPrompt(formData);
        alert('Prompt submitted successfully!');
        setFormData({ title: '', description: '', author: '', email: '', category: 'Other' });
        await fetchPrompts();
      } catch (error) {
        alert('Submission failed: ' + error.message);
      } finally {
        setLoading(false);
      }
    };

    return (
      <div className="min-h-screen bg-black py-12">
        <div className="max-w-2xl mx-auto p-6">
          <h2 className="text-4xl font-bold mb-8 text-center bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wider">
            Submit Your AI Prompt
          </h2>
          
          <div className="bg-gradient-to-br from-orange-400/10 via-pink-500/10 to-cyan-400/10 backdrop-blur-lg rounded-xl border border-cyan-500/20 p-8 shadow-2xl shadow-cyan-500/10">
            <form onSubmit={handleSubmitPrompt} className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-cyan-300 mb-3 tracking-wide">
                  PROMPT TITLE *
                </label>
                <SecureInput
                  placeholder="Enter your AI prompt title..."
                  value={formData.title}
                  onChange={(value) => setFormData(prev => ({ ...prev, title: value }))}
                  maxLength={SECURITY_CONFIG.MAX_INPUT_LENGTH.title}
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-cyan-300 mb-3 tracking-wide">
                  AUTHOR NAME *
                </label>
                <SecureInput
                  placeholder="Your name or team name..."
                  value={formData.author}
                  onChange={(value) => setFormData(prev => ({ ...prev, author: value }))}
                  maxLength={SECURITY_CONFIG.MAX_INPUT_LENGTH.author}
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-cyan-300 mb-3 tracking-wide">
                  EMAIL (Optional)
                </label>
                <SecureInput
                  type="email"
                  placeholder="your.email@example.com"
                  value={formData.email}
                  onChange={(value) => setFormData(prev => ({ ...prev, email: value }))}
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-cyan-300 mb-3 tracking-wide">
                  CATEGORY *
                </label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData(prev => ({ ...prev, category: e.target.value }))}
                  className="w-full px-4 py-3 bg-black/50 border border-cyan-500/30 rounded-lg focus:ring-2 focus:ring-cyan-400 focus:border-transparent text-white backdrop-blur-sm"
                  required
                >
                  {SECURITY_CONFIG.ALLOWED_CATEGORIES.map(category => (
                    <option key={category} value={category} className="bg-black">
                      {category}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-semibold text-cyan-300 mb-3 tracking-wide">
                  PROMPT DESCRIPTION *
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData(prev => ({ ...prev, description: DOMPurify.sanitize(e.target.value, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }) }))}
                  rows={6}
                  maxLength={SECURITY_CONFIG.MAX_INPUT_LENGTH.description}
                  className="w-full px-4 py-3 bg-black/50 border border-cyan-500/30 rounded-lg focus:ring-2 focus:ring-cyan-400 focus:border-transparent text-white placeholder-gray-400 backdrop-blur-sm"
                  placeholder="Describe your AI prompt idea in detail..."
                  required
                />
                <div className="text-xs text-gray-400 mt-1">
                  {formData.description.length}/{SECURITY_CONFIG.MAX_INPUT_LENGTH.description} characters
                </div>
              </div>

              <button
                type="submit"
                disabled={loading || !formData.title || !formData.description || !formData.author}
                className="w-full bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 text-black py-3 px-6 rounded-lg font-bold hover:shadow-xl hover:shadow-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all tracking-wide"
              >
                {loading ? (
                  <div className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-black mr-2"></div>
                    SUBMITTING...
                  </div>
                ) : (
                  <>
                    <Send className="inline w-5 h-5 mr-2" />
                    SUBMIT PROMPT
                  </>
                )}
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  };

  // Login Page
  const LoginPage = () => {
    const handleLogin = async (role) => {
      try {
        const credentials = {
          username: role === 'judge' ? 'judge1' : 'admin',
          password: role === 'judge' ? 'judge123!' : 'admin123!'
        };
        await login(credentials);
        navigateTo(role === 'judge' ? '/judge' : '/moderator');
      } catch (error) {
        alert('Login failed: ' + error.message);
      }
    };

    return (
      <div className="min-h-screen bg-black flex items-center justify-center py-12">
        <div className="max-w-md mx-auto p-6">
          <h2 className="text-4xl font-bold mb-8 text-center bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wider">
            LOGIN
          </h2>
          
          <div className="bg-gradient-to-br from-orange-400/10 via-pink-500/10 to-cyan-400/10 backdrop-blur-lg rounded-xl border border-cyan-500/20 p-6 shadow-2xl shadow-cyan-500/10">
            <p className="text-gray-300 mb-6 text-center">
              Select your role to access the hackathon dashboard:
            </p>
            
            <div className="space-y-4">
              <button
                onClick={() => handleLogin('judge')}
                disabled={loading}
                className="w-full flex items-center justify-center space-x-2 bg-gradient-to-r from-magenta-400 to-purple-500 text-black py-3 px-6 rounded-lg hover:shadow-xl hover:shadow-magenta-500/30 transition-all font-medium tracking-wide disabled:opacity-50"
              >
                <Gavel className="w-5 h-5" />
                <span>LOGIN AS JUDGE</span>
              </button>
              
              <button
                onClick={() => handleLogin('moderator')}
                disabled={loading}
                className="w-full flex items-center justify-center space-x-2 bg-gradient-to-r from-cyan-400 to-blue-500 text-black py-3 px-6 rounded-lg hover:shadow-xl hover:shadow-cyan-500/30 transition-all font-medium tracking-wide disabled:opacity-50"
              >
                <Shield className="w-5 h-5" />
                <span>LOGIN AS MODERATOR</span>
              </button>
            </div>
            
            <p className="text-sm text-gray-400 mt-4 text-center">
              This is a demo - credentials are pre-configured
            </p>
          </div>
        </div>
      </div>
    );
  };

  // Simple Moderator Panel
  const ModeratorPanel = () => {
    const [pendingPrompts, setPendingPrompts] = useState([]);

    useEffect(() => {
      if (isModerator) {
        api.getPendingPrompts().then(setPendingPrompts).catch(console.error);
      }
    }, [api, isModerator]);

    if (!isModerator) {
      return (
        <div className="min-h-screen bg-black flex items-center justify-center">
          <div className="text-center py-12">
            <Shield className="w-16 h-16 mx-auto text-cyan-400 mb-4" />
            <h2 className="text-2xl font-bold text-white mb-4">Moderator Access Required</h2>
            <button
              onClick={() => navigateTo('/login')}
              className="bg-gradient-to-r from-cyan-400 to-blue-500 text-black px-6 py-3 rounded-lg hover:shadow-xl hover:shadow-cyan-500/30 transition-all font-medium"
            >
              Login as Moderator
            </button>
          </div>
        </div>
      );
    }

    const handleApprove = async (id) => {
      try {
        await api.approvePrompt(id);
        setPendingPrompts(prev => prev.filter(p => p.id !== id));
        await fetchPrompts();
      } catch (error) {
        alert('Approval failed: ' + error.message);
      }
    };

    const handleReject = async (id) => {
      try {
        await api.rejectPrompt(id);
        setPendingPrompts(prev => prev.filter(p => p.id !== id));
      } catch (error) {
        alert('Rejection failed: ' + error.message);
      }
    };

    return (
      <div className="min-h-screen bg-black py-12">
        <div className="max-w-4xl mx-auto p-6">
          <h2 className="text-4xl font-bold mb-8 text-center bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wider">
            MODERATOR PANEL
          </h2>
          
          <div className="bg-gradient-to-br from-orange-400/10 via-pink-500/10 to-cyan-400/10 backdrop-blur-lg rounded-xl border border-cyan-500/20 p-6 shadow-2xl shadow-cyan-500/10">
            <h3 className="text-xl font-semibold mb-4 text-cyan-300">
              Pending Prompts ({pendingPrompts.length})
            </h3>
            
            {pendingPrompts.length === 0 ? (
              <p className="text-gray-400 text-center py-8">No pending prompts to review</p>
            ) : (
              <div className="space-y-4">
                {pendingPrompts.map(prompt => (
                  <div key={prompt.id} className="bg-black/30 border border-cyan-500/20 rounded-lg p-4">
                    <div className="flex justify-between items-start mb-2">
                      <h4 className="font-semibold text-lg text-white">
                        {DOMPurify.sanitize(prompt.title)}
                      </h4>
                      <span className="text-sm text-cyan-300">
                        by {DOMPurify.sanitize(prompt.author)}
                      </span>
                    </div>
                    <p className="text-gray-300 mb-4 max-h-32 overflow-y-auto">
                      {DOMPurify.sanitize(prompt.description)}
                    </p>
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleApprove(prompt.id)}
                        className="flex items-center space-x-1 bg-gradient-to-r from-green-500 to-emerald-500 text-white px-4 py-2 rounded hover:shadow-lg hover:shadow-green-500/30 transition-all"
                      >
                        <CheckCircle className="w-4 h-4" />
                        <span>Approve</span>
                      </button>
                      <button
                        onClick={() => handleReject(prompt.id)}
                        className="flex items-center space-x-1 bg-gradient-to-r from-red-500 to-pink-500 text-white px-4 py-2 rounded hover:shadow-lg hover:shadow-red-500/30 transition-all"
                      >
                        <XCircle className="w-4 h-4" />
                        <span>Reject</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // Simple Judge Panel
  const JudgePanel = () => {
    const [approvedPrompts, setApprovedPrompts] = useState([]);

    useEffect(() => {
      if (isJudge) {
        api.getJudgePrompts().then(setApprovedPrompts).catch(console.error);
      }
    }, [api, isJudge]);

    if (!isJudge) {
      return (
        <div className="min-h-screen bg-black flex items-center justify-center">
          <div className="text-center py-12">
            <Gavel className="w-16 h-16 mx-auto text-magenta-400 mb-4" />
            <h2 className="text-2xl font-bold text-white mb-4">Judge Access Required</h2>
            <button
              onClick={() => navigateTo('/login')}
              className="bg-gradient-to-r from-magenta-400 to-purple-500 text-black px-6 py-3 rounded-lg hover:shadow-xl hover:shadow-magenta-500/30 transition-all font-medium"
            >
              Login as Judge
            </button>
          </div>
        </div>
      );
    }

    const handleScore = async (promptId, score) => {
      try {
        await api.submitScore(promptId, { score });
        const updated = await api.getJudgePrompts();
        setApprovedPrompts(updated);
        await fetchPrompts();
      } catch (error) {
        alert('Scoring failed: ' + error.message);
      }
    };

    return (
      <div className="min-h-screen bg-black py-12">
        <div className="max-w-4xl mx-auto p-6">
          <h2 className="text-4xl font-bold mb-8 text-center bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wider">
            JUDGE PANEL
          </h2>
          
          <div className="bg-gradient-to-br from-orange-400/10 via-pink-500/10 to-cyan-400/10 backdrop-blur-lg rounded-xl border border-cyan-500/20 p-6 shadow-2xl shadow-cyan-500/10">
            <h3 className="text-xl font-semibold mb-4 text-cyan-300">
              Approved Prompts for Scoring ({approvedPrompts.length})
            </h3>
            
            {approvedPrompts.length === 0 ? (
              <p className="text-gray-400 text-center py-8">No approved prompts available for scoring</p>
            ) : (
              <div className="space-y-6">
                {approvedPrompts.map(prompt => (
                  <div key={prompt.id} className="bg-black/30 border border-cyan-500/20 rounded-lg p-4">
                    <div className="flex justify-between items-start mb-2">
                      <h4 className="font-semibold text-lg text-white">
                        {DOMPurify.sanitize(prompt.title)}
                      </h4>
                      <div className="text-right">
                        <span className="text-sm text-cyan-300">
                          by {DOMPurify.sanitize(prompt.author)}
                        </span>
                        <div className="text-sm text-gray-400">
                          Avg Score: <span className="text-cyan-400 font-semibold">
                            {prompt.avgScore || 0}
                          </span>
                          {prompt.reviewCount > 0 && (
                            <span className="ml-2">({prompt.reviewCount} reviews)</span>
                          )}
                        </div>
                        {prompt.userScore && (
                          <div className="text-sm text-green-400">
                            Your Score: {prompt.userScore}
                          </div>
                        )}
                      </div>
                    </div>
                    <p className="text-gray-300 mb-4 max-h-32 overflow-y-auto">
                      {DOMPurify.sanitize(prompt.description)}
                    </p>
                    
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-medium text-cyan-300">Your Score:</span>
                      {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(score => (
                        <button
                          key={score}
                          onClick={() => handleScore(prompt.id, score)}
                          disabled={!!prompt.userScore}
                          className={`w-8 h-8 rounded-full border-2 text-sm font-medium transition-all ${
                            prompt.userScore === score
                              ? 'bg-gradient-to-r from-cyan-400 to-blue-500 text-black border-cyan-400'
                              : prompt.userScore
                              ? 'border-gray-600 text-gray-500 cursor-not-allowed'
                              : 'border-cyan-400/50 hover:bg-gradient-to-r hover:from-cyan-400 hover:to-blue-500 hover:text-black hover:border-cyan-400 text-cyan-300 hover:shadow-lg hover:shadow-cyan-500/30'
                          }`}
                        >
                          {score}
                        </button>
                      ))}
                    </div>
                    {prompt.userScore && (
                      <div className="text-sm text-gray-400 mt-2">
                        You have already scored this prompt
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // Leaderboard
  const LeaderboardPage = () => {
    const [leaderboard, setLeaderboard] = useState([]);

    useEffect(() => {
      api.getLeaderboard().then(setLeaderboard).catch(console.error);
    }, [api]);

    return (
      <div className="min-h-screen bg-black py-12">
        <div className="max-w-4xl mx-auto p-6">
          <h2 className="text-4xl font-bold mb-8 text-center bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wider">
            🏆 LEADERBOARD
          </h2>
          
          <div className="bg-gradient-to-br from-orange-400/10 via-pink-500/10 to-cyan-400/10 backdrop-blur-lg rounded-xl border border-cyan-500/20 p-6 shadow-2xl shadow-cyan-500/10">
            {leaderboard.length === 0 ? (
              <p className="text-gray-400 text-center py-8">No scored prompts yet</p>
            ) : (
              <div className="space-y-4">
                {leaderboard.map((prompt, index) => (
                  <div 
                    key={prompt.id} 
                    className={`border-l-4 rounded-lg p-4 backdrop-blur-sm ${
                      index === 0 ? 'border-cyan-400 bg-gradient-to-r from-cyan-500/20 to-blue-500/20' :
                      index === 1 ? 'border-blue-400 bg-gradient-to-r from-blue-500/20 to-purple-500/20' :
                      index === 2 ? 'border-pink-400 bg-gradient-to-r from-purple-500/20 to-pink-500/20' :
                      'border-gray-400 bg-gradient-to-r from-gray-500/10 to-gray-600/10'
                    }`}
                  >
                    <div className="flex justify-between items-start">
                      <div className="flex items-center space-x-4">
                        <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-lg ${
                          index === 0 ? 'bg-gradient-to-r from-cyan-400 to-blue-500 text-black' :
                          index === 1 ? 'bg-gradient-to-r from-blue-400 to-purple-500 text-white' :
                          index === 2 ? 'bg-gradient-to-r from-purple-400 to-pink-500 text-white' :
                          'bg-gradient-to-r from-gray-400 to-gray-500 text-black'
                        }`}>
                          #{index + 1}
                        </div>
                        <div>
                          <h4 className="font-semibold text-lg text-white">
                            {DOMPurify.sanitize(prompt.title)}
                          </h4>
                          <p className="text-cyan-300">
                            by {DOMPurify.sanitize(prompt.author)}
                          </p>
                        </div>
                      </div>
                      
                      <div className="text-right">
                        <div className="flex items-center space-x-1">
                          <Star className="w-5 h-5 text-cyan-400 fill-current" />
                          <span className="font-bold text-xl text-cyan-400">
                            {prompt.avgScore}
                          </span>
                        </div>
                        <p className="text-sm text-gray-400">
                          {prompt.reviewCount} reviews
                        </p>
                      </div>
                    </div>
                    
                    <p className="text-gray-300 mt-2 max-h-20 overflow-y-auto">
                      {DOMPurify.sanitize(prompt.description)}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // Route renderer
  const renderCurrentPage = () => {
    switch (currentRoute) {
      case '/':
        return <HomePage />;
      case '/submit':
        return <SubmitPage />;
      case '/moderator':
        return <ModeratorPanel />;
      case '/judge':
        return <JudgePanel />;
      case '/leaderboard':
        return <LeaderboardPage />;
      case '/login':
        return <LoginPage />;
      default:
        return <HomePage />;
    }
  };

  return (
    <div className="min-h-screen bg-black">
      <Navigation />
      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 m-4">
          <div className="flex items-center">
            <AlertCircle className="w-5 h-5 text-red-400 mr-2" />
            <span className="text-red-300">{error}</span>
          </div>
        </div>
      )}
      <main className="py-8">
        {renderCurrentPage()}
      </main>
      
      <footer className="bg-black border-t border-pink-500/20 text-white py-8 mt-12">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <div className="flex justify-center items-center space-x-3 mb-4">
            <FountainPenLogo size={32} />
            <span className="text-lg font-black bg-gradient-to-r from-orange-400 via-pink-500 to-cyan-400 bg-clip-text text-transparent tracking-wide">BRAHM-AI-STRA</span>
          </div>
          <p className="text-gray-400 italic font-light">Innovation Starts, Where Hesitation Ends !</p>
        </div>
      </footer>
      
      {loading && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400"></div>
        </div>
      )}
    </div>
  );
};

// Main App Component
function App() {
  return (
    <APIProvider>
      <BrahmAIstraHackathonDashboard />
    </APIProvider>
  );
}

export default App;
