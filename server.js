const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');

const app = express();
const PORT = 5173;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  }
});

app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.'
  }
});

// CORS configuration
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'image/jpeg', 'image/png'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOC, DOCX, JPG, PNG files are allowed.'));
    }
  }
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Mock user database for authentication
const users = [
  {
    id: 'judge-alemu',
    username: 'judge.alemu',
    password: 'Judge123!', // In production, use proper hashing
    name: 'Judge Alemu Bekele',
    email: 'a.bekele@court.gov.et',
    roles: ['judge', 'court_admin'],
    permissions: ['case_management', 'hearing_control', 'virtual_hearing', 'user_management', 'reporting', 'system_config'],
    mfaEnabled: true,
    mfaSecret: '123456', // In production, use proper MFA
    isActive: true,
    lastLogin: new Date().toISOString(),
    failedAttempts: 0,
    isLocked: false
  },
  {
    id: 'lawyer-sara',
    username: 'lawyer.sara',
    password: 'Lawyer123!',
    name: 'Lawyer Sara Ahmed',
    email: 's.ahmed@lawfirm.et',
    roles: ['lawyer'],
    permissions: ['case_management', 'virtual_hearing', 'communication'],
    mfaEnabled: true,
    mfaSecret: '123456',
    isActive: true,
    lastLogin: new Date().toISOString(),
    failedAttempts: 0,
    isLocked: false
  },
  {
    id: 'admin-system',
    username: 'admin.system',
    password: 'Admin123!',
    name: 'System Administrator',
    email: 'admin@court.gov.et',
    roles: ['admin'],
    permissions: ['user_management', 'case_management', 'hearing_control', 'virtual_hearing', 'communication', 'reporting', 'system_config', 'security'],
    mfaEnabled: true,
    mfaSecret: '123456',
    isActive: true,
    lastLogin: new Date().toISOString(),
    failedAttempts: 0,
    isLocked: false
  },
  {
    id: 'clerk-mohammed',
    username: 'clerk.mohammed',
    password: 'Clerk123!',
    name: 'Clerk Mohammed Hassan',
    email: 'm.hassan@court.gov.et',
    roles: ['clerk'],
    permissions: ['case_management', 'communication'],
    mfaEnabled: false,
    mfaSecret: '123456',
    isActive: true,
    lastLogin: new Date().toISOString(),
    failedAttempts: 0,
    isLocked: false
  },
  {
    id: 'plaintiff-john',
    username: 'plaintiff.john',
    password: 'User123!',
    name: 'John Doe',
    email: 'john.doe@email.com',
    roles: ['plaintiff'],
    permissions: ['case_management', 'virtual_hearing'],
    mfaEnabled: false,
    mfaSecret: '123456',
    isActive: true,
    lastLogin: new Date().toISOString(),
    failedAttempts: 0,
    isLocked: false
  }
];

// JWT Secret (in production, use environment variable)
const JWT_SECRET = 'ethiopian-court-system-jwt-secret-2024';

// Mock JWT functions (in production, use jsonwebtoken)
const jwt = {
  sign: (payload, secret) => {
    return Buffer.from(JSON.stringify({...payload, iat: Date.now()})).toString('base64');
  },
  decode: (token) => {
    try {
      return JSON.parse(Buffer.from(token, 'base64').toString());
    } catch (error) {
      return null;
    }
  }
};

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  try {
    const decoded = jwt.decode(token);
    
    if (!decoded || !decoded.userId) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }

    const user = users.find(u => u.id === decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'User not found or inactive'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
};

// Middleware for role-based access control
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions.includes(permission)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }
    next();
  };
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/case-management', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'case-management.html'));
});

app.get('/virtual-hearing', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'virtual-hearing.html'));
});

app.get('/courtroom-control', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'courtroom-control.html'));
});

app.get('/communication', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'communication.html'));
});

app.get('/messages', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'communication.html'));
});

app.get('/notifications', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'notifications.html'));
});

app.get('/reporting', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reporting.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/integration', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'integration.html'));
});

app.get('/security', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'security.html'));
});

// Authentication endpoints
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { username, password, mfaCode } = req.body;

  try {
    const user = users.find(u => u.username === username);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    if (user.isLocked) {
      return res.status(423).json({
        success: false,
        message: 'Account locked due to multiple failed attempts'
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account is inactive'
      });
    }

    const passwordValid = password === user.password;
    
    if (!passwordValid) {
      user.failedAttempts += 1;
      
      if (user.failedAttempts >= 5) {
        user.isLocked = true;
        console.log(`ACCOUNT_LOCKED: ${username} at ${new Date().toISOString()}`);
      }
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        attemptsRemaining: 5 - user.failedAttempts
      });
    }

    user.failedAttempts = 0;
    user.isLocked = false;

    if (user.mfaEnabled) {
      if (!mfaCode) {
        const mfaToken = jwt.sign(
          { 
            userId: user.id, 
            mfaRequired: true,
            timestamp: Date.now()
          }, 
          JWT_SECRET
        );

        return res.json({
          success: true,
          requiresMFA: true,
          mfaToken: mfaToken,
          message: 'MFA code required'
        });
      }

      if (mfaCode.length !== 6 || !/^\d{6}$/.test(mfaCode)) {
        return res.status(401).json({
          success: false,
          message: 'Invalid MFA code'
        });
      }
    }

    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        roles: user.roles,
        permissions: user.permissions
      },
      JWT_SECRET
    );

    user.lastLogin = new Date().toISOString();
    console.log(`LOGIN_SUCCESS: ${username} at ${new Date().toISOString()}`);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token: token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          roles: user.roles,
          permissions: user.permissions
        },
        expiresIn: 86400
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Authentication failed'
    });
  }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  console.log(`LOGOUT: ${req.user.username} at ${new Date().toISOString()}`);
  
  res.json({
    success: true,
    message: 'Logout successful'
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({
    success: true,
    data: {
      id: req.user.id,
      username: req.user.username,
      name: req.user.name,
      email: req.user.email,
      roles: req.user.roles,
      permissions: req.user.permissions,
      lastLogin: req.user.lastLogin
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Ethiopian Digital Court System is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    uptime: process.uptime()
  });
});

// Mock API endpoints
app.get('/api/cases', authenticateToken, (req, res) => {
  const mockCases = [
    {
      id: 'CIV-2026-001',
      title: 'Contract Dispute',
      type: 'Civil',
      status: 'Active',
      plaintiff: 'John Doe',
      defendant: 'ABC Corporation',
      filedDate: '2026-03-01',
      assignedJudge: 'Judge Alemu Bekele'
    }
  ];
  
  res.json({
    success: true,
    data: mockCases,
    total: mockCases.length
  });
});

app.get('/api/users', authenticateToken, requirePermission('user_management'), (req, res) => {
  const mockUsers = users.map(u => ({
    id: u.id,
    username: u.username,
    name: u.name,
    email: u.email,
    roles: u.roles,
    isActive: u.isActive
  }));
  
  res.json({
    success: true,
    data: mockUsers,
    total: mockUsers.length
  });
});

// Catch-all handler for frontend routes (SPA support)
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      success: false,
      message: 'API endpoint not found'
    });
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error.stack);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🏛️ Ethiopian Digital Court System running on http://localhost:${PORT}`);
  console.log(`📊 Health check available at http://localhost:${PORT}/health`);
  console.log(`📚 System ready for testing`);
});
