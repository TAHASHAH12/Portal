 // server.js - Node.js Express Authentication Server
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files

// In-memory user store (replace with database in production)
const users = [
    {
        id: 1,
        username: 'admin',
        password: bcrypt.hashSync('password123', 10),
        role: 'admin'
    },
    {
        id: 2,
        username: 'user1',
        password: bcrypt.hashSync('seotools2025', 10),
        role: 'user'
    },
    {
        id: 3,
        username: 'demo',
        password: bcrypt.hashSync('demo123', 10),
        role: 'demo'
    }
];

// Tool configurations
const toolConfigs = {
    'seo-analyzer': {
        url: 'https://anchor-modification-jorvz2ergrnngqsdst2f4r.streamlit.app/',
        name: 'SEO Link Opportunity Analyzer',
        requiredRole: 'user'
    },
    'reverse-linkscience': {
        url: 'https://linkscience-ec3btbud6nqittyksto4wo.streamlit.app/',
        name: 'Reverse LinkScience',
        requiredRole: 'user'
    },
    'semantic-similarity': {
        url: 'https://cstool-g45qneb96haneuhmsuqlvz.streamlit.app/',
        name: 'Semantic Similarity Backlink Analyzer',
        requiredRole: 'user'
    }
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Find user
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify token endpoint
app.get('/api/verify', authenticateToken, (req, res) => {
    res.json({
        valid: true,
        user: req.user
    });
});

// Get available tools
app.get('/api/tools', authenticateToken, (req, res) => {
    const userRole = req.user.role;
    const availableTools = {};

    Object.keys(toolConfigs).forEach(toolKey => {
        const tool = toolConfigs[toolKey];
        if (hasPermission(userRole, tool.requiredRole)) {
            availableTools[toolKey] = {
                name: tool.name,
                url: tool.url
            };
        }
    });

    res.json(availableTools);
});

// Get tool access URL with auth
app.get('/api/tool/:toolKey', authenticateToken, (req, res) => {
    const { toolKey } = req.params;
    const tool = toolConfigs[toolKey];

    if (!tool) {
        return res.status(404).json({ error: 'Tool not found' });
    }

    if (!hasPermission(req.user.role, tool.requiredRole)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }

    // In a real implementation, you might:
    // 1. Generate a temporary access token for the tool
    // 2. Log the access
    // 3. Return a proxied URL with authentication

    res.json({
        toolName: tool.name,
        accessUrl: tool.url,
        message: 'Access granted'
    });
});

// Logout endpoint (for token blacklisting in production)
app.post('/api/logout', authenticateToken, (req, res) => {
    // In production, you would blacklist the token
    res.json({ message: 'Logged out successfully' });
});

// Helper function to check permissions
function hasPermission(userRole, requiredRole) {
    const roleHierarchy = {
        'demo': 0,
        'user': 1,
        'admin': 2
    };

    return roleHierarchy[userRole] >= roleHierarchy[requiredRole];
}

// Serve frontend files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Login at: http://localhost:${PORT}`);
    console.log(`Dashboard at: http://localhost:${PORT}/dashboard`);
});

module.exports = app;
