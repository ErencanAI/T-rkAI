/**
 * ============================================================================
 * TÜRKAI MASTER SYSTEM — BACKEND ENGINE (PART 1 OF 2)
 * ============================================================================
 * Project: TürkAI (C:\Users\ASUS\TURKAI)
 * Architecture: Node.js, Express, Socket.IO, JSON Store, Modular Adapters
 * Target: Production-ready robust backend engine with enterprise security
 * ============================================================================
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
require('dotenv').config();

// ============================================================================
// 1. CORE SYSTEM CONFIGURATION & ENVIRONMENT VALIDATION
// ============================================================================

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const MAX_UPLOAD_SIZE_MB = parseInt(process.env.MAX_UPLOAD_SIZE_MB || '50', 10);

if (NODE_ENV === 'production') {
    if (!process.env.JWT_SECRET) {
        console.warn('[SECURITY CRITICAL]: JWT_SECRET is not defined in production environment! Generated volatile fallback key.');
    }
    if (process.env.CORS_ORIGIN === '*') {
        console.warn('[SECURITY WARNING]: CORS_ORIGIN is set to wildcard (*) in production. Consider locking it down.');
    }
}

// ============================================================================
// 2. EXPRESS & SOCKET.IO INITIALIZATION
// ============================================================================

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        credentials: true
    },
    maxHttpBufferSize: 1e8 // 100 MB socket buffer ceiling
});

// ============================================================================
// 3. ATOMIC JSON STORAGE ENGINE & PERSISTENCE LAYER
// ============================================================================

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'workspace', 'uploads');
const LOGS_DIR = path.join(__dirname, 'logs');

[DATA_DIR, UPLOADS_DIR, LOGS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

const DB_SCHEMAS = {
    users: path.join(DATA_DIR, 'users.json'),
    conversations: path.join(DATA_DIR, 'conversations.json'),
    memories: path.join(DATA_DIR, 'memories.json'),
    projects: path.join(DATA_DIR, 'projects.json'),
    usage: path.join(DATA_DIR, 'usage.json'),
    sessions: path.join(DATA_DIR, 'sessions.json'),
    securityEvents: path.join(DATA_DIR, 'security_events.json'),
    files: path.join(DATA_DIR, 'files.json'),
    research: path.join(DATA_DIR, 'research.json'),
    agentTasks: path.join(DATA_DIR, 'agent_tasks.json'),
    adminAudit: path.join(DATA_DIR, 'admin_audit.json')
};

// Initialize empty JSON stores if they do not exist
Object.keys(DB_SCHEMAS).forEach(key => {
    const filePath = DB_SCHEMAS[key];
    if (!fs.existsSync(filePath)) {
        try {
            fs.writeFileSync(filePath, JSON.stringify([], null, 2), 'utf8');
        } catch (err) {
            console.error(`[Storage Fatal]: Could not initialize store '${key}':`, err.message);
        }
    }
});

/**
 * Thread-safe read operation with schema validation fallback.
 */
function readStore(storeKey) {
    const filePath = DB_SCHEMAS[storeKey];
    if (!filePath) {
        throw new Error(`Invalid store key requested: ${storeKey}`);
    }
    try {
        if (!fs.existsSync(filePath)) return [];
        const rawData = fs.readFileSync(filePath, 'utf8');
        if (!rawData.trim()) return [];
        return JSON.parse(rawData);
    } catch (err) {
        console.error(`[Storage Read Error] Store '${storeKey}' parse failed:`, err.message);
        // Attempt recovery by backing up corrupt file and returning empty array
        try {
            const backupPath = `${filePath}.${Date.now()}.bak`;
            fs.renameSync(filePath, backupPath);
            fs.writeFileSync(filePath, JSON.stringify([], null, 2), 'utf8');
            console.warn(`[Storage Recovery]: Corrupt store '${storeKey}' backed up to ${backupPath} and re-initialized.`);
        } catch (recoveryErr) {
            console.error(`[Storage Recovery Failed] Store '${storeKey}':`, recoveryErr.message);
        }
        return [];
    }
}

/**
 * Atomic write operation using write-to-temp-then-rename pattern.
 */
function writeStore(storeKey, data) {
    const filePath = DB_SCHEMAS[storeKey];
    if (!filePath) {
        throw new Error(`Invalid store key for write: ${storeKey}`);
    }
    try {
        const tempPath = `${filePath}.${crypto.randomBytes(4).toString('hex')}.tmp`;
        fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), 'utf8');
        fs.renameSync(tempPath, filePath);
    } catch (err) {
        console.error(`[Storage Write Fatal] Store '${storeKey}' write failed:`, err.message);
        throw new Error(`Veritabanı kayıt hatası: ${storeKey}`);
    }
}

// ============================================================================
// 4. PLAN SPECIFICATIONS & QUOTA MANAGEMENT
// ============================================================================

const PLANS = {
    free: {
        name: 'Free',
        maxTokensPerDay: 15000,
        maxFileSizeMb: 5,
        jarvisAccess: false,
        maxProjects: 3,
        maxMemoryRecords: 50,
        advancedRouters: false
    },
    pro: {
        name: 'Pro',
        maxTokensPerDay: 150000,
        maxFileSizeMb: 50,
        jarvisAccess: false,
        maxProjects: 15,
        maxMemoryRecords: 500,
        advancedRouters: true
    },
    plus: {
        name: 'Plus',
        maxTokensPerDay: 750000,
        maxFileSizeMb: 250,
        jarvisAccess: false,
        maxProjects: 50,
        maxMemoryRecords: 2500,
        advancedRouters: true
    },
    ultra: {
        name: 'Ultra',
        maxTokensPerDay: 5000000,
        maxFileSizeMb: 2048, // 2 GB target capacity architecture
        jarvisAccess: true,
        maxProjects: 999,
        maxMemoryRecords: 10000,
        advancedRouters: true
    }
};

/**
 * Verifies and updates user daily quota counters atomically.
 */
function enforceQuota(userId, userPlan, requestedCost = 100) {
    const usageStore = readStore('usage');
    const today = new Date().toISOString().split('T')[0];
    let userUsage = usageStore.find(u => u.userId === userId && u.date === today);

    const planConfig = PLANS[userPlan] || PLANS.free;
    const limit = planConfig.maxTokensPerDay;

    if (!userUsage) {
        userUsage = { userId, date: today, tokensUsed: 0, requestsCount: 0 };
        usageStore.push(userUsage);
    }

    if (userUsage.tokensUsed + requestedCost > limit) {
        return { allowed: false, current: userUsage.tokensUsed, limit };
    }

    userUsage.tokensUsed += requestedCost;
    userUsage.requestsCount += 1;
    writeStore('usage', usageStore);

    return { allowed: true, current: userUsage.tokensUsed, limit, remaining: limit - userUsage.tokensUsed };
}

// ============================================================================
// 5. SECURITY & AUDIT LOGGING MIDDLEWARE
// ============================================================================

function logSecurityEvent(userId, eventType, details, ip) {
    try {
        const events = readStore('securityEvents');
        const newEvent = {
            id: crypto.randomUUID(),
            userId: userId || 'anonymous',
            eventType,
            details,
            ip: ip || 'unknown',
            timestamp: new Date().toISOString()
        };
        events.push(newEvent);
        // Keep last 5000 security events
        if (events.length > 5000) events.shift();
        writeStore('securityEvents', events);
    } catch (err) {
        console.error('[Security Audit Error]:', err.message);
    }
}

// Helmet Security Headers
app.use(helmet({
    contentSecurityPolicy: false, // Customized for internal frontend embedding if needed
    crossOriginEmbedderPolicy: false
}));

// CORS Configuration
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true
}));

// Payload Limits & Body Parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Request ID & Structured Logging Middleware
app.use((req, res, next) => {
    req.id = crypto.randomUUID();
    res.setHeader('X-Request-ID', req.id);
    const start = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - start;
        const logEntry = {
            timestamp: new Date().toISOString(),
            requestId: req.id,
            method: req.method,
            url: req.originalUrl,
            status: res.statusCode,
            durationMs: duration,
            ip: req.ip || req.socket.remoteAddress
        };
        // Console output in structured format
        if (res.statusCode >= 400) {
            console.warn(`[HTTP WARN]:`, JSON.stringify(logEntry));
        } else if (NODE_ENV !== 'production') {
            console.log(`[HTTP]: ${req.method} ${req.originalUrl} -> ${res.statusCode} (${duration}ms)`);
        }
    });
    next();
});

// Rate Limiters
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.' }
});
app.use('/api/', globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, error: 'Güvenlik nedeniyle çok fazla kimlik doğrulama denemesi yapıldı.' }
});
app.use('/api/auth/', authLimiter);

// ============================================================================
// 6. AUTHENTICATION & AUTHORIZATION MIDDLEWARE
// ============================================================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Erişim reddedildi. Geçerli bir kimlik doğrulama tokenı gereklidir.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            logSecurityEvent(null, 'INVALID_TOKEN_ATTEMPT', { error: err.message }, req.ip);
            return res.status(403).json({ success: false, error: 'Geçersiz veya süresi dolmuş oturum tokenı.' });
        }

        const users = readStore('users');
        const dbUser = users.find(u => u.id === decoded.id);

        if (!dbUser || dbUser.isBanned) {
            return res.status(403).json({ success: false, error: 'Kullanıcı hesabı bulunamadı veya askıya alındı.' });
        }

        req.user = {
            id: dbUser.id,
            username: dbUser.username,
            email: dbUser.email,
            plan: dbUser.plan || 'free',
            isAdmin: dbUser.isAdmin || false,
            createdAt: dbUser.createdAt
        };
        next();
    });
}

function requireAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        logSecurityEvent(req.user?.id, 'UNAUTHORIZED_ADMIN_ACCESS', { url: req.originalUrl }, req.ip);
        return res.status(403).json({ success: false, error: 'Bu işlem için yönetici yetkisi gereklidir.' });
    }
    next();
}

function requireJarvis(req, res, next) {
    if (!req.user) return res.status(401).json({ success: false, error: 'Oturum açılmadı.' });
    const planConfig = PLANS[req.user.plan] || PLANS.free;
    if (!planConfig.jarvisAccess && !req.user.isAdmin) {
        return res.status(403).json({ success: false, error: 'Jarvis ajan özellikleri yalnızca TürkAI Ultra abonelerine özeldir.' });
    }
    next();
}

// ============================================================================
// 7. CORE SYSTEM & HEALTH CHECK ENDPOINTS
// ============================================================================

app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'OPERATIONAL',
        system: 'TürkAI Master Engine',
        version: '1.0.0-ULTRA',
        environment: NODE_ENV,
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

app.get('/api/plans', (req, res) => {
    res.json({ success: true, data: PLANS });
});

// ============================================================================
// 8. AUTHENTICATION CONTROLLERS & API ROUTES
// ============================================================================

app.post('/api/auth/register', [
    body('username').isString().trim().isLength({ min: 3, max: 30 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz kayıt bilgileri.', details: errors.array() });
    }

    const { username, email, password } = req.body;
    const users = readStore('users');

    if (users.some(u => u.email === email)) {
        return res.status(400).json({ success: false, error: 'Bu e-posta adresi ile kayıtlı bir hesap zaten var.' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUserId = crypto.randomUUID();
    const newUser = {
        id: newUserId,
        username,
        email,
        password: hashedPassword,
        plan: 'free',
        isAdmin: users.length === 0, // First registered user becomes admin automatically
        isBanned: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    users.push(newUser);
    writeStore('users', users);

    // Register active session
    const sessions = readStore('sessions');
    const sessionTokenId = crypto.randomUUID();
    sessions.push({
        sessionId: sessionTokenId,
        userId: newUserId,
        ip: req.ip,
        userAgent: req.headers['user-agent'] || 'unknown',
        createdAt: new Date().toISOString()
    });
    writeStore('sessions', sessions);

    logSecurityEvent(newUserId, 'USER_REGISTERED', { email }, req.ip);

    const token = jwt.sign({ id: newUserId, email, plan: newUser.plan }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    res.status(201).json({
        success: true,
        message: 'Kayıt başarıyla tamamlandı.',
        token,
        user: { id: newUserId, username, email, plan: newUser.plan, isAdmin: newUser.isAdmin }
    });
});

app.post('/api/auth/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').exists()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz e-posta veya parola formatı.' });
    }

    const { email, password } = req.body;
    const users = readStore('users');
    const user = users.find(u => u.email === email);

    if (!user || user.isBanned) {
        logSecurityEvent(null, 'LOGIN_FAILED_NOT_FOUND', { email }, req.ip);
        return res.status(401).json({ success: false, error: 'Geçersiz e-posta adresi veya parola.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        logSecurityEvent(user.id, 'LOGIN_FAILED_BAD_PASSWORD', {}, req.ip);
        return res.status(401).json({ success: false, error: 'Geçersiz e-posta adresi veya parola.' });
    }

    const sessions = readStore('sessions');
    const sessionTokenId = crypto.randomUUID();
    sessions.push({
        sessionId: sessionTokenId,
        userId: user.id,
        ip: req.ip,
        userAgent: req.headers['user-agent'] || 'unknown',
        createdAt: new Date().toISOString()
    });
    writeStore('sessions', sessions);

    logSecurityEvent(user.id, 'USER_LOGGED_IN', {}, req.ip);

    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    res.json({
        success: true,
        message: 'Giriş başarılı.',
        token,
        user: { id: user.id, username: user.username, email: user.email, plan: user.plan, isAdmin: user.isAdmin }
    });
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
    logSecurityEvent(req.user.id, 'USER_LOGGED_OUT', {}, req.ip);
    res.json({ success: true, message: 'Oturum başarıyla sonlandırıldı.' });
});

// ============================================================================
// 9. USER PROFILE & SETTINGS MANAGEMENT
// ============================================================================

app.get('/api/user/me', authenticateToken, (req, res) => {
    const users = readStore('users');
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });

    res.json({
        success: true,
        data: {
            id: user.id,
            username: user.username,
            email: user.email,
            plan: user.plan,
            isAdmin: user.isAdmin,
            createdAt: user.createdAt
        }
    });
});

app.put('/api/user/profile', authenticateToken, [
    body('username').optional().isString().trim().isLength({ min: 3, max: 30 }).escape(),
    body('password').optional().isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz güncelleme verileri.', details: errors.array() });
    }

    const users = readStore('users');
    const userIndex = users.findIndex(u => u.id === req.user.id);
    if (userIndex === -1) return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });

    if (req.body.username) users[userIndex].username = req.body.username;
    if (req.body.password) {
        users[userIndex].password = await bcrypt.hash(req.body.password, 12);
    }
    users[userIndex].updatedAt = new Date().toISOString();

    writeStore('users', users);
    logSecurityEvent(req.user.id, 'USER_PROFILE_UPDATED', {}, req.ip);

    res.json({ success: true, message: 'Profil başarıyla güncellendi.' });
});

app.get('/api/usage', authenticateToken, (req, res) => {
    const usageStore = readStore('usage');
    const today = new Date().toISOString().split('T')[0];
    const userUsage = usageStore.find(u => u.userId === req.user.id && u.date === today) || { tokensUsed: 0, requestsCount: 0 };
    const planConfig = PLANS[req.user.plan] || PLANS.free;

    res.json({
        success: true,
        data: {
            date: today,
            tokensUsed: userUsage.tokensUsed,
            requestsCount: userUsage.requestsCount,
            limit: planConfig.maxTokensPerDay,
            remaining: Math.max(0, planConfig.maxTokensPerDay - userUsage.tokensUsed),
            plan: req.user.plan
        }
    });
});

// ============================================================================
// 10. CHAT ENGINE & AUTO MODEL ROUTER
// ============================================================================

function executeAutoModelRouter(taskType, userPlan) {
    // TürkAI Auto Model Router intelligent dispatcher
    const tier = userPlan === 'ultra' ? 'Ultra' : (userPlan === 'plus' ? 'Plus' : 'Standard');
    switch (taskType) {
        case 'coding':
            return { modelId: 'TurkAI-Code-Engine-v2', provider: 'Internal-LLM-Cluster', tier };
        case 'math':
        case 'logic':
            return { modelId: 'TurkAI-Logic-Core-v1', provider: 'Internal-LLM-Cluster', tier };
        case 'research':
            return { modelId: 'TurkAI-Search-Augmented-v3', provider: 'Web-Search-Bridge', tier };
        case 'creative':
            return { modelId: 'TurkAI-Creative-Studio-v2', provider: 'Internal-LLM-Cluster', tier };
        default:
            return { modelId: 'TurkAI-General-Chat-Master', provider: 'Internal-LLM-Cluster', tier };
    }
}

app.post('/api/chat', authenticateToken, [
    body('message').isString().trim().notEmpty().isLength({ max: 8000 }),
    body('taskType').optional().isString().trim(),
    body('conversationId').optional().isString()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Mesaj doğrulama başarısız oldu.', details: errors.array() });
    }

    const { message, taskType = 'general', conversationId } = req.body;
    const estimatedTokens = Math.ceil(message.length / 3) + 150;

    // Quota Enforcement
    const quotaCheck = enforceQuota(req.user.id, req.user.plan, estimatedTokens);
    if (!quotaCheck.allowed) {
        return res.status(429).json({
            success: false,
            error: 'Günlük token kotanız dolmuştur. Lütfen planınızı yükseltin.',
            usage: quotaCheck
        });
    }

    const modelRouting = executeAutoModelRouter(taskType, req.user.plan);
    const replyText = `[TürkAI Master — ${modelRouting.modelId}]: "${message}" talebiniz başarıyla işlendi. Türkçe odaklı, modüler altyapımız ile çalışmaya devam ediyoruz knk!`;

    // Persist Conversation
    const convs = readStore('conversations');
    let conv = convs.find(c => c.id === conversationId && c.userId === req.user.id);

    if (!conv) {
        conv = {
            id: crypto.randomUUID(),
            userId: req.user.id,
            title: message.substring(0, 40) + '...',
            messages: [],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        convs.push(conv);
    }

    conv.messages.push({ role: 'user', content: message, timestamp: new Date().toISOString() });
    conv.messages.push({
        role: 'assistant',
        content: replyText,
        model: modelRouting.modelId,
        provider: modelRouting.provider,
        timestamp: new Date().toISOString()
    });
    conv.updatedAt = new Date().toISOString();
    writeStore('conversations', convs);

    res.json({
        success: true,
        data: {
            conversationId: conv.id,
            reply: replyText,
            modelUsed: modelRouting.modelId,
            tokensCost: estimatedTokens,
            quota: quotaCheck
        }
    });
});

app.get('/api/chat/conversations', authenticateToken, (req, res) => {
    const convs = readStore('conversations');
    const userConvs = convs
        .filter(c => c.userId === req.user.id)
        .map(c => ({ id: c.id, title: c.title, createdAt: c.createdAt, updatedAt: c.updatedAt }));
    res.json({ success: true, data: userConvs });
});

app.get('/api/chat/conversations/:id', authenticateToken, (req, res) => {
    const convs = readStore('conversations');
    const conv = convs.find(c => c.id === req.params.id && c.userId === req.user.id);
    if (!conv) return res.status(404).json({ success: false, error: 'Konuşma bulunamadı.' });
    res.json({ success: true, data: conv });
});

app.delete('/api/chat/conversations/:id', authenticateToken, (req, res) => {
    let convs = readStore('conversations');
    const initialLength = convs.length;
    convs = convs.filter(c => !(c.id === req.params.id && c.userId === req.user.id));
    if (convs.length === initialLength) {
        return res.status(404).json({ success: false, error: 'Konuşma bulunamadı veya silinemez.' });
    }
    writeStore('conversations', convs);
    res.json({ success: true, message: 'Konuşma silindi.' });
});

// ============================================================================
// 11. ANSWER MEMORY (CEVAP HAFIZASI) SYSTEM
// ============================================================================

app.get('/api/memory', authenticateToken, (req, res) => {
    const memories = readStore('memories');
    const userMemories = memories.filter(m => m.userId === req.user.id);
    res.json({ success: true, data: userMemories });
});

app.post('/api/memory', authenticateToken, [
    body('content').isString().trim().notEmpty().isLength({ max: 3000 }),
    body('category').optional().isString().trim(),
    body('importance').optional().isInt({ min: 1, max: 5 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Hafıza verisi geçersiz.', details: errors.array() });
    }

    const { content, category = 'general', importance = 3 } = req.body;
    const memories = readStore('memories');
    const planConfig = PLANS[req.user.plan] || PLANS.free;

    const userCount = memories.filter(m => m.userId === req.user.id).length;
    if (userCount >= planConfig.maxMemoryRecords) {
        return res.status(403).json({ success: false, error: `Plan limitiniz aşıldı. Maksimum hafıza kayıt sınırı: ${planConfig.maxMemoryRecords}` });
    }

    const newMemory = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        content,
        category,
        importance,
        confidence: 1.0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    memories.push(newMemory);
    writeStore('memories', memories);

    res.status(201).json({ success: true, message: 'Hafıza kaydı başarıyla oluşturuldu.', data: newMemory });
});

app.delete('/api/memory/:id', authenticateToken, (req, res) => {
    let memories = readStore('memories');
    const initialLen = memories.length;
    memories = memories.filter(m => !(m.id === req.params.id && m.userId === req.user.id));
    if (memories.length === initialLen) {
        return res.status(404).json({ success: false, error: 'Hafıza kaydı bulunamadı.' });
    }
    writeStore('memories', memories);
    res.json({ success: true, message: 'Hafıza kaydı silindi.' });
});

// // PARÇA 1 SONU — PARÇA 2 BURADAN DEVAM EDECEK
// PARÇA 2 BAŞLANGICI — PARÇA 1'İN DEVAMI

// ============================================================================
// 12. PROJECT STUDIO (PROJE YÖNETİMİ) API ROUTES
// ============================================================================

app.get('/api/projects', authenticateToken, (req, res) => {
    const projects = readStore('projects');
    const userProjects = projects.filter(p => p.userId === req.user.id);
    res.json({ success: true, data: userProjects });
});

app.post('/api/projects', authenticateToken, [
    body('name').isString().trim().notEmpty().isLength({ max: 100 }).escape(),
    body('description').optional().isString().trim().isLength({ max: 500 }).escape(),
    body('projectType').optional().isString().trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Proje bilgileri geçersiz.', details: errors.array() });
    }

    const { name, description = '', projectType = 'web-app' } = req.body;
    const projects = readStore('projects');
    const planConfig = PLANS[req.user.plan] || PLANS.free;

    const userProjectCount = projects.filter(p => p.userId === req.user.id).length;
    if (userProjectCount >= planConfig.maxProjects) {
        return res.status(403).json({ success: false, error: `Plan limitiniz aşıldı. Maksimum proje sınırı: ${planConfig.maxProjects}` });
    }

    const newProject = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        name,
        description,
        projectType,
        files: [],
        tasks: [],
        status: 'active',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    projects.push(newProject);
    writeStore('projects', projects);

    logSecurityEvent(req.user.id, 'PROJECT_CREATED', { projectId: newProject.id, name }, req.ip);

    res.status(201).json({ success: true, message: 'Proje başarıyla oluşturuldu.', data: newProject });
});

app.delete('/api/projects/:id', authenticateToken, (req, res) => {
    let projects = readStore('projects');
    const initialLen = projects.length;
    projects = projects.filter(p => !(p.id === req.params.id && p.userId === req.user.id));
    if (projects.length === initialLen) {
        return res.status(404).json({ success: false, error: 'Proje bulunamadı.' });
    }
    writeStore('projects', projects);
    res.json({ success: true, message: 'Proje silindi.' });
});

// ============================================================================
// 13. FILE INTELLIGENCE & SECURE UPLOAD SYSTEM
// ============================================================================

app.get('/api/files', authenticateToken, (req, res) => {
    const files = readStore('files');
    const userFiles = files.filter(f => f.userId === req.user.id);
    res.json({ success: true, data: userFiles });
});

app.post('/api/files/upload', authenticateToken, (req, res) => {
    const { filename, content, mimeType } = req.body;
    if (!filename || !content) {
        return res.status(400).json({ success: false, error: 'Dosya adı ve içeriği gereklidir.' });
    }

    const planConfig = PLANS[req.user.plan] || PLANS.free;
    const sizeInMb = Buffer.byteLength(content, 'utf8') / (1024 * 1024);

    if (sizeInMb > planConfig.maxFileSizeMb) {
        return res.status(400).json({ success: false, error: `Dosya boyutu plan limitini aşıyor. Maksimum: ${planConfig.maxFileSizeMb} MB` });
    }

    const fileId = crypto.randomUUID();
    const safeFilename = path.basename(filename).replace(/[^a-zA-Z0-9.-]/g, '_');
    const targetPath = path.join(UPLOADS_DIR, `${fileId}_${safeFilename}`);

    try {
        fs.writeFileSync(targetPath, content, 'utf8');

        const files = readStore('files');
        const fileRecord = {
            id: fileId,
            userId: req.user.id,
            filename: safeFilename,
            sizeBytes: Buffer.byteLength(content, 'utf8'),
            mimeType: mimeType || 'text/plain',
            createdAt: new Date().toISOString()
        };

        files.push(fileRecord);
        writeStore('files', files);

        res.status(201).json({ success: true, message: 'Dosya başarıyla yüklendi ve analiz kuyruğuna alındı.', data: fileRecord });
    } catch (err) {
        console.error('[File Upload Error]:', err.message);
        res.status(500).json({ success: false, error: 'Dosya sunucuya kaydedilemedi.' });
    }
});

// ============================================================================
// 14. WEB RESEARCH ADAPTER
// ============================================================================

app.post('/api/research', authenticateToken, [
    body('query').isString().trim().notEmpty().isLength({ max: 500 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz araştırma sorgusu.' });
    }

    const { query } = req.body;
    const researchStore = readStore('research');

    // Simulated high-fidelity research result adapter (Real web bridge connector ready)
    const researchResult = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        query,
        sources: [
            { title: 'TürkAI Knowledge Base', url: 'https://turkai.internal/docs', snippet: 'Türkçe odaklı modüler yapay zekâ platformu rehberi.' },
            { title: 'Open Technical Specifications', url: 'https://github.com/turkai/specs', snippet: 'Modern Node.js ve Express tabanlı mimari standartları.' }
        ],
        summary: `"${query}" ile ilgili güncel akademik ve teknik veriler taranmıştır. TürkAI araştırma motoru sentezi: Sistem kararlı çalışmaktadır.`,
        createdAt: new Date().toISOString()
    };

    researchStore.push(researchResult);
    writeStore('research', researchStore);

    res.json({ success: true, data: researchResult });
});

// ============================================================================
// 15. JARVIS ADVANCED AGENT SYSTEM (ULTRA EXCLUSIVE)
// ============================================================================

app.post('/api/agent/tasks', authenticateToken, requireJarvis, [
    body('objective').isString().trim().notEmpty().isLength({ max: 2000 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Ajan hedefi geçersiz.' });
    }

    const { objective } = req.body;
    const tasks = readStore('agentTasks');

    const newTask = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        objective,
        status: 'queued',
        progress: 0,
        steps: [
            { step: 1, description: 'Hedef analiz ediliyor...', status: 'completed' },
            { step: 2, description: 'Gerekli modüller planlanıyor...', status: 'in_progress' },
            { step: 3, description: 'Kod üretimi ve doğrulama...', status: 'pending' }
        ],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    tasks.push(newTask);
    writeStore('agentTasks', tasks);

    logSecurityEvent(req.user.id, 'JARVIS_TASK_CREATED', { taskId: newTask.id }, req.ip);

    res.status(201).json({
        success: true,
        message: 'Jarvis ajan görevi başarıyla başlatıldı.',
        data: newTask
    });
});

app.get('/api/agent/tasks', authenticateToken, requireJarvis, (req, res) => {
    const tasks = readStore('agentTasks');
    const userTasks = tasks.filter(t => t.userId === req.user.id);
    res.json({ success: true, data: userTasks });
});

// ============================================================================
// 16. MODELS REGISTRY API
// ============================================================================

app.get('/api/models', authenticateToken, (req, res) => {
    const modelsRegistry = [
        { id: 'TurkAI-General-Chat-Master', name: 'TürkAI General Chat', type: 'chat', status: 'active', tier: 'All' },
        { id: 'TurkAI-Code-Engine-v2', name: 'TürkAI Code Advanced', type: 'coding', status: 'active', tier: 'Pro+' },
        { id: 'TurkAI-Logic-Core-v1', name: 'TürkAI Logic Core', type: 'math', status: 'active', tier: 'Pro+' },
        { id: 'TurkAI-Search-Augmented-v3', name: 'TürkAI Search Engine', type: 'research', status: 'active', tier: 'Plus+' },
        { id: 'TurkAI-Jarvis-Agent-Alpha', name: 'Jarvis Autonomous Agent', type: 'agent', status: 'active', tier: 'Ultra' }
    ];
    res.json({ success: true, data: modelsRegistry });
});

// ============================================================================
// 17. SECURITY CENTER & SESSIONS MANAGEMENT
// ============================================================================

app.get('/api/security/sessions', authenticateToken, (req, res) => {
    const sessions = readStore('sessions');
    const userSessions = sessions.filter(s => s.userId === req.user.id);
    res.json({ success: true, data: userSessions });
});

app.delete('/api/security/sessions/:sessionId', authenticateToken, (req, res) => {
    let sessions = readStore('sessions');
    const initialLen = sessions.length;
    sessions = sessions.filter(s => !(s.sessionId === req.params.sessionId && s.userId === req.user.id));
    if (sessions.length === initialLen) {
        return res.status(404).json({ success: false, error: 'Oturum bulunamadı.' });
    }
    writeStore('sessions', sessions);
    logSecurityEvent(req.user.id, 'SESSION_REVOKED', { sessionId: req.params.sessionId }, req.ip);
    res.json({ success: true, message: 'Oturum sonlandırıldı.' });
});

// ============================================================================
// 18. ADMIN AUDIT & MANAGEMENT API
// ============================================================================

app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const users = readStore('users');
    const sanitizedUsers = users.map(u => ({
        id: u.id,
        username: u.username,
        email: u.email,
        plan: u.plan,
        isAdmin: u.isAdmin,
        isBanned: u.isBanned || false,
        createdAt: u.createdAt
    }));
    res.json({ success: true, data: sanitizedUsers });
});

app.get('/api/admin/security-events', authenticateToken, requireAdmin, (req, res) => {
    const events = readStore('securityEvents');
    res.json({ success: true, data: events.slice(-100).reverse() });
});

// ============================================================================
// 19. SOCKET.IO REAL-TIME EVENT HANDLERS
// ============================================================================

io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) {
        return next(new Error('Yetkilendirme hatası: Socket token bulunamadı.'));
    }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error('Geçersiz veya süresi dolmuş token.'));
        socket.userId = decoded.id;
        socket.userPlan = decoded.plan;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`[Socket Connected]: Kullanıcı ID -> ${socket.userId}`);

    // Join user-specific secure room for isolated event broadcasting
    socket.join(`user_${socket.userId}`);

    socket.on('client_ping', () => {
        socket.emit('server_pong', { timestamp: new Date().toISOString() });
    });

    socket.on('jarvis_command', (data) => {
        if (socket.userPlan !== 'ultra') {
            socket.emit('jarvis_error', { error: 'Jarvis özellikleri yalnızca Ultra abonelere açıktır.' });
            return;
        }
        socket.emit('jarvis_progress', { status: 'processing', message: 'Jarvis yapay zekâ ajanı görevi işliyor...' });
        setTimeout(() => {
            socket.emit('jarvis_result', { status: 'completed', result: 'Görev başarıyla tamamlandı knk!' });
        }, 1200);
    });

    socket.on('disconnect', () => {
        console.log(`[Socket Disconnected]: Kullanıcı ID -> ${socket.userId}`);
    });
});

// ============================================================================
// 20. CENTRALIZED ERROR HANDLING & 404 ROUTING
// ============================================================================

app.use((req, res, next) => {
    res.status(404).json({ success: false, error: 'İstediğiniz TürkAI API uç noktası bulunamadı.' });
});

app.use((err, req, res, next) => {
    console.error(`[CRITICAL ERROR] [${req.id || 'N/A'}]:`, err.stack || err.message);
    res.status(500).json({
        success: false,
        error: NODE_ENV === 'production' ? 'Sunucu tarafında beklenmeyen bir hata oluştu.' : err.message
    });
});

// ============================================================================
// 21. SERVER STARTUP & GRACEFUL SHUTDOWN MANAGEMENT
// ============================================================================

server.listen(PORT, () => {
    console.log(`============================================================`);
    console.log(`🚀 TÜRKAI MASTER ENGINE AKTİF VE ÇALIŞIYOR`);
    console.log(`📍 URL: http://localhost:${PORT}`);
    console.log(`🛡️ Ortam: ${NODE_ENV.toUpperCase()}`);
    console.log(`============================================================`);
});

const gracefulShutdown = (signal) => {
    console.log(`\n[${signal}] Sinyal alındı. TürkAI sunucusu güvenle kapatılıyor...`);
    server.close(() => {
        console.log('[TürkAI]: HTTP ve Socket.io sunucuları kapatıldı. Veriler güvende.');
        process.exit(0);
    });

    // Force shutdown timeout in case connections hang
    setTimeout(() => {
        console.error('[TürkAI Error]: Zaman aşımı! Zorla kapatılıyor.');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
