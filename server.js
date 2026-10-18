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
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// --- 1. CONFIGURATION & ENVIRONMENT ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
    console.warn('[UYARI]: Üretim ortamında JWT_SECRET tanımlı değil! Rastgele anahtar üretildi.');
}

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST']
    }
});

// --- 2. DATA STORAGE SETUP (JSON FILE STORE) ---
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const dbFiles = {
    users: path.join(DATA_DIR, 'users.json'),
    conversations: path.join(DATA_DIR, 'conversations.json'),
    memories: path.join(DATA_DIR, 'memories.json'),
    projects: path.join(DATA_DIR, 'projects.json'),
    usage: path.join(DATA_DIR, 'usage.json'),
    sessions: path.join(DATA_DIR, 'sessions.json')
};

function readStore(storeName) {
    try {
        const filePath = dbFiles[storeName];
        if (!filePath || !fs.existsSync(filePath)) return [];
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error(`[DB Hata] ${storeName} okunamadı:`, err.message);
        return [];
    }
}

function writeStore(storeName, data) {
    try {
        const filePath = dbFiles[storeName];
        if (!filePath) return;
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
        console.error(`[DB Hata] ${storeName} yazılamadı:`, err.message);
    }
}

// Varsayılan dosyaları kontrol et / oluştur
Object.keys(dbFiles).forEach(name => {
    if (!fs.existsSync(dbFiles[name])) {
        writeStore(name, []);
    }
});

// --- 3. PLANS & QUOTAS DEFINITION ---
const PLANS = {
    free: { name: 'Free', maxTokensPerDay: 10000, maxFileSizeMb: 5, jarvisAccess: false },
    pro: { name: 'Pro', maxTokensPerDay: 100000, maxFileSizeMb: 50, jarvisAccess: false },
    plus: { name: 'Plus', maxTokensPerDay: 500000, maxFileSizeMb: 250, jarvisAccess: false },
    ultra: { name: 'Ultra', maxTokensPerDay: 2000000, maxFileSizeMb: 2048, jarvisAccess: true }
};

// --- 4. MIDDLEWARES (SECURITY, LOGGING, RATE LIMIT) ---
app.use(helmet());
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// İstek Kimliği (Request ID) ve Yapılandırılmış Günlükleme
app.use((req, res, next) => {
    req.id = crypto.randomUUID();
    res.setHeader('X-Request-ID', req.id);
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[${new Date().toISOString()}] [${req.id}] ${req.method} ${req.originalUrl} - Status: ${res.statusCode} - ${duration}ms`);
    });
    next();
});

// Hız Sınırlandırma (Rate Limiting)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Çok fazla istek gönderildi, lütfen daha sonra tekrar deneyin.' }
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, error: 'Çok fazla giriş denemesi yapıldı, lütfen bekleyin.' }
});
app.use('/api/auth/', authLimiter);

// Kimlik Doğrulama Middleware (JWT)
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, error: 'Erişim reddedildi. Token bulunamadı.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Geçersiz veya süresi dolmuş token.' });
        }
        // Kullanıcının güncel durumunu kontrol et
        const users = readStore('users');
        const dbUser = users.find(u => u.id === user.id);
        if (!dbUser) {
            return res.status(403).json({ success: false, error: 'Kullanıcı bulunamadı.' });
        }
        req.user = { id: dbUser.id, username: dbUser.username, email: dbUser.email, plan: dbUser.plan || 'free' };
        next();
    });
}

// Kota Kontrol Middleware
function checkQuota(req, res, next) {
    if (!req.user) return next();
    const usageStore = readStore('usage');
    const today = new Date().toISOString().split('T')[0];
    let userUsage = usageStore.find(u => u.userId === req.user.id && u.date === today);

    const planLimit = PLANS[req.user.plan]?.maxTokensPerDay || PLANS.free.maxTokensPerDay;

    if (!userUsage) {
        userUsage = { userId: req.user.id, date: today, tokensUsed: 0 };
        usageStore.push(userUsage);
        writeStore('usage', usageStore);
    }

    if (userUsage.tokensUsed >= planLimit) {
        return res.status(429).json({ success: false, error: 'Günlük kullanım kotanız doldu. Lütfen plan yükseltin.' });
    }

    req.userUsage = userUsage;
    next();
}

// --- 5. STANDART API YANIT FORMATI & ROUTES ---

// Health Check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'OK',
        service: 'TürkAI Master System',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// Plans
app.get('/api/plans', (req, res) => {
    res.json({ success: true, data: PLANS });
});

// --- AUTHENTICATION ROUTES ---
app.post('/api/auth/register', [
    body('username').isString().trim().isLength({ min: 3, max: 30 }),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz girdi verileri.', details: errors.array() });
    }

    const { username, email, password } = req.body;
    const users = readStore('users');

    if (users.some(u => u.email === email)) {
        return res.status(400).json({ success: false, error: 'Bu e-posta adresi zaten kullanımda.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: crypto.randomUUID(),
        username,
        email,
        password: hashedPassword,
        plan: 'free',
        createdAt: new Date().toISOString()
    };

    users.push(newUser);
    writeStore('users', users);

    // Oturum kaydı
    const sessions = readStore('sessions');
    sessions.push({ userId: newUser.id, ip: req.ip, createdAt: new Date().toISOString() });
    writeStore('sessions', sessions);

    const token = jwt.sign({ id: newUser.id, email: newUser.email, plan: newUser.plan }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
        success: true,
        message: 'Kayıt başarılı.',
        token,
        user: { id: newUser.id, username: newUser.username, email: newUser.email, plan: newUser.plan }
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

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ success: false, error: 'Geçersiz e-posta veya parola.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
        success: true,
        message: 'Giriş başarılı.',
        token,
        user: { id: user.id, username: user.username, email: user.email, plan: user.plan }
    });
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
    // JWT stateless olduğu için istemci tarafında token silinir. Ek oturum temizliği yapılabilir.
    res.json({ success: true, message: 'Çıkış başarılı.' });
});

// --- USER INFO ---
app.get('/api/user/me', authenticateToken, (req, res) => {
    const users = readStore('users');
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });

    res.json({
        success: true,
        data: { id: user.id, username: user.username, email: user.email, plan: user.plan, createdAt: user.createdAt }
    });
});

// --- USAGE ---
app.get('/api/usage', authenticateToken, (req, res) => {
    const usageStore = readStore('usage');
    const today = new Date().toISOString().split('T')[0];
    const userUsage = usageStore.find(u => u.userId === req.user.id && u.date === today) || { tokensUsed: 0 };
    const limit = PLANS[req.user.plan]?.maxTokensPerDay || PLANS.free.maxTokensPerDay;

    res.json({
        success: true,
        data: {
            date: today,
            tokensUsed: userUsage.tokensUsed,
            limit,
            remaining: Math.max(0, limit - userUsage.tokensUsed)
        }
    });
});

// --- CHAT & AUTO MODEL ROUTER ---
function routeModel(taskType) {
    // TürkAI Auto Model Router simülasyonu
    switch (taskType) {
        case 'coding': return 'TurkAI-Code-Advanced';
        case 'math': return 'TurkAI-Logic-Core';
        case 'research': return 'TurkAI-Search-Engine';
        default: return 'TurkAI-General-Chat';
    }
}

app.post('/api/chat', authenticateToken, checkQuota, [
    body('message').isString().trim().notEmpty().isLength({ max: 5000 }),
    body('taskType').optional().isString()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz mesaj içeriği.' });
    }

    const { message, taskType = 'general', conversationId } = req.body;
    const selectedModel = routeModel(taskType);

    // Yanıt simülasyonu / Üretim
    const replyText = `[TürkAI - ${selectedModel}]: Mesajınız alındı: "${message}". Sistem yerel motor üzerinden güvenle yanıtlıyor knk!`;
    const tokensCost = message.length + replyText.length;

    // Kullanım kotasını güncelle
    const usageStore = readStore('usage');
    const today = new Date().toISOString().split('T')[0];
    const usageIndex = usageStore.findIndex(u => u.userId === req.user.id && u.date === today);
    if (usageIndex !== -1) {
        usageStore[usageIndex].tokensUsed += tokensCost;
        writeStore('usage', usageStore);
    }

    // Konuşma geçmişini kaydet
    const convs = readStore('conversations');
    let conv = convs.find(c => c.id === conversationId && c.userId === req.user.id);
    if (!conv) {
        conv = { id: crypto.randomUUID(), userId: req.user.id, title: message.substring(0, 30), messages: [], createdAt: new Date().toISOString() };
        convs.push(conv);
    }
    conv.messages.push({ role: 'user', content: message, timestamp: new Date().toISOString() });
    conv.messages.push({ role: 'assistant', content: replyText, model: selectedModel, timestamp: new Date().toISOString() });
    writeStore('conversations', convs);

    res.json({
        success: true,
        data: {
            conversationId: conv.id,
            reply: replyText,
            model: selectedModel,
            tokensCost
        }
    });
});

app.get('/api/chat/conversations', authenticateToken, (req, res) => {
    const convs = readStore('conversations');
    const userConvs = convs.filter(c => c.userId === req.user.id).map(c => ({ id: c.id, title: c.title, createdAt: c.createdAt }));
    res.json({ success: true, data: userConvs });
});

// --- MEMORY (CEVAP HAFIZASI) ---
app.get('/api/memory', authenticateToken, (req, res) => {
    const memories = readStore('memories');
    const userMemories = memories.filter(m => m.userId === req.user.id);
    res.json({ success: true, data: userMemories });
});

app.post('/api/memory', authenticateToken, [
    body('content').isString().trim().notEmpty().isLength({ max: 2000 }),
    body('category').optional().isString(),
    body('importance').optional().isInt({ min: 1, max: 5 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz hafıza verisi.' });
    }

    const { content, category = 'general', importance = 3 } = req.body;
    const memories = readStore('memories');

    const newMemory = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        content,
        category,
        importance,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    memories.push(newMemory);
    writeStore('memories', memories);

    res.status(201).json({ success: true, message: 'Hafıza kaydedildi.', data: newMemory });
});

// --- PROJECTS ---
app.get('/api/projects', authenticateToken, (req, res) => {
    const projects = readStore('projects');
    const userProjects = projects.filter(p => p.userId === req.user.id);
    res.json({ success: true, data: userProjects });
});

app.post('/api/projects', authenticateToken, [
    body('name').isString().trim().notEmpty().isLength({ max: 100 }),
    body('description').optional().isString().isLength({ max: 500 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Geçersiz proje bilgileri.' });
    }

    const { name, description = '' } = req.body;
    const projects = readStore('projects');

    const newProject = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        name,
        description,
        files: [],
        createdAt: new Date().toISOString()
    };

    projects.push(newProject);
    writeStore('projects', projects);

    res.status(201).json({ success: true, message: 'Proje oluşturuldu.', data: newProject });
});

// --- MODELS ---
app.get('/api/models', authenticateToken, (req, res) => {
    const models = [
        { id: 'TurkAI-General-Chat', name: 'TürkAI General Chat', type: 'chat', description: 'Günlük sohbet ve genel amaçlı model.' },
        { id: 'TurkAI-Code-Advanced', name: 'TürkAI Code Advanced', type: 'coding', description: 'Gelişmiş yazılım geliştirme ve hata ayıklama.' },
        { id: 'TurkAI-Logic-Core', name: 'TürkAI Logic Core', type: 'math', description: 'Matematik ve mantık işlemleri.' },
        { id: 'TurkAI-Search-Engine', name: 'TürkAI Search Engine', type: 'research', description: 'Web araştırması ve bilgi doğrulama.' }
    ];
    res.json({ success: true, data: models });
});

// --- SECURITY SESSIONS ---
app.get('/api/security/sessions', authenticateToken, (req, res) => {
    const sessions = readStore('sessions');
    const userSessions = sessions.filter(s => s.userId === req.user.id);
    res.json({ success: true, data: userSessions });
});

// --- 6. SOCKET.IO CONNECTION HANDLING ---
io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) {
        return next(new Error('Yetkilendirme hatası: Socket token bulunamadı.'));
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return next(new Error('Geçersiz token.'));
        socket.user = user;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`[Socket] Kullanıcı bağlandı: ${socket.user.id}`);

    socket.on('join_room', (room) => {
        socket.join(room);
        socket.emit('joined', { room });
    });

    socket.on('jarvis_task', (data) => {
        // Jarvis Ajan Görev Simülasyonu
        socket.emit('jarvis_progress', { status: 'processing', message: 'Jarvis görevi analiz ediyor...' });
        setTimeout(() => {
            socket.emit('jarvis_result', { status: 'completed', result: 'Görev başarıyla tamamlandı knk!' });
        }, 1500);
    });

    socket.on('disconnect', () => {
        console.log(`[Socket] Kullanıcı ayrıldı: ${socket.user.id}`);
    });
});

// --- 7. 404 & CENTRALIZED ERROR HANDLER ---
app.use((req, res, next) => {
    res.status(404).json({ success: false, error: 'Aradığınız API uç noktası bulunamadı.' });
});

app.use((err, req, res, next) => {
    console.error(`[Kritik Hata] [${req.id || 'N/A'}]:`, err.stack || err.message);
    res.status(500).json({
        success: false,
        error: process.env.NODE_ENV === 'production' ? 'Sunucu tarafında beklenmeyen bir hata oluştu.' : err.message
    });
});

// --- 8. SERVER STARTUP & GRACEFUL SHUTDOWN ---
server.listen(PORT, () => {
    console.log(`[TürkAI Master Server]: http://localhost:${PORT} adresinde çalışıyor.`);
});

const gracefulShutdown = (signal) => {
    console.log(`\n[${signal}] Sinyal alındı. Sunucu güvenle kapatılıyor...`);
    server.close(() => {
        console.log('[TürkAI]: HTTP sunucusu kapatıldı.');
        process.exit(0);
    });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
