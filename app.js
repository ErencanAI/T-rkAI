// ============================================================================
// TÜRKAI MASTER SYSTEM — FRONTEND CORE APP.JS (PART 1 & 2 COMBINED)
// ============================================================================

let state = {
    token: localStorage.getItem('turkai_token') || null,
    user: JSON.parse(localStorage.getItem('turkai_user') || 'null'),
    currentView: 'chat',
    currentConversationId: null,
    conversations: [],
    socket: null
};

const API_BASE = '/api';

document.addEventListener('DOMContentLoaded', () => {
    if (!state.token) {
        document.getElementById('auth-modal')?.classList.remove('hidden');
    } else {
        initApp();
    }
});

// --- AUTHENTICATION TABS & SUBMIT ---
function switchAuthTab(tab) {
    const isLogin = tab === 'login';
    document.getElementById('username-field')?.classList.toggle('hidden', isLogin);
    
    const loginBtn = document.getElementById('tab-login-btn');
    const registerBtn = document.getElementById('tab-register-btn');
    const submitBtn = document.getElementById('auth-submit-btn');

    if (loginBtn && registerBtn && submitBtn) {
        loginBtn.className = isLogin ? 'flex-1 pb-2 font-medium text-brand-purple border-b-2 border-brand-purple transition' : 'flex-1 pb-2 font-medium text-slate-400 hover:text-slate-200 transition';
        registerBtn.className = !isLogin ? 'flex-1 pb-2 font-medium text-brand-purple border-b-2 border-brand-purple transition' : 'flex-1 pb-2 font-medium text-slate-400 hover:text-slate-200 transition';
        submitBtn.textContent = isLogin ? 'Giriş Yap' : 'Kayıt Ol';
    }
}

async function handleAuthSubmit(event) {
    event.preventDefault();
    const email = document.getElementById('auth-email').value;
    const password = document.getElementById('auth-password').value;
    const usernameElem = document.getElementById('auth-username');
    const username = usernameElem ? usernameElem.value : '';
    const isRegister = usernameElem && !usernameElem.closest('#username-field').classList.contains('hidden');

    const endpoint = isRegister ? '/auth/register' : '/auth/login';
    const payload = isRegister ? { username, email, password } : { email, password };

    try {
        const res = await fetch(API_BASE + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error || 'İşlem başarısız.');

        state.token = data.token;
        state.user = data.user;
        localStorage.setItem('turkai_token', data.token);
        localStorage.setItem('turkai_user', JSON.stringify(data.user));

        document.getElementById('auth-modal')?.classList.add('hidden');
        initApp();
        showToast('Başarıyla giriş yapıldı!');
    } catch (err) {
        const errDiv = document.getElementById('auth-error');
        if (errDiv) {
            errDiv.textContent = err.message;
            errDiv.classList.remove('hidden');
        }
    }
}

function logout() {
    localStorage.removeItem('turkai_token');
    localStorage.removeItem('turkai_user');
    location.reload();
}

function initApp() {
    if (state.user) {
        const usernameEl = document.getElementById('sidebar-username');
        const userplanEl = document.getElementById('sidebar-userplan');
        const avatarEl = document.getElementById('user-avatar-initial');

        if (usernameEl) usernameEl.textContent = state.user.username;
        if (userplanEl) userplanEl.textContent = `${state.user.plan} Plan`;
        if (avatarEl) avatarEl.textContent = state.user.username.charAt(0).toUpperCase();
    }
    initSocket();
    loadConversations();
    loadPlans();
}

function initSocket() {
    state.socket = io({
        auth: { token: state.token }
    });
    state.socket.on('connect', () => console.log('[Socket]: Bağlandı.'));
    state.socket.on('connect_error', (err) => console.error('[Socket Hata]:', err.message));
}

function switchView(viewName) {
    state.currentView = viewName;
    document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
    document.getElementById(`view-${viewName}`)?.classList.remove('hidden');

    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('data-view') === viewName) {
            link.className = 'nav-link flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-slate-200 bg-dark-600 border border-dark-400 transition';
        } else {
            link.className = 'nav-link flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-dark-500 transition';
        }
    });

    const titles = {
        chat: 'Sohbet Asistanı',
        memory: 'Cevap Hafızası',
        projects: 'Proje Stüdyosu',
        files: 'Dosya İstihbaratı',
        research: 'Web Araştırma Motoru',
        agent: 'Jarvis Gelişmiş Ajanı',
        plans: 'Abonelik Planları',
        security: 'Güvenlik Merkezi'
    };
    
    const titleEl = document.getElementById('current-view-title');
    if (titleEl) titleEl.textContent = titles[viewName] || 'TürkAI';

    if (viewName === 'memory') loadMemories();
    if (viewName === 'projects') loadProjects();
    if (viewName === 'files') loadFiles();
    if (viewName === 'security') loadSessions();
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `glass-panel px-4 py-3 rounded-xl text-xs font-medium text-white shadow-xl border ${type === 'success' ? 'border-emerald-500/40 bg-emerald-950/40' : 'border-red-500/40 bg-red-950/40'} pointer-events-auto transition animate-bounce`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar?.classList.toggle('-translate-x-full');
}

// --- API HELPER ---
async function apiCall(endpoint, method = 'GET', body = null) {
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`
    };
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    try {
        const res = await fetch(API_BASE + endpoint, options);
        const data = await res.json();
        if (res.status === 401) {
            showToast('Oturum süresi doldu. Lütfen tekrar giriş yapın.', 'error');
            logout();
            return null;
        }
        return data;
    } catch (err) {
        console.error('[API Hatası]:', err);
        showToast('Sunucu bağlantı hatası oluştu.', 'error');
        return null;
    }
}

// --- SOHBET SİSTEMİ ---
async function loadConversations() {
    const data = await apiCall('/chat/conversations');
    if (!data || !data.success) return;

    state.conversations = data.data;
    const container = document.getElementById('conversations-list');
    if (!container) return;
    container.innerHTML = '';

    state.conversations.forEach(conv => {
        const item = document.createElement('div');
        item.className = `group flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium cursor-pointer transition ${state.currentConversationId === conv.id ? 'bg-dark-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-dark-500'}`;
        item.innerHTML = `
            <span class="truncate flex-1" onclick="loadConversationDetail('${conv.id}')">${escapeHtml(conv.title)}</span>
            <button onclick="deleteConversation(event, '${conv.id}')" class="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-red-400 px-1">×</button>
        `;
        container.appendChild(item);
    });
}

async function loadConversationDetail(id) {
    const data = await apiCall(`/chat/conversations/${id}`);
    if (!data || !data.success) return;

    state.currentConversationId = id;
    switchView('chat');

    const container = document.getElementById('chat-messages-container');
    if (!container) return;
    container.innerHTML = '';

    data.data.messages.forEach(msg => {
        appendChatMessage(msg.role === 'user' ? 'user' : 'assistant', msg.content);
    });
    loadConversations();
}

function createNewChat() {
    state.currentConversationId = null;
    switchView('chat');
    const container = document.getElementById('chat-messages-container');
    if (container) {
        container.innerHTML = `
            <div class="flex items-start gap-4 max-w-3xl mx-auto w-full">
                <div class="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-purple to-brand-blue flex items-center justify-center font-bold shrink-0 shadow-md">T</div>
                <div class="glass-panel p-4 rounded-2xl text-sm leading-relaxed text-slate-200 border border-dark-400">
                    Yeni bir sohbet başlattık knk! Nasıl yardımcı olabilirim?
                </div>
            </div>
        `;
    }
}

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    if (!input) return;
    const message = input.value.trim();
    if (!message) return;

    input.value = '';
    input.style.height = 'auto';

    appendChatMessage('user', message);

    const container = document.getElementById('chat-messages-container');
    if (!container) return;

    const loadingId = 'loading-' + Date.now();
    const loadingDiv = document.createElement('div');
    loadingDiv.id = loadingId;
    loadingDiv.className = 'flex items-start gap-4 max-w-3xl mx-auto w-full';
    loadingDiv.innerHTML = `
        <div class="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-purple to-brand-blue flex items-center justify-center font-bold shrink-0 shadow-md animate-pulse">T</div>
        <div class="glass-panel p-4 rounded-2xl text-sm text-slate-400 border border-dark-400">TürkAI düşünüyor...</div>
    `;
    container.appendChild(loadingDiv);
    container.scrollTop = container.scrollHeight;

    const data = await apiCall('/chat', 'POST', {
        message,
        taskType: 'general',
        conversationId: state.currentConversationId
    });

    document.getElementById(loadingId)?.remove();

    if (data && data.success) {
        state.currentConversationId = data.data.conversationId;
        appendChatMessage('assistant', data.data.reply);
        loadConversations();
    } else {
        appendChatMessage('assistant', 'Üzgünüm, yanıt alınamadı veya kota sınırına ulaşıldı.');
    }
}

function appendChatMessage(role, text) {
    const container = document.getElementById('chat-messages-container');
    if (!container) return;
    const isUser = role === 'user';
    const div = document.createElement('div');
    div.className = `flex items-start gap-4 max-w-3xl mx-auto w-full ${isUser ? 'flex-row-reverse' : ''}`;
    
    div.innerHTML = `
        <div class="w-8 h-8 rounded-xl ${isUser ? 'bg-brand-blue/30 text-brand-blue' : 'bg-gradient-to-br from-brand-purple to-brand-blue text-white'} flex items-center justify-center font-bold shrink-0 shadow-md">${isUser ? state.user.username.charAt(0).toUpperCase() : 'T'}</div>
        <div class="glass-panel p-4 rounded-2xl text-sm leading-relaxed ${isUser ? 'bg-brand-blue/10 border-brand-blue/20 text-white' : 'text-slate-200 border-dark-400'} max-w-[80%]">${escapeHtml(text)}</div>
    `;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function handleChatKeyDown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendChatMessage();
    }
}

async function deleteConversation(event, id) {
    event.stopPropagation();
    const data = await apiCall(`/chat/conversations/${id}`, 'DELETE');
    if (data && data.success) {
        if (state.currentConversationId === id) createNewChat();
        loadConversations();
        showToast('Konuşma silindi.');
    }
}

// --- CEVAP HAFIZASI ---
async function loadMemories() {
    const data = await apiCall('/memory');
    if (!data || !data.success) return;

    const container = document.getElementById('memory-list-container');
    if (!container) return;
    container.innerHTML = '';

    if (data.data.length === 0) {
        container.innerHTML = '<div class="col-span-2 text-center text-slate-500 py-8">Henüz hafıza kaydı bulunmuyor.</div>';
        return;
    }

    data.data.forEach(mem => {
        const card = document.createElement('div');
        card.className = 'glass-panel p-4 rounded-2xl border border-dark-400 flex flex-col justify-between gap-3';
        card.innerHTML = `
            <div>
                <div class="flex justify-between items-center mb-1">
                    <span class="text-[10px] bg-brand-purple/20 text-brand-purple px-2 py-0.5 rounded-full uppercase">${escapeHtml(mem.category)}</span>
                    <span class="text-[10px] text-slate-500">Önem: ${mem.importance}</span>
                </div>
                <p class="text-xs text-slate-200 leading-relaxed">${escapeHtml(mem.content)}</p>
            </div>
            <div class="flex justify-end gap-2">
                <button onclick="deleteMemory('${mem.id}')" class="text-xs text-red-400 hover:text-red-300">Sil</button>
            </div>
        `;
        container.appendChild(card);
    });
}

async function openCreateMemoryModal() {
    const content = prompt('Hafızaya kaydedilecek bilgiyi girin:');
    if (!content) return;

    const data = await apiCall('/memory', 'POST', { content, category: 'user-pref', importance: 3 });
    if (data && data.success) {
        showToast('Hafıza kaydedildi.');
        loadMemories();
    }
}

async function deleteMemory(id) {
    const data = await apiCall(`/memory/${id}`, 'DELETE');
    if (data && data.success) {
        showToast('Hafıza kaydı silindi.');
        loadMemories();
    }
}

// --- PROJE STÜDYOSU ---
async function loadProjects() {
    const data = await apiCall('/projects');
    if (!data || !data.success) return;

    const container = document.getElementById('projects-list-container');
    if (!container) return;
    container.innerHTML = '';

    if (data.data.length === 0) {
        container.innerHTML = '<div class="col-span-2 text-center text-slate-500 py-8">Henüz aktif projeniz bulunmuyor.</div>';
        return;
    }

    data.data.forEach(proj => {
        const card = document.createElement('div');
        card.className = 'glass-panel p-4 rounded-2xl border border-dark-400 flex flex-col justify-between gap-3';
        card.innerHTML = `
            <div>
                <h4 class="font-bold text-sm text-white">${escapeHtml(proj.name)}</h4>
                <p class="text-xs text-slate-400 mt-1">${escapeHtml(proj.description || 'Açıklama yok.')}</p>
            </div>
            <div class="flex justify-between items-center text-[10px] text-slate-500">
                <span>Tür: ${proj.projectType}</span>
                <button onclick="deleteProject('${proj.id}')" class="text-red-400 hover:text-red-300">Projeyi Sil</button>
            </div>
        `;
        container.appendChild(card);
    });
}

async function openCreateProjectModal() {
    const name = prompt('Proje adı girin:');
    if (!name) return;
    const description = prompt('Proje açıklaması (isteğe bağlı):') || '';

    const data = await apiCall('/projects', 'POST', { name, description, projectType: 'web-app' });
    if (data && data.success) {
        showToast('Proje oluşturuldu.');
        loadProjects();
    }
}

async function deleteProject(id) {
    const data = await apiCall(`/projects/${id}`, 'DELETE');
    if (data && data.success) {
        showToast('Proje silindi.');
        loadProjects();
    }
}

// --- DOSYA İSTİHBARATI ---
async function loadFiles() {
    const data = await apiCall('/files');
    if (!data || !data.success) return;

    const container = document.getElementById('files-list-container');
    if (!container) return;
    container.innerHTML = '';

    if (data.data.length === 0) {
        container.innerHTML = '<div class="text-center text-slate-500 py-4">Yüklenmiş dosya bulunmuyor.</div>';
        return;
    }

    data.data.forEach(file => {
        const item = document.createElement('div');
        item.className = 'glass-panel p-3 rounded-xl border border-dark-400 flex justify-between items-center text-xs';
        item.innerHTML = `
            <div class="flex items-center gap-3">
                <span>📄</span>
                <div>
                    <div class="font-semibold text-white">${escapeHtml(file.filename)}</div>
                    <div class="text-[10px] text-slate-500">Boyut: ${(file.sizeBytes / 1024).toFixed(1)} KB</div>
                </div>
            </div>
            <span class="text-emerald-400 font-medium">Analiz Edildi</span>
        `;
        container.appendChild(item);
    });
}

async function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async function(e) {
        const content = e.target.result;
        const data = await apiCall('/files/upload', 'POST', {
            filename: file.name,
            content,
            mimeType: file.type || 'text/plain'
        });

        if (data && data.success) {
            showToast('Dosya başarıyla yüklendi.');
            loadFiles();
        } else {
            showToast(data?.error || 'Dosya yükleme başarısız.', 'error');
        }
    };
    reader.readAsText(file);
}

// --- WEB ARAŞTIRMASI ---
async function executeResearch() {
    const input = document.getElementById('research-query-input');
    if (!input) return;
    const query = input.value.trim();
    if (!query) return;

    const container = document.getElementById('research-results-container');
    if (!container) return;
    container.innerHTML = '<div class="text-center text-slate-400 py-4">Web taranıyor ve kaynaklar sentezleniyor...</div>';

    const data = await apiCall('/research', 'POST', { query });
    if (!data || !data.success) {
        container.innerHTML = '<div class="text-center text-red-400 py-4">Araştırma gerçekleştirilemedi.</div>';
        return;
    }

    const res = data.data;
    container.innerHTML = `
        <div class="glass-panel p-5 rounded-2xl border border-dark-400 space-y-4">
            <h4 class="font-bold text-sm text-white">Sentez Raporu</h4>
            <p class="text-xs text-slate-200 leading-relaxed">${escapeHtml(res.summary)}</p>
            <div class="border-t border-dark-400 pt-3">
                <div class="text-[11px] font-semibold text-slate-400 mb-2">Kullanılan Kaynaklar:</div>
                <div class="space-y-1">
                    ${res.sources.map(s => `<a href="${s.url}" target="_blank" class="block text-xs text-brand-blue hover:underline">🔗 ${escapeHtml(s.title)} -${escapeHtml(s.snippet)}</a>`).join('')}
                </div>
            </div>
        </div>
    `;
}

// --- JARVIS AJANI ---
async function startAgentTask() {
    const input = document.getElementById('agent-objective-input');
    if (!input) return;
    const objective = input.value.trim();
    if (!objective) return;

    const data = await apiCall('/agent/tasks', 'POST', { objective });
    if (data && data.success) {
        showToast('Jarvis ajan görevi başlatıldı.');
        loadAgentTasks();
    } else {
        showToast(data?.error || 'Ajan görevi başlatılamadı. Ultra plan gerekli olabilir.', 'error');
    }
}

async function loadAgentTasks() {
    const data = await apiCall('/agent/tasks');
    if (!data || !data.success) return;

    const container = document.getElementById('agent-tasks-container');
    if (!container) return;
    container.innerHTML = '';

    data.data.forEach(task => {
        const card = document.createElement('div');
        card.className = 'glass-panel p-4 rounded-2xl border border-dark-400 space-y-2';
        card.innerHTML = `
            <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-white">Hedef: ${escapeHtml(task.objective)}</span>
                <span class="text-[10px] bg-brand-purple/20 text-brand-purple px-2 py-0.5 rounded-full">${task.status}</span>
            </div>
            <div class="space-y-1 mt-2">
                ${task.steps.map(s => `<div class="text-[11px] text-slate-400">🔹 Adım ${s.step}: ${escapeHtml(s.description)} (${s.status})</div>`).join('')}
            </div>
        `;
        container.appendChild(card);
    });
}

// --- PLANLAR ---
async function loadPlans() {
    const data = await apiCall('/plans');
    if (!data || !data.success) return;

    const container = document.getElementById('plans-container');
    if (!container) return;
    container.innerHTML = '';

    Object.keys(data.data).forEach(key => {
        const plan = data.data[key];
        const isCurrent = state.user && state.user.plan === key;
        const card = document.createElement('div');
        card.className = `glass-panel p-6 rounded-2xl border ${isCurrent ? 'border-brand-purple glow-effect' : 'border-dark-400'} flex flex-col justify-between`;
        card.innerHTML = `
            <div>
                <h4 class="font-bold text-lg text-white capitalize">${plan.name} Plan</h4>
                <p class="text-xs text-slate-400 mt-2">Günlük Token: ${plan.maxTokensPerDay.toLocaleString()}</p>
                <p class="text-xs text-slate-400 mt-1">Dosya Boyutu: ${plan.maxFileSizeMb} MB</p>
                <p class="text-xs text-slate-400 mt-1">Jarvis Ajanı: ${plan.jarvisAccess ? '✅ Aktif' : '❌ Yok'}</p>
            </div>
            <button class="mt-6 w-full py-2.5 rounded-xl font-semibold text-xs ${isCurrent ? 'bg-dark-600 text-slate-400 cursor-default' : 'bg-brand-purple text-white hover:opacity-90'} transition">
                ${isCurrent ? 'Mevcut Planınız' : 'Planı Seç'}
            </button>
        `;
        container.appendChild(card);
    });
}

// --- GÜVENLİK MERKEZİ ---
async function loadSessions() {
    const data = await apiCall('/security/sessions');
    if (!data || !data.success) return;

    const container = document.getElementById('sessions-list-container');
    if (!container) return;
    container.innerHTML = '';

    data.data.forEach(session => {
        const item = document.createElement('div');
        item.className = 'glass-panel p-4 rounded-xl border border-dark-400 flex justify-between items-center text-xs';
        item.innerHTML = `
            <div>
                <div class="font-semibold text-white">IP: ${escapeHtml(session.ip)}</div>
                <div class="text-[10px] text-slate-500">Tarayıcı: ${escapeHtml(session.userAgent || 'Bilinmiyor')}</div>
            </div>
            <button onclick="revokeSession('${session.sessionId}')" class="text-red-400 hover:text-red-300 font-medium">Oturumu Kapat</button>
        `;
        container.appendChild(item);
    });
}

async function revokeSession(sessionId) {
    const data = await apiCall(`/security/sessions/${sessionId}`, 'DELETE');
    if (data && data.success) {
        showToast('Oturum sonlandırıldı.');
        loadSessions();
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}
