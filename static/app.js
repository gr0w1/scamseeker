let currentToken = localStorage.getItem('token') || null;
let currentUser = null;
let isRegisterMode = false;

const API_BASE = 'http://localhost:8000/api/v1';

document.addEventListener('DOMContentLoaded', initApp);

async function initApp() {
  await checkAuth();
  setupEventListeners();
  if (currentUser) loadHistory();
}

function setupEventListeners() {
  document.getElementById('loginBtn').onclick = () => showAuthModal(false);
  document.getElementById('logoutBtn').onclick = logout;
  document.getElementById('analyzeBtn').onclick = analyzeText;
  document.getElementById('closeModal').onclick = hideAuthModal;
  document.getElementById('authForm').onsubmit = handleAuth;
  document.getElementById('switchMode').onclick = toggleAuthMode;
  
  document.getElementById('authModal').onclick = (e) => {
    if (e.target === e.currentTarget) hideAuthModal();
  };
}

async function checkAuth() {
  if (!currentToken) {
    updateUIForGuest();
    return;
  }
  
  try {
    const response = await fetch(`${API_BASE}/auth/me`, {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    
    if (response.ok) {
      currentUser = await response.json();
      updateUIForUser();
    } else {
      localStorage.removeItem('token');
      currentToken = null;
      updateUIForGuest();
    }
  } catch {
    localStorage.removeItem('token');
    currentToken = null;
    updateUIForGuest();
  }
}

function updateUIForGuest() {
  document.getElementById('loginBtn').style.display = 'inline-block';
  document.getElementById('logoutBtn').style.display = 'none';
  document.getElementById('userInfo').style.display = 'none';
  document.getElementById('historySection').style.display = 'none';
}

function updateUIForUser() {
  document.getElementById('loginBtn').style.display = 'none';
  document.getElementById('logoutBtn').style.display = 'inline-block';
  document.getElementById('userInfo').textContent = `${currentUser.first_name} ${currentUser.last_name}`;
  document.getElementById('userInfo').style.display = 'inline-block';
  document.getElementById('historySection').style.display = 'block';
}

function showAuthModal(register = false) {
  isRegisterMode = register;
  document.getElementById('modalTitle').textContent = register ? 'Регистрация' : 'Вход';
  document.getElementById('nameFields').style.display = register ? 'block' : 'none';
  document.getElementById('switchMode').textContent = register ? 'У меня есть аккаунт' : 'Создать аккаунт';
  document.getElementById('switchMode').style.display = 'block';
  document.getElementById('submitBtn').textContent = register ? 'Зарегистрироваться' : 'Войти';
  document.getElementById('authModal').style.display = 'flex';
}

function hideAuthModal() {
  document.getElementById('authModal').style.display = 'none';
  document.getElementById('authForm').reset();
}

function toggleAuthMode() {
  showAuthModal(!isRegisterMode);
}

async function handleAuth(e) {
  e.preventDefault();
  
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  
  try {
    if (isRegisterMode) {
      const firstName = document.getElementById('firstName').value;
      const lastName = document.getElementById('lastName').value;
      
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, first_name: firstName, last_name: lastName, password })
      });
      
      if (!response.ok) throw new Error('Registration failed');
      
      alert('✅ Регистрация успешна! Теперь войдите в аккаунт.');
      showAuthModal(false);
    } else {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      if (response.ok) {
        const data = await response.json();
        currentToken = data.access_token;
        localStorage.setItem('token', currentToken);
        await checkAuth();
        hideAuthModal();
        loadHistory();
      } else {
        const error = await response.json();
        alert(`❌ ${error.detail || 'Неверный email или пароль'}`);
      }
    }
  } catch (error) {
    console.error('Auth error:', error);
    alert('❌ Ошибка авторизации. Попробуйте позже.');
  }
}

function logout() {
  localStorage.removeItem('token');
  currentToken = null;
  currentUser = null;
  updateUIForGuest();
  document.getElementById('historyList').innerHTML = '<p style="text-align: center; color: #6b7280;">История пуста</p>';
  document.getElementById('results').style.display = 'none';
}

async function analyzeText() {
  const text = document.getElementById('textInput').value.trim();
  if (!text) {
    alert('⚠️ Введите текст для анализа');
    return;
  }
  
  const analyzeBtn = document.getElementById('analyzeBtn');
  analyzeBtn.textContent = '🔄 Анализирую...';
  analyzeBtn.disabled = true;
  
  try {
    const response = await fetch(`${API_BASE}/analysis/check`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        ...(currentToken && { 'Authorization': `Bearer ${currentToken}` })
      },
      body: JSON.stringify({ text })
    });
    
    if (response.ok) {
      const result = await response.json();
      showResults(result);
    } else {
      const error = await response.json();
      alert(`❌ Ошибка анализа: ${error.detail || 'Неизвестная ошибка'}`);
    }
  } catch (error) {
    console.error('Analysis error:', error);
    alert('❌ Ошибка соединения с сервером. Убедитесь, что бэкенд запущен.');
  } finally {
    analyzeBtn.textContent = '🚀 Проверить';
    analyzeBtn.disabled = false;
  }
}

function showResults(result) {
  const riskLevel = document.getElementById('riskLevel');
  const riskClass = `risk-${result.risk_level}`;
  riskLevel.textContent = result.risk_level.toUpperCase();
  riskLevel.className = `risk-badge ${riskClass}`;
  
  document.getElementById('finalScore').textContent = (result.final_score * 100).toFixed(1) + '%';
  
  document.getElementById('shortExplanation').textContent = result.short_explanation;
  
  const highlightsList = document.getElementById('highlightsList');
  if (result.highlights && result.highlights.length) {
    highlightsList.innerHTML = result.highlights.map(h => 
      `<div class="highlight ${h.severity}">
        <strong>"${h.text}"</strong><br>
        <small>${h.label} • Оценка: ${h.score.toFixed(2)} • ${h.reason_code}</small>
      </div>`
    ).join('');
  } else {
    highlightsList.innerHTML = '<p style="color: #6b7280;">Подозрительных фрагментов не найдено</p>';
  }
  
  const recList = document.getElementById('recommendationsList');
  recList.innerHTML = result.recommendations.map(rec => `<li>${rec}</li>`).join('');
  
  document.getElementById('results').style.display = 'block';
  document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

async function loadHistory() {
  if (!currentToken || !currentUser) return;
  
  try {
    const response = await fetch(`${API_BASE}/history`, {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    
    if (response.ok) {
      const history = await response.json();
      const historyList = document.getElementById('historyList');
      
      if (history.length === 0) {
        historyList.innerHTML = '<p style="text-align: center; color: #6b7280;">История пуста</p>';
      } else {
        historyList.innerHTML = history.map(item => `
          <div class="history-item ${item.risk_level}" onclick="loadHistoryItem(${item.id})">
            <div style="font-weight: 600; margin-bottom: 4px;">${item.short_explanation}</div>
            <div style="color: #6b7280; font-size: 14px;">
              ${(item.final_score * 100).toFixed(1)}% • 
              ${new Date(item.created_at).toLocaleString('ru-RU')}
            </div>
          </div>
        `).join('');
      }
    }
  } catch (error) {
    console.error('History load error:', error);
    document.getElementById('historyList').innerHTML = '<p style="color: #ef4444;">Ошибка загрузки истории</p>';
  }
}

async function loadHistoryItem(id) {
  try {
    const response = await fetch(`${API_BASE}/history/${id}`, {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    
    if (response.ok) {
      const result = await response.json();
      document.getElementById('textInput').value = result.text;
      showResults(result);
    }
  } catch (error) {
    console.error('History item error:', error);
    alert('❌ Ошибка загрузки элемента истории');
  }
}

async function login(email, password) {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }), 
});

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || 'Ошибка логина');
  }

  const data = await response.json();
 
  const token = data.access_token;
  localStorage.setItem('token', token);
  return token;
}
