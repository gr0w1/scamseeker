let currentToken = localStorage.getItem('token') || null;
let currentUser = null;
let isRegisterMode = false;

const API_BASE = '/api/v1';

document.addEventListener('DOMContentLoaded', initApp);

async function initApp() {
  await checkAuth();
  setupEventListeners();
  if (currentUser) loadHistory();
}

function setupEventListeners() {
  const loginBtn = document.getElementById('loginBtn');
  if (loginBtn) loginBtn.onclick = () => showAuthModal(false);
  
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.onclick = logout;
  
  const analyzeBtn = document.getElementById('analyzeBtn');
  if (analyzeBtn) analyzeBtn.onclick = analyzeText;
  
  const closeModal = document.getElementById('closeModal');
  if (closeModal) closeModal.onclick = hideAuthModal;
  
  const authForm = document.getElementById('authForm');
  if (authForm) {
    authForm.onsubmit = handleAuth;
    console.log('✅ Форма авторизации подключена');
  }
  
  const switchMode = document.getElementById('switchMode');
  if (switchMode) switchMode.onclick = toggleAuthMode;
  
  const authModal = document.getElementById('authModal');
  if (authModal) {
    authModal.onclick = (e) => {
      if (e.target === e.currentTarget) hideAuthModal();
    };
  }
}

async function checkAuth() {
  if (!currentToken) {
    updateUIForGuest();
    return;
  }
  
  try {
    const response = await fetch(`${API_BASE}/auth/me`, {
      headers: { 'Authorization': Bearer ${currentToken} }
    });
    
    if (response.ok) {
      currentUser = await response.json();
      updateUIForUser();
      console.log('✅ Авторизация проверена:', currentUser.email);
    } else {
      console.log('❌ Токен недействителен');
      localStorage.removeItem('token');
      currentToken = null;
      updateUIForGuest();
    }
  } catch (error) {
    console.error('Ошибка checkAuth:', error);
    localStorage.removeItem('token');
    currentToken = null;
    updateUIForGuest();
  }
}

function updateUIForGuest() {
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const userInfo = document.getElementById('userInfo');
  const historySection = document.getElementById('historySection');
  
  if (loginBtn) loginBtn.style.display = 'inline-block';
  if (logoutBtn) logoutBtn.style.display = 'none';
  if (userInfo) userInfo.style.display = 'none';
  if (historySection) historySection.style.display = 'none';
}

function updateUIForUser() {
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const userInfo = document.getElementById('userInfo');
  const historySection = document.getElementById('historySection');
  
  if (loginBtn) loginBtn.style.display = 'none';
  if (logoutBtn) logoutBtn.style.display = 'inline-block';
  if (userInfo) {
    userInfo.textContent = ${currentUser.first_name || ''} ${currentUser.last_name || ''}.trim() || currentUser.email;
    userInfo.style.display = 'inline-block';
  }
  if (historySection) historySection.style.display = 'block';
}

function showAuthModal(register = false) {
  isRegisterMode = register;

  const modalTitle = document.getElementById('modalTitle');
  const nameFields = document.getElementById('nameFields');
  const switchMode = document.getElementById('switchMode');
  const submitBtn = document.querySelector('#authForm button[type="submit"]');
  const firstName = document.getElementById('firstName');
  const lastName = document.getElementById('lastName');

  if (modalTitle) modalTitle.textContent = register ? 'Регистрация' : 'Вход';
  if (nameFields) nameFields.style.display = register ? 'block' : 'none';

  if (switchMode) {
    switchMode.textContent = register ? 'У меня есть аккаунт' : 'Создать аккаунт';
    switchMode.style.display = 'block';
  }

  if (submitBtn) submitBtn.textContent = register ? 'Зарегистрироваться' : 'Войти';

  if (firstName) {
    firstName.disabled = !register;
    firstName.required = register;
    if (!register) firstName.value = '';
  }
  if (lastName) {
      lastName.disabled = !register;
      lastName.required = register;
      if (!register) lastName.value = '';
  }

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
  console.log('🔄 handleAuth вызвана, режим:', isRegisterMode ? 'регистрация' : 'логин');
  
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  
  if (!email || !password) {
    alert('⚠️ Заполните email и пароль');
    return;
  }
  
  try {
    if (isRegisterMode) {
      const firstName = document.getElementById('firstName').value.trim();
      const lastName = document.getElementById('lastName').value.trim();
      
      if (!firstName || !lastName) {
        alert('⚠️ Заполните имя и фамилию');
        return;
      }
      
      console.log('🔄 Регистрация:', { email, firstName, lastName });
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          email, 
          first_name: firstName, 
          last_name: lastName, 
          password 
        })
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Ошибка регистрации');
      }
      
      alert('✅ Регистрация успешна! Теперь войдите.');
      showAuthModal(false);
    } else {
      console.log('🔄 Логин:', email);
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      console.log('📡 Ответ сервера:', response.status);
      
      if (response.ok) {
        const data = await response.json();
        console.log('✅ Токен получен:', data.access_token ? 'ДА' : 'НЕТ');
        
        currentToken = data.access_token;
        localStorage.setItem('token', currentToken);
        await checkAuth();
        hideAuthModal();
        if (currentUser) loadHistory();
      } else {
        const error = await response.json().catch(() => ({}));
        console.error('Ошибка логина:', error);
        alert(`❌ ${error.detail || 'Неверный email или пароль'}`);
      }
    }
  } catch (error) {
    console.error('🚨 Ошибка авторизации:', error);
    alert('❌ Ошибка: ' + error.message);
  }
}

function logout() {
  localStorage.removeItem('token');
  currentToken = null;
  currentUser = null;
  updateUIForGuest();
  const historyList = document.getElementById('historyList');
  if (historyList) historyList.innerHTML = '<p style="text-align: center; color: #6b7280;">История пуста</p>';
  const results = document.getElementById('results');
  if (results) results.style.display = 'none';
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
    const headers = { 
      'Content-Type': 'application/json',
      ...(currentToken && { 'Authorization': Bearer ${currentToken} })
    };
    
    const response = await fetch(`${API_BASE}/analysis/check`, {
      method: 'POST',
      headers,
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
    alert('❌ Ошибка соединения. Бэкенд запущен?');
  } finally {
    analyzeBtn.textContent = 'Проанализировать';
    analyzeBtn.disabled = false;
  }
}

function showResults(result) {
  const riskLevel = document.getElementById('riskLevel');
  const riskClass = risk-${result.risk_level};
  riskLevel.textContent = result.risk_level?.toUpperCase() || '—';
  riskLevel.className = badge-risk ${riskClass};
  
  document.getElementById('finalScore').textContent = (result.final_score * 100).toFixed(1) + '%';
  document.getElementById('shortExplanation').textContent = result.short_explanation || '—';
  
  const highlightsList = document.getElementById('highlightsList');
  if (result.highlights?.length) {
    highlightsList.innerHTML = result.highlights.map(h => 
      `<div class="highlight ${h.severity}">
        <strong>"${h.text}"</strong><br>
        <small>${h.label} (${h.score?.toFixed(2)}) ${h.reason_code}</small>
      </div>`
    ).join('');
  } else {
    highlightsList.innerHTML = '<p style="color: #6b7280;">Подозрительных фрагментов не найдено</p>';
  }
  
  const recList = document.getElementById('recommendationsList');
  recList.innerHTML = (result.recommendations || []).map(rec => `<li>${rec}</li>`).join('');
  
  document.getElementById('results').style.display = 'block';
  document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

async function loadHistory() {
  if (!currentToken) return;
  
  try {
    const response = await fetch(`${API_BASE}/history/ `, {
      headers: { 'Authorization': Bearer ${currentToken} }
    });
    
    if (response.ok) {
      const history = await response.json();
      const historyList = document.getElementById('historyList');
      
      if (!history.length) {
        historyList.innerHTML = '<p style="text-align: center; color: #6b7280;">История пуста</p>';
      } else {
        historyList.innerHTML = history.map(item => `
          <div class="history-item ${item.risk_level}" onclick="loadHistoryItem(${item.id})" style="padding:16px; border-radius:8px; background:rgba(15,23,42,0.5); margin:4px 0; cursor:pointer;">
            <div style="font-weight:600;">${item.short_explanation}</div>
            <div style="color:#9ca3af; font-size:0.9rem;">
              ${(item.final_score * 100).toFixed(1)}% • ${new Date(item.created_at).toLocaleString('ru-RU')}
            </div>
          </div>
        `).join('');
      }
    }
  } catch (error) {
    console.error('History error:', error);
  }
}

async function loadHistoryItem(id) {
  try {
    const response = await fetch(`${API_BASE}/history/${id}`, {
      headers: { 'Authorization': Bearer ${currentToken} }
    });
    
    if (response.ok) {
      const result = await response.json();
      document.getElementById('textInput').value = result.text;
      showResults(result);
    }
  } catch (error) {
    alert('Ошибка загрузки истории');
  }
}
