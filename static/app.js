// ── State ──
let currentEmail = '';
let analysisResult = null;
let chatHistory = [];

// ── Signal helpers ──
function getSigType(t) {
  if (t.startsWith('🤖')) return 'ml';
  if (t.startsWith('🧠')) return 'ai';
  return 'rule';
}

function getSigIcon(t) {
  if (t.startsWith('⚠️') || t.startsWith('⚠')) return '⚠';
  if (t.startsWith('🔗')) return '⛓';
  if (t.startsWith('📧')) return '✉';
  if (t.startsWith('🤖')) return '◈';
  if (t.startsWith('🧠')) return '◆';
  return '·';
}

function sigTag(type) {
  if (type === 'ml') return '<span class="sig-tag t-ml">ML</span>';
  if (type === 'ai') return '<span class="sig-tag t-ai">LLM</span>';
  return '<span class="sig-tag t-rule">Rule</span>';
}

// ── Score ring animation ──
function animateScore(target) {
  const numEl = document.getElementById('scoreNum');
  const ringEl = document.getElementById('scoreRing');
  const circumference = 188; // 2 * pi * r=30
  let current = 0;
  const step = target / 40;
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    numEl.textContent = Math.round(current);
    ringEl.style.strokeDashoffset = circumference - (current / 100) * circumference;
    if (current >= target) clearInterval(timer);
  }, 25);
}

// ── Chat helpers ──
function appendMessage(role, html) {
  const container = document.getElementById('chatMessages');
  const isAI = role === 'ai';
  const div = document.createElement('div');
  div.className = `msg ${role}`;
  div.innerHTML = `
    <div class="msg-avatar">${isAI ? 'AI' : 'ME'}</div>
    <div class="msg-bubble">
      <div class="msg-label">${isAI ? 'PhishGuard AI' : 'You'}</div>
      ${html}
    </div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function showTyping() {
  const container = document.getElementById('chatMessages');
  const div = document.createElement('div');
  div.className = 'msg ai';
  div.id = 'typingIndicator';
  div.innerHTML = `
    <div class="msg-avatar">AI</div>
    <div class="msg-bubble">
      <div class="msg-label">PhishGuard AI</div>
      <div class="typing-dots"><span></span><span></span><span></span></div>
    </div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function removeTyping() {
  const el = document.getElementById('typingIndicator');
  if (el) el.remove();
}

// ── Analyze Email ──
async function analyzeEmail() {
  const emailText = document.getElementById('emailInput').value.trim();
  if (!emailText) { alert('Please paste an email to analyze.'); return; }

  const btn = document.getElementById('analyzeBtn');
  const scanBar = document.getElementById('scanBar');

  currentEmail = emailText;
  btn.disabled = true;
  btn.querySelector('span').textContent = '⟳   Analyzing threat...';
  scanBar.classList.add('active');

  try {
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: emailText })
    });
    const data = await res.json();
    analysisResult = data;

    // Show results, hide empty state
    document.getElementById('emptyState').style.display = 'none';
    const rp = document.getElementById('resultsPanel');
    rp.style.display = 'flex';

    // Verdict
    const card = document.getElementById('verdictCard');
    card.className = `verdict-card c-${data.color}`;
    document.getElementById('vlabel').textContent = data.verdict;
    document.getElementById('vsummary').textContent = data.summary;

    // Score ring
    document.getElementById('scoreNum').textContent = '0';
    document.getElementById('scoreRing').style.strokeDashoffset = '188';
    setTimeout(() => animateScore(data.score), 80);

    // Signals
    document.getElementById('signalsList').innerHTML = data.reasons.map(r => {
      const type = getSigType(r);
      const icon = getSigIcon(r);
      const clean = r.replace(/^[\u{1F000}-\u{1FFFF}⚠🔗📧🤖🧠·]\uFE0F?\s*/u, '');
      return `<div class="signal-row">
        <span class="sig-icon">${icon}</span>
        ${sigTag(type)}
        <span>${clean}</span>
      </div>`;
    }).join('');

    // Set up chat with full analysis context
    const verdictColor = data.color === 'green' ? 'var(--green)'
      : data.color === 'red' ? 'var(--red)'
      : data.color === 'orange' ? 'var(--orange)'
      : 'var(--yellow)';

    chatHistory = [
      {
        role: 'user',
        content: `I have analyzed the following email for phishing threats.\n\nEMAIL:\n${emailText}\n\nANALYSIS RESULT:\n- Verdict: ${data.verdict}\n- Risk score: ${data.score}/100\n- Signals: ${data.reasons.join('; ')}\n${data.ai_explanation ? '- AI explanation: ' + data.ai_explanation : ''}\n\nPlease be ready to answer follow-up questions about this email.`
      },
      {
        role: 'assistant',
        content: `Analysis complete. I've assessed this email as ${data.verdict} with a risk score of ${data.score}/100. ${data.ai_explanation || data.summary} I have full context on this email — ask me anything.`
      }
    ];

    // Reset and populate chat
    document.getElementById('chatMessages').innerHTML = '';
    appendMessage('ai',
      `Analysis complete. Verdict: <strong style="color:${verdictColor}">${data.verdict}</strong> (${data.score}/100).<br><br>${data.ai_explanation || data.summary}<br><br>Ask me anything about this email.`
    );

    // Enable chat
    document.getElementById('chatInput').disabled = false;
    document.getElementById('chatSend').disabled = false;
    document.getElementById('chatHint').textContent = 'Enter to send · Ask anything about this email';

  } catch (e) {
    alert('Error connecting to server. Is Flask running?');
  } finally {
    btn.disabled = false;
    btn.querySelector('span').textContent = '⟶ &nbsp; Run Threat Analysis';
    scanBar.classList.remove('active');
  }
}

// ── Chat ──
async function sendChat() {
  const input = document.getElementById('chatInput');
  const question = input.value.trim();
  if (!question || !analysisResult) return;

  input.value = '';
  input.disabled = true;
  document.getElementById('chatSend').disabled = true;

  appendMessage('user', question);
  chatHistory.push({ role: 'user', content: question });
  showTyping();

  try {
    const res = await fetch('/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ history: chatHistory })
    });
    const data = await res.json();
    removeTyping();
    const reply = data.reply || 'Sorry, I could not generate a response.';
    appendMessage('ai', reply);
    chatHistory.push({ role: 'assistant', content: reply });
  } catch (e) {
    removeTyping();
    appendMessage('ai', 'Connection error. Is the server running?');
  } finally {
    input.disabled = false;
    document.getElementById('chatSend').disabled = false;
    input.focus();
  }
}

// Cmd/Ctrl+Enter to analyze
document.getElementById('emailInput').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyzeEmail();
});