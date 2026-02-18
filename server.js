const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const path = require('path');
const https = require('https');
const http = require('http');

const app = express();
const PORT = 3000;

// ─── Database Setup ───────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    max_reviews INTEGER DEFAULT -1,
    used_reviews INTEGER DEFAULT 0,
    subscription_end TEXT DEFAULT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT DEFAULT '新批改',
    topic TEXT DEFAULT '',
    essay TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(session_id) REFERENCES sessions(id)
  );

  CREATE TABLE IF NOT EXISTS auth_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// Create default admin if not exists
const adminExists = db.prepare("SELECT id FROM users WHERE is_admin = 1").get();
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(`INSERT INTO users (id, username, password_hash, display_name, is_admin)
              VALUES (?, 'admin', ?, '管理员', 1)`)
    .run(uuidv4(), hash);
  console.log('✅ 默认管理员账户已创建: admin / admin123');
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: '未登录' });
  const row = db.prepare("SELECT u.* FROM auth_tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?").get(token);
  if (!row) return res.status(401).json({ error: '登录已过期' });
  req.user = row;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: '需要管理员权限' });
    next();
  });
}

// ─── Auth APIs ────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '请填写用户名和密码' });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  // Check subscription
  if (!user.is_admin && user.subscription_end) {
    const now = new Date();
    const end = new Date(user.subscription_end);
    if (now > end) {
      return res.status(403).json({ error: '您的订阅已过期，请联系管理员续期' });
    }
  }

  const token = uuidv4();
  db.prepare("INSERT INTO auth_tokens (token, user_id) VALUES (?, ?)").run(token, user.id);

  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      is_admin: user.is_admin,
      max_reviews: user.max_reviews,
      used_reviews: user.used_reviews,
      subscription_end: user.subscription_end
    }
  });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = req.cookies.token || req.headers['x-auth-token'];
  db.prepare("DELETE FROM auth_tokens WHERE token = ?").run(token);
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const u = req.user;
  res.json({
    id: u.id,
    username: u.username,
    display_name: u.display_name,
    is_admin: u.is_admin,
    max_reviews: u.max_reviews,
    used_reviews: u.used_reviews,
    subscription_end: u.subscription_end
  });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { old_password, new_password, display_name } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);

  if (new_password) {
    if (!old_password || !bcrypt.compareSync(old_password, user.password_hash)) {
      return res.status(400).json({ error: '原密码错误' });
    }
    if (new_password.length < 6) return res.status(400).json({ error: '新密码至少6位' });
    const hash = bcrypt.hashSync(new_password, 10);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, user.id);
  }

  if (display_name) {
    db.prepare("UPDATE users SET display_name = ? WHERE id = ?").run(display_name, user.id);
  }

  res.json({ ok: true });
});

// ─── Admin APIs ───────────────────────────────────────────────────────────────
app.get('/api/admin/settings', requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT key, value FROM settings WHERE key IN ('apiKey','apiBase','model')").all();
  const result = {};
  rows.forEach(r => result[r.key] = r.value);
  res.json(result);
});

app.put('/api/admin/settings', requireAdmin, (req, res) => {
  const { apiKey, apiBase, model } = req.body;
  const upsert = db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
  if (apiKey !== undefined) upsert.run('apiKey', apiKey);
  if (apiBase !== undefined) upsert.run('apiBase', apiBase);
  if (model !== undefined) upsert.run('model', model);
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare("SELECT id, username, display_name, max_reviews, used_reviews, subscription_end, is_admin, created_at FROM users ORDER BY created_at DESC").all();
  res.json(users);
});

// Generate random username/password
function randomStr(len, chars) {
  let result = '';
  for (let i = 0; i < len; i++) result += chars[Math.floor(Math.random() * chars.length)];
  return result;
}

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const username = 'user_' + randomStr(6, 'abcdefghijklmnopqrstuvwxyz0123456789');
  const password = randomStr(10, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789');
  const hash = bcrypt.hashSync(password, 10);
  const id = uuidv4();

  const { max_reviews = -1, subscription_end = null } = req.body || {};

  db.prepare(`INSERT INTO users (id, username, password_hash, display_name, max_reviews, subscription_end)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, username, hash, username, max_reviews, subscription_end);

  res.json({ id, username, password, max_reviews, subscription_end });
});

app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { max_reviews, subscription_end, display_name } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: '用户不存在' });

  if (max_reviews !== undefined) db.prepare("UPDATE users SET max_reviews = ? WHERE id = ?").run(max_reviews, req.params.id);
  if (subscription_end !== undefined) db.prepare("UPDATE users SET subscription_end = ? WHERE id = ?").run(subscription_end, req.params.id);
  if (display_name !== undefined) db.prepare("UPDATE users SET display_name = ? WHERE id = ?").run(display_name, req.params.id);

  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: '不能删除自己' });
  db.prepare("DELETE FROM auth_tokens WHERE user_id = ?").run(req.params.id);
  db.prepare("DELETE FROM messages WHERE session_id IN (SELECT id FROM sessions WHERE user_id = ?)").run(req.params.id);
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(req.params.id);
  db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

// Admin reset a user's password
app.post('/api/admin/users/:id/reset-password', requireAdmin, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  if (user.is_admin) return res.status(400).json({ error: '不能重置管理员密码' });
  const newPassword = randomStr(10, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789');
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, req.params.id);
  // Invalidate all existing sessions for this user
  db.prepare("DELETE FROM auth_tokens WHERE user_id = ?").run(req.params.id);
  res.json({ password: newPassword });
});

// ─── Session APIs ─────────────────────────────────────────────────────────────
app.get('/api/sessions', requireAuth, (req, res) => {
  const sessions = db.prepare("SELECT id, title, topic, status, created_at, updated_at FROM sessions WHERE user_id = ? ORDER BY updated_at DESC").all(req.user.id);
  res.json(sessions);
});

app.post('/api/sessions', requireAuth, (req, res) => {
  const id = uuidv4();
  db.prepare("INSERT INTO sessions (id, user_id, title) VALUES (?, ?, '新批改')").run(id, req.user.id);
  res.json({ id });
});

app.get('/api/sessions/:id', requireAuth, (req, res) => {
  const session = db.prepare("SELECT * FROM sessions WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id);
  if (!session) return res.status(404).json({ error: '会话不存在' });
  const messages = db.prepare("SELECT * FROM messages WHERE session_id = ? ORDER BY created_at ASC").all(req.params.id);
  res.json({ ...session, messages });
});

app.delete('/api/sessions/:id', requireAuth, (req, res) => {
  const session = db.prepare("SELECT * FROM sessions WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id);
  if (!session) return res.status(404).json({ error: '会话不存在' });
  db.prepare("DELETE FROM messages WHERE session_id = ?").run(req.params.id);
  db.prepare("DELETE FROM sessions WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

// ─── AI Proxy Helper ──────────────────────────────────────────────────────────
function getAIConfig() {
  const rows = db.prepare("SELECT key, value FROM settings WHERE key IN ('apiKey','apiBase','model')").all();
  const cfg = { apiKey: '', apiBase: 'https://api.openai.com/v1', model: 'gpt-4o-mini' };
  rows.forEach(r => cfg[r.key] = r.value);
  return cfg;
}

async function callAI(systemPrompt, userContent, cfg) {
  const { apiKey, apiBase, model } = cfg;
  if (!apiKey) throw new Error('管理员尚未配置 API Key，请联系管理员');

  const body = JSON.stringify({
    model,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userContent }
    ],
    temperature: 0.7
  });

  return new Promise((resolve, reject) => {
    const url = new URL(`${apiBase}/chat/completions`);
    const lib = url.protocol === 'https:' ? https : http;
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'Content-Length': Buffer.byteLength(body)
      }
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) return reject(new Error(json.error.message || JSON.stringify(json.error)));
          resolve(json.choices[0].message.content);
        } catch (e) {
          reject(new Error('AI 响应解析失败: ' + data.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Review API ───────────────────────────────────────────────────────────────
const PROMPTS = {
  A_Analysis: `你是一位极其严苛的雅思语法考官（Grammar Guru）。你的任务是只关注【词汇(LR)】和【语法(GRA)】。
1. 找出所有语法错误（时态、单复数、从句错误等）。
2. 指出中式英语（Chinglish）表达，并提供地道替换。
3. 严厉批评词汇重复或低级的问题。
不要写总结，直接列出错误点和修正建议。`,

  B_Analysis: `你是一位雅思逻辑思维导师（Logic Master）。你的任务是忽略小语法错误，只关注【任务回应(TR)】和【连贯衔接(CC)】。
1. 论点是否切题？有没有跑题？
2. 论证是否充分？逻辑链条是否断裂？
3. 段落连接词是否自然？
如果逻辑不通，请直言不讳。`,

  A_Critique: `你现在进入了委员会辩论环节。针对 Logic Master (逻辑导师) 的反馈，你有什么补充或反对意见？
1. 考生的语法错误是否严重到了影响逻辑表达？
2. Logic Master 是否漏掉了因语言晦涩导致的逻辑不清？
请简短回应（100字以内），开头用 "To Logic Master: ..."`,

  B_Critique: `你现在进入了委员会辩论环节。针对 Grammar Guru (语法考官) 的反馈，你有什么补充或反对意见？
1. 语法考官是否过于吹毛求疵，忽略了内容的深度？
2. 某些被认为"错误"的表达在特定语境下是否可接受？
请简短回应（100字以内），开头用 "To Grammar Guru: ..."`,

  C_Final: `你是一位资深雅思主考官。你的任务是阅读考官A和B的第一轮分析，以及他们的第二轮辩论，最后给出一份最终报告。
1. 总结A和B的观点，并判定谁在辩论中更有理。
2. 给出【详细评分表】（TR, CC, LR, GRA 四项分及总分）。
3. 综合修改意见，给出一篇优化后的范文。
语气要专业、权威且富有鼓励性，使用Markdown格式。`
};

app.post('/api/review', requireAuth, async (req, res) => {
  const { session_id, topic, essay } = req.body;
  if (!essay) return res.status(400).json({ error: '请提供作文内容' });

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);

  // Check subscription
  if (!user.is_admin && user.subscription_end) {
    if (new Date() > new Date(user.subscription_end)) {
      return res.status(403).json({ error: '您的订阅已过期，请联系管理员续期' });
    }
  }

  // Check review count
  if (!user.is_admin && user.max_reviews !== -1 && user.used_reviews >= user.max_reviews) {
    return res.status(403).json({ error: `批改次数已用完（${user.used_reviews}/${user.max_reviews}），请联系管理员` });
  }

  // Verify session belongs to user
  const session = db.prepare("SELECT * FROM sessions WHERE id = ? AND user_id = ?").get(session_id, user.id);
  if (!session) return res.status(404).json({ error: '会话不存在' });

  const cfg = getAIConfig();
  const userInput = `Topic: ${topic || '(未提供题目)'}\n\nEssay: ${essay}`;

  try {
    // Round 1: Independent Analysis
    const [resA, resB] = await Promise.all([
      callAI(PROMPTS.A_Analysis, userInput, cfg),
      callAI(PROMPTS.B_Analysis, userInput, cfg)
    ]);

    // Round 2: Cross-Examination
    const [critiqueA, critiqueB] = await Promise.all([
      callAI(PROMPTS.A_Critique, `Original Essay: ${essay}\nLogic Master's Feedback: ${resB}`, cfg),
      callAI(PROMPTS.B_Critique, `Original Essay: ${essay}\nGrammar Guru's Feedback: ${resA}`, cfg)
    ]);

    // Round 3: Final Verdict
    const synthesisInput = `
Original Topic: ${topic || '(未提供)'}
Original Essay: ${essay}

[Round 1 Analysis]
Grammar Examiner: ${resA}
Logic Examiner: ${resB}

[Round 2 Debate]
Grammar Examiner's Critique: ${critiqueA}
Logic Examiner's Critique: ${critiqueB}

Please provide the final verdict, scores, and revised essay.
    `.trim();

    const resC = await callAI(PROMPTS.C_Final, synthesisInput, cfg);

    // Save to DB
    const saveMsg = db.prepare("INSERT INTO messages (id, session_id, role, content) VALUES (?, ?, ?, ?)");
    const saveMany = db.transaction(() => {
      saveMsg.run(uuidv4(), session_id, 'agentA', resA);
      saveMsg.run(uuidv4(), session_id, 'agentB', resB);
      saveMsg.run(uuidv4(), session_id, 'critiqueA', critiqueA);
      saveMsg.run(uuidv4(), session_id, 'critiqueB', critiqueB);
      saveMsg.run(uuidv4(), session_id, 'agentC', resC);
    });
    saveMany();

    // Update session info
    const title = (topic || essay).slice(0, 40) + '...';
    db.prepare("UPDATE sessions SET topic = ?, essay = ?, title = ?, status = 'done', updated_at = datetime('now') WHERE id = ?")
      .run(topic || '', essay, title, session_id);

    // Increment used_reviews
    if (!user.is_admin) {
      db.prepare("UPDATE users SET used_reviews = used_reviews + 1 WHERE id = ?").run(user.id);
    }

    res.json({ resA, resB, critiqueA, critiqueB, resC });

  } catch (e) {
    console.error('Review error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Chat API ─────────────────────────────────────────────────────────────────
app.post('/api/chat', requireAuth, async (req, res) => {
  const { session_id, messages } = req.body;
  if (!session_id || !messages) return res.status(400).json({ error: '参数缺失' });

  const session = db.prepare("SELECT * FROM sessions WHERE id = ? AND user_id = ?").get(session_id, req.user.id);
  if (!session) return res.status(404).json({ error: '会话不存在' });

  const cfg = getAIConfig();
  if (!cfg.apiKey) return res.status(500).json({ error: '管理员尚未配置 API Key' });

  const body = JSON.stringify({ model: cfg.model, messages, temperature: 0.7 });

  try {
    const reply = await new Promise((resolve, reject) => {
      const url = new URL(`${cfg.apiBase}/chat/completions`);
      const lib = url.protocol === 'https:' ? https : http;
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${cfg.apiKey}`,
          'Content-Length': Buffer.byteLength(body)
        }
      };
      const r = lib.request(options, (response) => {
        let data = '';
        response.on('data', c => data += c);
        response.on('end', () => {
          try {
            const json = JSON.parse(data);
            if (json.error) return reject(new Error(json.error.message));
            resolve(json.choices[0].message.content);
          } catch (e) { reject(e); }
        });
      });
      r.on('error', reject);
      r.write(body);
      r.end();
    });

    // Save user message and reply
    const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
    if (lastUserMsg) {
      db.prepare("INSERT INTO messages (id, session_id, role, content) VALUES (?, ?, 'user', ?)").run(uuidv4(), session_id, lastUserMsg.content);
    }
    db.prepare("INSERT INTO messages (id, session_id, role, content) VALUES (?, ?, 'assistant', ?)").run(uuidv4(), session_id, reply);
    db.prepare("UPDATE sessions SET updated_at = datetime('now') WHERE id = ?").run(session_id);

    res.json({ reply });
  } catch (e) {
    console.error('Chat error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 IELTS Reviewer 服务已启动`);
  console.log(`   访问地址: http://localhost:${PORT}`);
  console.log(`   管理员后台: http://localhost:${PORT}/admin.html`);
  console.log(`   默认管理员: admin / admin123\n`);
});
