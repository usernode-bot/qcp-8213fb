const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

const PUBLIC_API_PATHS = new Set(['/health']);

app.use(express.json());

app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_SECRET) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  }
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

async function requireSessionAdmin(req, res, sessionId) {
  const { rows } = await pool.query('SELECT created_by_user_id FROM sessions WHERE id = $1', [sessionId]);
  if (!rows[0] || rows[0].created_by_user_id !== req.user.id) {
    res.status(403).json({ error: 'Forbidden' });
    return false;
  }
  return true;
}

// GET /api/sessions — list all sessions with stats
app.get('/api/sessions', async (_req, res) => {
  try {
    const { rows: sessions } = await pool.query(`
      SELECT s.id, s.title, s.total_tps, s.status, s.created_by_user_id, s.created_by_username, s.created_at,
        COALESCE(SUM(tv.votes), 0)::int AS total_votes,
        COUNT(DISTINCT tr.id)::int AS tps_reported
      FROM sessions s
      LEFT JOIN tps_reports tr ON tr.session_id = s.id
      LEFT JOIN tps_votes tv ON tv.tps_report_id = tr.id
      GROUP BY s.id
      ORDER BY s.created_at DESC
    `);
    const { rows: candidates } = await pool.query(`
      SELECT id, session_id, name, ballot_number, display_order
      FROM candidates
      ORDER BY session_id, display_order
    `);
    const candsBySession = {};
    for (const c of candidates) {
      if (!candsBySession[c.session_id]) candsBySession[c.session_id] = [];
      candsBySession[c.session_id].push(c);
    }
    res.json({ sessions: sessions.map(s => ({ ...s, candidates: candsBySession[s.id] || [] })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/sessions — create a new session
app.post('/api/sessions', async (req, res) => {
  const { title, total_tps, candidates } = req.body;
  if (!title || !total_tps || !Array.isArray(candidates) || candidates.length < 2) {
    return res.status(400).json({ error: 'title, total_tps, and at least 2 candidates required' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO sessions (title, total_tps, created_by_user_id, created_by_username)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [title.trim(), parseInt(total_tps), req.user.id, req.user.username]
    );
    const sessionId = rows[0].id;
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i];
      if (!c.name || !c.name.trim()) continue;
      await client.query(
        `INSERT INTO candidates (session_id, name, ballot_number, display_order) VALUES ($1, $2, $3, $4)`,
        [sessionId, c.name.trim(), c.ballot_number ? parseInt(c.ballot_number) : null, i]
      );
    }
    await client.query('COMMIT');
    res.json({ session_id: sessionId });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// GET /api/sessions/:id — session detail + candidates
app.get('/api/sessions/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM sessions WHERE id = $1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    const { rows: candidates } = await pool.query(
      'SELECT id, name, ballot_number, display_order FROM candidates WHERE session_id = $1 ORDER BY display_order',
      [req.params.id]
    );
    res.json({ session: rows[0], candidates });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/sessions/:id — close or reopen (admin only)
app.patch('/api/sessions/:id', async (req, res) => {
  try {
    const ok = await requireSessionAdmin(req, res, req.params.id);
    if (!ok) return;
    const { status } = req.body;
    if (!['active', 'closed'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
    await pool.query('UPDATE sessions SET status = $1 WHERE id = $2', [status, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/sessions/:id/stats — live stats for dashboard polling
app.get('/api/sessions/:id/stats', async (req, res) => {
  try {
    const { rows: sessRows } = await pool.query('SELECT * FROM sessions WHERE id = $1', [req.params.id]);
    if (!sessRows[0]) return res.status(404).json({ error: 'Not found' });
    const session = sessRows[0];
    const { rows: candidates } = await pool.query(`
      SELECT c.id, c.name, c.ballot_number, c.display_order,
        COALESCE(SUM(tv.votes), 0)::int AS total_votes
      FROM candidates c
      LEFT JOIN (
        SELECT tv2.candidate_id, tv2.votes
        FROM tps_votes tv2
        JOIN tps_reports tr2 ON tv2.tps_report_id = tr2.id
        WHERE tr2.session_id = $1
      ) tv ON tv.candidate_id = c.id
      WHERE c.session_id = $1
      GROUP BY c.id
      ORDER BY total_votes DESC, c.display_order
    `, [req.params.id]);
    const { rows: countRows } = await pool.query(
      'SELECT COUNT(*)::int AS tps_reported FROM tps_reports WHERE session_id = $1',
      [req.params.id]
    );
    const totalVotes = candidates.reduce((s, c) => s + c.total_votes, 0);
    const candidatesWithPct = candidates.map(c => ({
      ...c,
      pct: totalVotes > 0 ? Math.round((c.total_votes / totalVotes) * 1000) / 10 : 0
    }));
    res.json({
      session,
      candidates: candidatesWithPct,
      tps_reported: countRows[0].tps_reported,
      total_tps: session.total_tps,
      total_votes: totalVotes
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/sessions/:id/reports/check — check if a TPS number already reported
app.get('/api/sessions/:id/reports/check', async (req, res) => {
  const { tps_number } = req.query;
  if (!tps_number) return res.json({ exists: false });
  try {
    const { rows } = await pool.query(
      'SELECT id FROM tps_reports WHERE session_id = $1 AND tps_number = $2',
      [req.params.id, tps_number]
    );
    res.json({ exists: rows.length > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/sessions/:id/reports — submit or update a tally
app.post('/api/sessions/:id/reports', async (req, res) => {
  const { tps_number, votes, notes } = req.body;
  if (!tps_number || !Array.isArray(votes) || votes.length === 0) {
    return res.status(400).json({ error: 'tps_number and votes array required' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: sessRows } = await client.query('SELECT status FROM sessions WHERE id = $1', [req.params.id]);
    if (!sessRows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Session not found' }); }
    if (sessRows[0].status !== 'active') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Session is closed' }); }

    const { rows: reportRows } = await client.query(`
      INSERT INTO tps_reports (session_id, tps_number, submitted_by_user_id, submitted_by_username, notes)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (session_id, tps_number) DO UPDATE SET
        submitted_by_user_id = EXCLUDED.submitted_by_user_id,
        submitted_by_username = EXCLUDED.submitted_by_username,
        notes = EXCLUDED.notes,
        updated_at = NOW()
      RETURNING id
    `, [req.params.id, tps_number.trim(), req.user.id, req.user.username, notes || null]);
    const reportId = reportRows[0].id;

    await client.query('DELETE FROM tps_votes WHERE tps_report_id = $1', [reportId]);
    for (const v of votes) {
      if (v.candidate_id == null) continue;
      await client.query(
        'INSERT INTO tps_votes (tps_report_id, candidate_id, votes) VALUES ($1, $2, $3)',
        [reportId, v.candidate_id, parseInt(v.votes) || 0]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true, report_id: reportId });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// GET /api/sessions/:id/reports — public report list (no notes)
app.get('/api/sessions/:id/reports', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT tr.id, tr.tps_number, tr.submitted_by_username, tr.created_at, tr.updated_at,
        COALESCE(
          json_agg(json_build_object('candidate_id', tv.candidate_id, 'votes', tv.votes)
            ORDER BY tv.candidate_id) FILTER (WHERE tv.id IS NOT NULL),
          '[]'::json
        ) AS votes
      FROM tps_reports tr
      LEFT JOIN tps_votes tv ON tv.tps_report_id = tr.id
      WHERE tr.session_id = $1
      GROUP BY tr.id
      ORDER BY tr.tps_number
    `, [req.params.id]);
    res.json({ reports: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/sessions/:id/admin/reports — admin report list (includes notes)
app.get('/api/sessions/:id/admin/reports', async (req, res) => {
  try {
    const ok = await requireSessionAdmin(req, res, req.params.id);
    if (!ok) return;
    const { rows } = await pool.query(`
      SELECT tr.id, tr.tps_number, tr.submitted_by_username, tr.notes, tr.created_at, tr.updated_at,
        COALESCE(
          json_agg(json_build_object('candidate_id', tv.candidate_id, 'votes', tv.votes)
            ORDER BY tv.candidate_id) FILTER (WHERE tv.id IS NOT NULL),
          '[]'::json
        ) AS votes
      FROM tps_reports tr
      LEFT JOIN tps_votes tv ON tv.tps_report_id = tr.id
      WHERE tr.session_id = $1
      GROUP BY tr.id
      ORDER BY tr.tps_number
    `, [req.params.id]);
    res.json({ reports: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/sessions/:id/reports/:reportId — admin only
app.delete('/api/sessions/:id/reports/:reportId', async (req, res) => {
  try {
    const ok = await requireSessionAdmin(req, res, req.params.id);
    if (!ok) return;
    const { rows } = await pool.query(
      'SELECT id FROM tps_reports WHERE id = $1 AND session_id = $2',
      [req.params.reportId, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Report not found' });
    await pool.query('DELETE FROM tps_reports WHERE id = $1', [req.params.reportId]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/sessions/:id/admin/witnesses — admin only
app.get('/api/sessions/:id/admin/witnesses', async (req, res) => {
  try {
    const ok = await requireSessionAdmin(req, res, req.params.id);
    if (!ok) return;
    const { rows } = await pool.query(`
      SELECT submitted_by_username, COUNT(*)::int AS tps_count, MAX(updated_at) AS last_submitted_at
      FROM tps_reports
      WHERE session_id = $1
      GROUP BY submitted_by_username
      ORDER BY tps_count DESC
    `, [req.params.id]);
    res.json({ witnesses: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  if (!req.user) {
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Usernode</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Usernode</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="https://social-vibecoding.usernodelabs.org" style="display:inline-block;padding:0.5rem 1rem;background:#7c3aed;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Go to Usernode</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      total_tps INTEGER NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_by_user_id INTEGER NOT NULL,
      created_by_username VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS candidates (
      id SERIAL PRIMARY KEY,
      session_id INTEGER NOT NULL REFERENCES sessions(id),
      name VARCHAR(255) NOT NULL,
      ballot_number INTEGER,
      display_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tps_reports (
      id SERIAL PRIMARY KEY,
      session_id INTEGER NOT NULL REFERENCES sessions(id),
      tps_number VARCHAR(50) NOT NULL,
      submitted_by_user_id INTEGER NOT NULL,
      submitted_by_username VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(session_id, tps_number)
    )
  `);
  await pool.query(`ALTER TABLE tps_reports ADD COLUMN IF NOT EXISTS notes TEXT`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tps_votes (
      id SERIAL PRIMARY KEY,
      tps_report_id INTEGER NOT NULL REFERENCES tps_reports(id) ON DELETE CASCADE,
      candidate_id INTEGER NOT NULL REFERENCES candidates(id),
      votes INTEGER NOT NULL DEFAULT 0,
      UNIQUE(tps_report_id, candidate_id)
    )
  `);

  if (IS_STAGING) {
    await seedStagingData();
  }

  app.listen(port, () => console.log(`Listening on :${port}`));
}

async function seedStagingData() {
  await pool.query(`
    INSERT INTO sessions (id, title, total_tps, status, created_by_user_id, created_by_username)
    VALUES
      (9001, 'Staging demo — Pilpres 2024', 50, 'active', 9991, 'demo_admin'),
      (9002, 'Staging demo — Pilkada Kota Demo', 30, 'active', 9991, 'demo_admin'),
      (9003, 'Staging demo — Pilkada 2023 (Closed)', 20, 'closed', 9991, 'demo_admin')
    ON CONFLICT (id) DO NOTHING
  `);
  await pool.query(`
    INSERT INTO candidates (id, session_id, name, ballot_number, display_order)
    VALUES
      (9001, 9001, 'Arif – Budi', 1, 0),
      (9002, 9001, 'Citra – Deni', 2, 1),
      (9003, 9001, 'Eko – Farida', 3, 2),
      (9004, 9002, 'Pasangan A (Gani – Hesti)', 1, 0),
      (9005, 9002, 'Pasangan B (Indra – Joko)', 2, 1),
      (9006, 9003, 'Paslon A (Kiri – Lestari)', 1, 0),
      (9007, 9003, 'Paslon B (Mardi – Nani)', 2, 1)
    ON CONFLICT (id) DO NOTHING
  `);

  // Session 1: 20 TPS reports, ~45/35/20 split
  const s1votes = [
    [112,87,51],[98,76,44],[121,93,56],[105,82,48],[118,91,52],
    [107,83,49],[115,89,53],[102,79,46],[119,92,54],[110,85,50],
    [113,88,51],[108,84,49],[116,90,53],[101,78,46],[122,94,55],
    [103,80,47],[117,91,53],[109,85,50],[120,93,54],[104,81,47]
  ];
  const s1notes = { 4: 'Staging demo — TPS buka terlambat 30 menit', 13: 'Staging demo — Satu kotak suara rusak, sudah diganti' };

  for (let i = 0; i < 20; i++) {
    const tpsNum = `TPS ${String(i + 1).padStart(3, '0')}`;
    const rid = 9001 + i;
    const username = i < 12 ? 'demo_relawan1' : 'demo_relawan2';
    const userId = i < 12 ? 9992 : 9993;
    const notes = s1notes[i] || null;
    await pool.query(
      `INSERT INTO tps_reports (id, session_id, tps_number, submitted_by_user_id, submitted_by_username, notes)
       VALUES ($1, 9001, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING`,
      [rid, tpsNum, userId, username, notes]
    );
    for (let j = 0; j < 3; j++) {
      await pool.query(
        `INSERT INTO tps_votes (tps_report_id, candidate_id, votes) VALUES ($1, $2, $3)
         ON CONFLICT (tps_report_id, candidate_id) DO NOTHING`,
        [rid, 9001 + j, s1votes[i][j]]
      );
    }
  }

  // Session 2: 5 TPS reports
  const s2votes = [[145,128],[138,142],[152,135],[141,138],[149,131]];
  for (let i = 0; i < 5; i++) {
    const tpsNum = `TPS ${String(i + 1).padStart(3, '0')}`;
    const rid = 9021 + i;
    await pool.query(
      `INSERT INTO tps_reports (id, session_id, tps_number, submitted_by_user_id, submitted_by_username)
       VALUES ($1, 9002, $2, 9992, 'demo_relawan1') ON CONFLICT (id) DO NOTHING`,
      [rid, tpsNum]
    );
    for (let j = 0; j < 2; j++) {
      await pool.query(
        `INSERT INTO tps_votes (tps_report_id, candidate_id, votes) VALUES ($1, $2, $3)
         ON CONFLICT (tps_report_id, candidate_id) DO NOTHING`,
        [rid, 9004 + j, s2votes[i][j]]
      );
    }
  }

  // Session 3: 20 TPS reports (fully reported, closed)
  const s3votes = [
    [178,142],[165,155],[183,147],[171,159],[188,142],
    [169,161],[176,154],[162,168],[185,145],[173,157],
    [180,150],[167,163],[184,146],[160,170],[186,144],
    [172,158],[179,151],[166,164],[187,143],[170,160]
  ];
  for (let i = 0; i < 20; i++) {
    const tpsNum = `TPS ${String(i + 1).padStart(3, '0')}`;
    const rid = 9026 + i;
    await pool.query(
      `INSERT INTO tps_reports (id, session_id, tps_number, submitted_by_user_id, submitted_by_username)
       VALUES ($1, 9003, $2, 9992, 'demo_relawan1') ON CONFLICT (id) DO NOTHING`,
      [rid, tpsNum]
    );
    for (let j = 0; j < 2; j++) {
      await pool.query(
        `INSERT INTO tps_votes (tps_report_id, candidate_id, votes) VALUES ($1, $2, $3)
         ON CONFLICT (tps_report_id, candidate_id) DO NOTHING`,
        [rid, 9006 + j, s3votes[i][j]]
      );
    }
  }

  // Advance sequences past seed IDs
  await pool.query(`SELECT setval('sessions_id_seq', GREATEST((SELECT MAX(id) FROM sessions), 1))`);
  await pool.query(`SELECT setval('candidates_id_seq', GREATEST((SELECT MAX(id) FROM candidates), 1))`);
  await pool.query(`SELECT setval('tps_reports_id_seq', GREATEST((SELECT MAX(id) FROM tps_reports), 1))`);
  await pool.query(`SELECT setval('tps_votes_id_seq', GREATEST((SELECT MAX(id) FROM tps_votes), 1))`);
}

start().catch(err => { console.error(err); process.exit(1); });
