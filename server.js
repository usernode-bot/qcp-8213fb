const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

const PUBLIC_API_PATHS = new Set(['/health', '/api/status']);
const PUBLIC_PREFIXES = ['/explorer-api/'];

app.use(express.json());

app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_SECRET) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  }
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (PUBLIC_PREFIXES.some((p) => req.path.startsWith(p))) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/api/status', (_req, res) => res.json({ isStaging: IS_STAGING }));

async function requireAdmin(req, res, next) {
  try {
    const { rows: countRows } = await pool.query('SELECT COUNT(*) as count FROM admins');
    if (parseInt(countRows[0].count) === 0) {
      await pool.query(
        'INSERT INTO admins (user_id, username, added_by_username) VALUES ($1, $2, $3) ON CONFLICT (username) DO UPDATE SET user_id = EXCLUDED.user_id',
        [req.user.id, req.user.username, 'system']
      );
      return next();
    }
    const { rows } = await pool.query('SELECT id FROM admins WHERE user_id = $1', [req.user.id]);
    if (rows.length > 0) return next();
    const { rows: byUser } = await pool.query('SELECT id FROM admins WHERE username = $1 AND user_id IS NULL', [req.user.username]);
    if (byUser.length > 0) {
      await pool.query('UPDATE admins SET user_id = $1 WHERE username = $2 AND user_id IS NULL', [req.user.id, req.user.username]);
      return next();
    }
    return res.status(403).json({ error: 'Admin access required' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

function buildVoteMap(rows) {
  const m = {};
  for (const v of rows) {
    if (!m[v.geo_id]) m[v.geo_id] = {};
    m[v.geo_id][v.candidate_id] = parseInt(v.total_votes);
  }
  return m;
}

// ---- Active election ----

app.get('/api/elections/active', async (req, res) => {
  try {
    const { rows: electionRows } = await pool.query(
      "SELECT * FROM elections WHERE status = 'active' ORDER BY created_at DESC LIMIT 1"
    );
    if (!electionRows.length) return res.json({ election: null, candidates: [] });
    const { rows: candidates } = await pool.query(
      'SELECT * FROM candidates WHERE election_id = $1 ORDER BY sequence_number',
      [electionRows[0].id]
    );
    res.json({ election: electionRows[0], candidates });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- National results ----

app.get('/api/results', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json({ election_id: null, total_tps: 0, reported_tps: 0, votes: [] });
    const eid = er[0].id;

    const { rows: totals } = await pool.query(`
      SELECT
        COUNT(DISTINCT t.id) as total_tps,
        COUNT(DISTINCT te.tps_id) as reported_tps
      FROM tps t
      LEFT JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1 AND te.status = 'confirmed'
    `, [eid]);

    const { rows: votes } = await pool.query(`
      SELECT tev.candidate_id, SUM(tev.votes)::integer as total_votes
      FROM tps_entries te
      JOIN tps_entry_votes tev ON tev.entry_id = te.id
      WHERE te.election_id = $1 AND te.status = 'confirmed'
      GROUP BY tev.candidate_id
    `, [eid]);

    res.json({
      election_id: eid,
      total_tps: parseInt(totals[0].total_tps),
      reported_tps: parseInt(totals[0].reported_tps),
      votes
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/results/provinces', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json([]);
    const eid = er[0].id;

    const { rows } = await pool.query(`
      SELECT p.id, p.name, p.code,
        COUNT(DISTINCT t.id) as total_tps,
        COUNT(DISTINCT CASE WHEN te.status = 'confirmed' THEN te.tps_id END) as reported_tps
      FROM geo_provinces p
      LEFT JOIN geo_cities c ON c.province_id = p.id
      LEFT JOIN geo_districts d ON d.city_id = c.id
      LEFT JOIN tps t ON t.district_id = d.id
      LEFT JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1
      GROUP BY p.id, p.name, p.code
      ORDER BY p.name
    `, [eid]);

    const { rows: votes } = await pool.query(`
      SELECT p.id as geo_id, tev.candidate_id, SUM(tev.votes)::integer as total_votes
      FROM geo_provinces p
      JOIN geo_cities c ON c.province_id = p.id
      JOIN geo_districts d ON d.city_id = c.id
      JOIN tps t ON t.district_id = d.id
      JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1 AND te.status = 'confirmed'
      JOIN tps_entry_votes tev ON tev.entry_id = te.id
      GROUP BY p.id, tev.candidate_id
    `, [eid]);

    const vm = buildVoteMap(votes);
    res.json(rows.map(r => ({ ...r, total_tps: parseInt(r.total_tps), reported_tps: parseInt(r.reported_tps), votes: vm[r.id] || {} })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/results/provinces/:id', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json({ province: null, cities: [] });
    const eid = er[0].id;

    const { rows: pRows } = await pool.query('SELECT * FROM geo_provinces WHERE id = $1', [req.params.id]);
    if (!pRows.length) return res.status(404).json({ error: 'Not found' });

    const { rows: cities } = await pool.query(`
      SELECT c.id, c.name, c.code,
        COUNT(DISTINCT t.id) as total_tps,
        COUNT(DISTINCT CASE WHEN te.status = 'confirmed' THEN te.tps_id END) as reported_tps
      FROM geo_cities c
      LEFT JOIN geo_districts d ON d.city_id = c.id
      LEFT JOIN tps t ON t.district_id = d.id
      LEFT JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1
      WHERE c.province_id = $2
      GROUP BY c.id, c.name, c.code
      ORDER BY c.name
    `, [eid, req.params.id]);

    const { rows: votes } = await pool.query(`
      SELECT c.id as geo_id, tev.candidate_id, SUM(tev.votes)::integer as total_votes
      FROM geo_cities c
      JOIN geo_districts d ON d.city_id = c.id
      JOIN tps t ON t.district_id = d.id
      JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1 AND te.status = 'confirmed'
      JOIN tps_entry_votes tev ON tev.entry_id = te.id
      WHERE c.province_id = $2
      GROUP BY c.id, tev.candidate_id
    `, [eid, req.params.id]);

    const vm = buildVoteMap(votes);
    res.json({
      province: pRows[0],
      cities: cities.map(r => ({ ...r, total_tps: parseInt(r.total_tps), reported_tps: parseInt(r.reported_tps), votes: vm[r.id] || {} }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/results/cities/:id', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json({ city: null, districts: [] });
    const eid = er[0].id;

    const { rows: cRows } = await pool.query(
      'SELECT c.*, p.name as province_name, p.id as province_id FROM geo_cities c JOIN geo_provinces p ON p.id = c.province_id WHERE c.id = $1',
      [req.params.id]
    );
    if (!cRows.length) return res.status(404).json({ error: 'Not found' });

    const { rows: districts } = await pool.query(`
      SELECT d.id, d.name, d.code,
        COUNT(DISTINCT t.id) as total_tps,
        COUNT(DISTINCT CASE WHEN te.status = 'confirmed' THEN te.tps_id END) as reported_tps
      FROM geo_districts d
      LEFT JOIN tps t ON t.district_id = d.id
      LEFT JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1
      WHERE d.city_id = $2
      GROUP BY d.id, d.name, d.code
      ORDER BY d.name
    `, [eid, req.params.id]);

    const { rows: votes } = await pool.query(`
      SELECT d.id as geo_id, tev.candidate_id, SUM(tev.votes)::integer as total_votes
      FROM geo_districts d
      JOIN tps t ON t.district_id = d.id
      JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1 AND te.status = 'confirmed'
      JOIN tps_entry_votes tev ON tev.entry_id = te.id
      WHERE d.city_id = $2
      GROUP BY d.id, tev.candidate_id
    `, [eid, req.params.id]);

    const vm = buildVoteMap(votes);
    res.json({
      city: cRows[0],
      districts: districts.map(r => ({ ...r, total_tps: parseInt(r.total_tps), reported_tps: parseInt(r.reported_tps), votes: vm[r.id] || {} }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/results/districts/:id', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json({ district: null, tps_list: [] });
    const eid = er[0].id;

    const { rows: dRows } = await pool.query(`
      SELECT d.*, c.name as city_name, c.id as city_id, p.name as province_name, p.id as province_id
      FROM geo_districts d
      JOIN geo_cities c ON c.id = d.city_id
      JOIN geo_provinces p ON p.id = c.province_id
      WHERE d.id = $1
    `, [req.params.id]);
    if (!dRows.length) return res.status(404).json({ error: 'Not found' });

    const { rows: tpsList } = await pool.query(`
      SELECT t.id, t.number, t.registered_voters,
        te.id as entry_id, te.status as entry_status,
        te.submitted_by_username, te.photo_url, te.confirmed_by_username
      FROM tps t
      LEFT JOIN LATERAL (
        SELECT * FROM tps_entries
        WHERE tps_id = t.id AND election_id = $1 AND status IN ('pending','confirmed')
        ORDER BY submitted_at DESC LIMIT 1
      ) te ON true
      WHERE t.district_id = $2
      ORDER BY t.number
    `, [eid, req.params.id]);

    const entryIds = tpsList.filter(t => t.entry_id && t.entry_status === 'confirmed').map(t => t.entry_id);
    let voteMap = {};
    if (entryIds.length > 0) {
      const { rows: voteRows } = await pool.query(
        'SELECT entry_id, candidate_id, votes FROM tps_entry_votes WHERE entry_id = ANY($1)',
        [entryIds]
      );
      for (const v of voteRows) {
        if (!voteMap[v.entry_id]) voteMap[v.entry_id] = {};
        voteMap[v.entry_id][v.candidate_id] = parseInt(v.votes);
      }
    }

    res.json({
      district: dRows[0],
      tps_list: tpsList.map(t => ({ ...t, votes: t.entry_id ? (voteMap[t.entry_id] || {}) : {} }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Geography cascades ----

app.get('/api/geo/provinces', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, code, name FROM geo_provinces ORDER BY name');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/geo/provinces/:id/cities', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, code, name FROM geo_cities WHERE province_id = $1 ORDER BY name', [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/geo/cities/:id/districts', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, code, name FROM geo_districts WHERE city_id = $1 ORDER BY name', [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/geo/districts/:id/tps', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, number, registered_voters FROM tps WHERE district_id = $1 ORDER BY number', [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tps/:id/status', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json({ entry: null, election_id: null, is_own_entry: false });
    const eid = er[0].id;

    const { rows } = await pool.query(
      "SELECT * FROM tps_entries WHERE tps_id = $1 AND election_id = $2 AND status IN ('pending','confirmed') ORDER BY submitted_at DESC LIMIT 1",
      [req.params.id, eid]
    );
    if (!rows.length) return res.json({ entry: null, election_id: eid, is_own_entry: false });

    const entry = rows[0];
    let votes = [];
    if (entry.status === 'confirmed') {
      const { rows: voteRows } = await pool.query('SELECT candidate_id, votes FROM tps_entry_votes WHERE entry_id = $1', [entry.id]);
      votes = voteRows;
    } else if (entry.status === 'pending') {
      const { rows: voteRows } = await pool.query('SELECT candidate_id, votes FROM tps_entry_votes WHERE entry_id = $1', [entry.id]);
      votes = voteRows;
    }
    res.json({ entry, votes, election_id: eid, is_own_entry: entry.submitted_by_user_id === req.user.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Entries ----

app.get('/api/entries/pending', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT te.id, te.tps_id, te.election_id, te.status, te.photo_url, te.notes,
        te.submitted_by_user_id, te.submitted_by_username, te.submitted_at,
        t.number as tps_number, d.name as district_name, d.id as district_id,
        c.name as city_name, p.name as province_name,
        COALESCE(json_agg(json_build_object('candidate_id', tev.candidate_id, 'votes', tev.votes)) FILTER (WHERE tev.id IS NOT NULL), '[]') as votes
      FROM tps_entries te
      JOIN tps t ON t.id = te.tps_id
      JOIN geo_districts d ON d.id = t.district_id
      JOIN geo_cities c ON c.id = d.city_id
      JOIN geo_provinces p ON p.id = c.province_id
      LEFT JOIN tps_entry_votes tev ON tev.entry_id = te.id
      WHERE te.status = 'pending'
      GROUP BY te.id, t.number, d.name, d.id, c.name, p.name
      ORDER BY te.submitted_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/entries/mine', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT te.id, te.tps_id, te.election_id, te.status, te.submitted_at, te.confirmed_at,
        t.number as tps_number, d.name as district_name, c.name as city_name, p.name as province_name
      FROM tps_entries te
      JOIN tps t ON t.id = te.tps_id
      JOIN geo_districts d ON d.id = t.district_id
      JOIN geo_cities c ON c.id = d.city_id
      JOIN geo_provinces p ON p.id = c.province_id
      WHERE te.submitted_by_user_id = $1
      ORDER BY te.submitted_at DESC
      LIMIT 50
    `, [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/entries', async (req, res) => {
  const { tps_id, election_id, votes, photo_url, notes } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: er } = await client.query('SELECT status FROM elections WHERE id = $1', [election_id]);
    if (!er.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Election not found' }); }
    if (er[0].status === 'completed') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Election is completed; submissions are closed.' }); }

    const { rows: existing } = await client.query(
      "SELECT * FROM tps_entries WHERE tps_id = $1 AND election_id = $2 AND status IN ('pending','confirmed')",
      [tps_id, election_id]
    );
    if (existing.length > 0) {
      const e = existing[0];
      if (e.status === 'confirmed') {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'This TPS has already been confirmed.' });
      }
      if (e.submitted_by_user_id !== req.user.id) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'A pending entry already exists for this TPS; confirm or reject it first.' });
      }
      await client.query("UPDATE tps_entries SET status = 'withdrawn' WHERE id = $1", [e.id]);
    }

    const { rows: newEntry } = await client.query(
      `INSERT INTO tps_entries (tps_id, election_id, submitted_by_user_id, submitted_by_username, status, photo_url, notes, submitted_at)
       VALUES ($1, $2, $3, $4, 'pending', $5, $6, NOW()) RETURNING *`,
      [tps_id, election_id, req.user.id, req.user.username, photo_url || null, notes || null]
    );
    for (const v of (votes || [])) {
      await client.query(
        'INSERT INTO tps_entry_votes (entry_id, candidate_id, votes) VALUES ($1, $2, $3)',
        [newEntry[0].id, v.candidate_id, v.votes]
      );
    }
    await client.query('COMMIT');
    res.json({ entry: newEntry[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/entries/:id/withdraw', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tps_entries WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].submitted_by_user_id !== req.user.id) return res.status(403).json({ error: 'Not your entry' });
    if (rows[0].status !== 'pending') return res.status(409).json({ error: 'Can only withdraw pending entries' });
    await pool.query("UPDATE tps_entries SET status = 'withdrawn' WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/entries/:id/confirm', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tps_entries WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].submitted_by_user_id === req.user.id) return res.status(403).json({ error: 'Cannot confirm your own entry' });
    if (rows[0].status !== 'pending') return res.status(409).json({ error: 'Entry is not pending' });
    await pool.query(
      "UPDATE tps_entries SET status = 'confirmed', confirmed_by_user_id = $1, confirmed_by_username = $2, confirmed_at = NOW() WHERE id = $3",
      [req.user.id, req.user.username, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/entries/:id/reject', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tps_entries WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].submitted_by_user_id === req.user.id) return res.status(403).json({ error: 'Cannot reject your own entry' });
    if (rows[0].status !== 'pending') return res.status(409).json({ error: 'Entry is not pending' });
    await pool.query("UPDATE tps_entries SET status = 'rejected' WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Admin ----

app.get('/api/admin/check', async (req, res) => {
  try {
    const { rows: countRows } = await pool.query('SELECT COUNT(*) as count FROM admins');
    if (parseInt(countRows[0].count) === 0) return res.json({ isAdmin: true });
    const { rows } = await pool.query('SELECT id FROM admins WHERE user_id = $1', [req.user.id]);
    if (rows.length > 0) return res.json({ isAdmin: true });
    const { rows: byUser } = await pool.query('SELECT id FROM admins WHERE username = $1', [req.user.username]);
    res.json({ isAdmin: byUser.length > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/elections', requireAdmin, async (req, res) => {
  const { name, description, status } = req.body;
  try {
    if (status === 'active') {
      await pool.query("UPDATE elections SET status = 'inactive' WHERE status = 'active'");
    }
    const { rows } = await pool.query(
      'INSERT INTO elections (name, description, status, created_by_user_id, created_by_username) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description || '', status || 'active', req.user.id, req.user.username]
    );
    res.json({ election: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/elections/:id', requireAdmin, async (req, res) => {
  const { name, description, status } = req.body;
  try {
    const { rows } = await pool.query(
      'UPDATE elections SET name = COALESCE($1, name), description = COALESCE($2, description), status = COALESCE($3, status) WHERE id = $4 RETURNING *',
      [name, description, status, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ election: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/candidates', requireAdmin, async (req, res) => {
  const { election_id, sequence_number, name, running_mate, photo_url, color } = req.body;
  try {
    const { rows } = await pool.query(
      'INSERT INTO candidates (election_id, sequence_number, name, running_mate, photo_url, color) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [election_id, sequence_number, name, running_mate || null, photo_url || null, color || '#3b82f6']
    );
    res.json({ candidate: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/candidates/:id', requireAdmin, async (req, res) => {
  const { sequence_number, name, running_mate, photo_url, color } = req.body;
  try {
    const { rows } = await pool.query(
      'UPDATE candidates SET sequence_number = COALESCE($1, sequence_number), name = COALESCE($2, name), running_mate = COALESCE($3, running_mate), photo_url = COALESCE($4, photo_url), color = COALESCE($5, color) WHERE id = $6 RETURNING *',
      [sequence_number, name, running_mate, photo_url, color, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ candidate: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/candidates/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM candidates WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/geo/provinces', requireAdmin, async (req, res) => {
  const { code, name } = req.body;
  try {
    const { rows } = await pool.query('INSERT INTO geo_provinces (code, name) VALUES ($1, $2) RETURNING *', [code, name]);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/geo/cities', requireAdmin, async (req, res) => {
  const { province_id, code, name } = req.body;
  try {
    const { rows } = await pool.query('INSERT INTO geo_cities (province_id, code, name) VALUES ($1, $2, $3) RETURNING *', [province_id, code, name]);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/geo/districts', requireAdmin, async (req, res) => {
  const { city_id, code, name } = req.body;
  try {
    const { rows } = await pool.query('INSERT INTO geo_districts (city_id, code, name) VALUES ($1, $2, $3) RETURNING *', [city_id, code, name]);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/geo/tps', requireAdmin, async (req, res) => {
  const { district_id, number, registered_voters } = req.body;
  try {
    const { rows } = await pool.query(
      'INSERT INTO tps (district_id, number, registered_voters) VALUES ($1, $2, $3) RETURNING *',
      [district_id, number, registered_voters || null]
    );
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/seed-geo', requireAdmin, async (req, res) => {
  if (!IS_STAGING) return res.status(400).json({ error: 'Only available in staging' });
  try {
    await seedDemoData();
    res.json({ ok: true, message: 'Demo geography seeded' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/admins', requireAdmin, async (req, res) => {
  const { username } = req.body;
  try {
    await pool.query(
      'INSERT INTO admins (username, added_by_username) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING',
      [username, req.user.username]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/entries', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT te.id, te.tps_id, te.election_id, te.status, te.photo_url, te.notes,
        te.submitted_by_user_id, te.submitted_by_username, te.submitted_at,
        te.confirmed_by_user_id, te.confirmed_by_username, te.confirmed_at,
        t.number as tps_number, d.name as district_name,
        c.name as city_name, p.name as province_name,
        COALESCE(json_agg(json_build_object('candidate_id', tev.candidate_id, 'votes', tev.votes)) FILTER (WHERE tev.id IS NOT NULL), '[]') as votes
      FROM tps_entries te
      JOIN tps t ON t.id = te.tps_id
      JOIN geo_districts d ON d.id = t.district_id
      JOIN geo_cities c ON c.id = d.city_id
      JOIN geo_provinces p ON p.id = c.province_id
      LEFT JOIN tps_entry_votes tev ON tev.entry_id = te.id
      GROUP BY te.id, t.number, d.name, c.name, p.name
      ORDER BY te.submitted_at DESC
      LIMIT 200
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/entries/:id/confirm', requireAdmin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE tps_entries SET status = 'confirmed', confirmed_by_user_id = $1, confirmed_by_username = $2, confirmed_at = NOW() WHERE id = $3 AND status = 'pending'",
      [req.user.id, req.user.username, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/entries/:id/reject', requireAdmin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE tps_entries SET status = 'rejected' WHERE id = $1 AND status = 'pending'",
      [req.params.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/entries/:id/reset', requireAdmin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE tps_entries SET status = 'pending', confirmed_by_user_id = NULL, confirmed_by_username = NULL, confirmed_at = NULL WHERE id = $1",
      [req.params.id]
    );
    res.json({ ok: true });
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

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS elections (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      description TEXT DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_by_user_id INTEGER,
      created_by_username VARCHAR(255),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS candidates (
      id SERIAL PRIMARY KEY,
      election_id INTEGER NOT NULL REFERENCES elections(id),
      sequence_number INTEGER NOT NULL,
      name VARCHAR(255) NOT NULL,
      running_mate VARCHAR(255),
      photo_url TEXT,
      color VARCHAR(20) DEFAULT '#3b82f6'
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS geo_provinces (
      id SERIAL PRIMARY KEY,
      code VARCHAR(20) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS geo_cities (
      id SERIAL PRIMARY KEY,
      province_id INTEGER NOT NULL REFERENCES geo_provinces(id),
      code VARCHAR(20) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS geo_districts (
      id SERIAL PRIMARY KEY,
      city_id INTEGER NOT NULL REFERENCES geo_cities(id),
      code VARCHAR(20) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tps (
      id SERIAL PRIMARY KEY,
      district_id INTEGER NOT NULL REFERENCES geo_districts(id),
      number VARCHAR(10) NOT NULL,
      registered_voters INTEGER,
      UNIQUE (district_id, number)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tps_entries (
      id SERIAL PRIMARY KEY,
      tps_id INTEGER NOT NULL REFERENCES tps(id),
      election_id INTEGER NOT NULL REFERENCES elections(id),
      submitted_by_user_id INTEGER,
      submitted_by_username VARCHAR(255),
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      photo_url TEXT,
      notes TEXT,
      submitted_at TIMESTAMPTZ DEFAULT NOW(),
      confirmed_by_user_id INTEGER,
      confirmed_by_username VARCHAR(255),
      confirmed_at TIMESTAMPTZ
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_tps_entries_election_status ON tps_entries(election_id, status)
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tps_entry_votes (
      id SERIAL PRIMARY KEY,
      entry_id INTEGER NOT NULL REFERENCES tps_entries(id),
      candidate_id INTEGER NOT NULL REFERENCES candidates(id),
      votes INTEGER NOT NULL DEFAULT 0
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_tps_entry_votes_entry ON tps_entry_votes(entry_id)
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username VARCHAR(255) NOT NULL UNIQUE,
      added_by_username VARCHAR(255),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS admins_user_id_unique ON admins(user_id) WHERE user_id IS NOT NULL
  `);
}

async function seedDemoData() {
  const { rows: existing } = await pool.query(
    "SELECT id FROM elections WHERE name = 'Pemilihan Presiden Staging 2029' LIMIT 1"
  );
  if (existing.length > 0) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: [elec] } = await client.query(
      "INSERT INTO elections (name, description, status, created_by_user_id, created_by_username) VALUES ('Pemilihan Presiden Staging 2029', 'Demo election for staging environment', 'active', 0, 'staging-seed-user') RETURNING id"
    );
    const eid = elec.id;

    const CANDIDATES = [
      { seq: 1, name: 'Budi Santoso', mate: 'Dewi Rahayu', color: '#3b82f6', photo: 'https://ui-avatars.com/api/?name=Budi+Santoso&background=3b82f6&color=fff&size=128' },
      { seq: 2, name: 'Agus Wijaya', mate: 'Sri Mulyani', color: '#ef4444', photo: 'https://ui-avatars.com/api/?name=Agus+Wijaya&background=ef4444&color=fff&size=128' },
      { seq: 3, name: 'Cahyo Prabowo', mate: 'Rina Susanti', color: '#22c55e', photo: 'https://ui-avatars.com/api/?name=Cahyo+Prabowo&background=22c55e&color=fff&size=128' },
    ];
    const candidateIds = [];
    for (const c of CANDIDATES) {
      const { rows: [row] } = await client.query(
        'INSERT INTO candidates (election_id, sequence_number, name, running_mate, photo_url, color) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
        [eid, c.seq, c.name, c.mate, c.photo, c.color]
      );
      candidateIds.push(row.id);
    }

    const { rows: [pA] } = await client.query("INSERT INTO geo_provinces (code, name) VALUES ('ST-A', 'Staging Provinsi Alpha') RETURNING id");
    const { rows: [pB] } = await client.query("INSERT INTO geo_provinces (code, name) VALUES ('ST-B', 'Staging Provinsi Beta') RETURNING id");

    const cityIds = {};
    const cityDefs = [
      { pId: pA.id, code: 'ST-A-1', name: 'Staging Kota Alpha-1' },
      { pId: pA.id, code: 'ST-A-2', name: 'Staging Kota Alpha-2' },
      { pId: pB.id, code: 'ST-B-1', name: 'Staging Kota Beta-1' },
      { pId: pB.id, code: 'ST-B-2', name: 'Staging Kota Beta-2' },
    ];
    for (const cd of cityDefs) {
      const { rows: [row] } = await client.query(
        'INSERT INTO geo_cities (province_id, code, name) VALUES ($1, $2, $3) RETURNING id',
        [cd.pId, cd.code, cd.name]
      );
      cityIds[cd.code] = row.id;
    }

    const districtIds = {};
    const districtDefs = [
      { cCode: 'ST-A-1', code: 'ST-A-1-1', name: 'Staging Kecamatan Alpha-1-1' },
      { cCode: 'ST-A-1', code: 'ST-A-1-2', name: 'Staging Kecamatan Alpha-1-2' },
      { cCode: 'ST-A-2', code: 'ST-A-2-1', name: 'Staging Kecamatan Alpha-2-1' },
      { cCode: 'ST-A-2', code: 'ST-A-2-2', name: 'Staging Kecamatan Alpha-2-2' },
      { cCode: 'ST-B-1', code: 'ST-B-1-1', name: 'Staging Kecamatan Beta-1-1' },
      { cCode: 'ST-B-1', code: 'ST-B-1-2', name: 'Staging Kecamatan Beta-1-2' },
      { cCode: 'ST-B-2', code: 'ST-B-2-1', name: 'Staging Kecamatan Beta-2-1' },
      { cCode: 'ST-B-2', code: 'ST-B-2-2', name: 'Staging Kecamatan Beta-2-2' },
    ];
    for (const dd of districtDefs) {
      const { rows: [row] } = await client.query(
        'INSERT INTO geo_districts (city_id, code, name) VALUES ($1, $2, $3) RETURNING id',
        [cityIds[dd.cCode], dd.code, dd.name]
      );
      districtIds[dd.code] = row.id;
    }

    const tpsIds = {};
    for (const [code, did] of Object.entries(districtIds)) {
      tpsIds[code] = [];
      for (let n = 1; n <= 5; n++) {
        const num = String(n).padStart(3, '0');
        const { rows: [row] } = await client.query(
          'INSERT INTO tps (district_id, number, registered_voters) VALUES ($1, $2, 300) RETURNING id',
          [did, num]
        );
        tpsIds[code].push(row.id);
      }
    }

    // 10 confirmed entries across Alpha districts
    const confirmedDists = ['ST-A-1-1', 'ST-A-1-2'];
    const confirmedVotes = [
      [120, 105, 65], [115, 110, 70], [130, 95, 60], [100, 125, 65], [125, 100, 70],
      [110, 115, 60], [135, 90, 65], [105, 120, 70], [120, 105, 60], [115, 110, 65]
    ];
    let confIdx = 0;
    for (const dCode of confirmedDists) {
      for (const tpsId of tpsIds[dCode]) {
        const vd = confirmedVotes[confIdx++];
        const { rows: [entry] } = await client.query(
          `INSERT INTO tps_entries (tps_id, election_id, submitted_by_user_id, submitted_by_username, status, submitted_at, confirmed_by_user_id, confirmed_by_username, confirmed_at)
           VALUES ($1, $2, 0, 'staging-seed-user', 'confirmed', NOW(), -1, 'staging-seed-confirmer', NOW()) RETURNING id`,
          [tpsId, eid]
        );
        for (let i = 0; i < candidateIds.length; i++) {
          await client.query(
            'INSERT INTO tps_entry_votes (entry_id, candidate_id, votes) VALUES ($1, $2, $3)',
            [entry.id, candidateIds[i], vd[i]]
          );
        }
      }
    }

    // 3 pending entries in Beta district ST-B-1-1
    const pendingVotes = [[90, 100, 80], [95, 105, 75], [100, 95, 80]];
    for (let i = 0; i < 3; i++) {
      const tpsId = tpsIds['ST-B-1-1'][i];
      const vd = pendingVotes[i];
      const { rows: [entry] } = await client.query(
        `INSERT INTO tps_entries (tps_id, election_id, submitted_by_user_id, submitted_by_username, status, submitted_at)
         VALUES ($1, $2, 0, 'staging-seed-user', 'pending', NOW()) RETURNING id`,
        [tpsId, eid]
      );
      for (let j = 0; j < candidateIds.length; j++) {
        await client.query(
          'INSERT INTO tps_entry_votes (entry_id, candidate_id, votes) VALUES ($1, $2, $3)',
          [entry.id, candidateIds[j], vd[j]]
        );
      }
    }

    await client.query('COMMIT');
    console.log('Staging demo data seeded');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function start() {
  await migrate();
  if (IS_STAGING) {
    await seedDemoData().catch(err => console.error('Seed error:', err));
  }
  app.listen(port, () => console.log(`Listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
