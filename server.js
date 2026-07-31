const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const USERNODE_JWT_PUBLIC_KEY = process.env.USERNODE_JWT_PUBLIC_KEY;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

const PUBLIC_API_PATHS = new Set([
  '/health', '/api/status', '/favicon.ico',
  '/api/results/trend', '/api/anomalies', '/api/audit-log', '/api/results/compare',
]);
const PUBLIC_PREFIXES = ['/explorer-api/', '/api/public/'];

app.use(express.json());

app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && USERNODE_JWT_PUBLIC_KEY) {
    try {
      const payload = jwt.verify(token, USERNODE_JWT_PUBLIC_KEY, {
        algorithms: ['RS256'],
        issuer: 'usernode',
        audience: 'usernode:app:' + process.env.USERNODE_APP_ID,
      });
      if (payload.pur === 'iframe') req.user = payload;
    } catch {}
  }
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (PUBLIC_PREFIXES.some((p) => req.path.startsWith(p))) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/favicon.ico', (_req, res) => res.status(204).end());
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

async function logAudit(action, entityType, entityId, tpsId, actorUsername, metadata) {
  try {
    await pool.query(
      `INSERT INTO audit_log (action, entity_type, entity_id, tps_id, actor_username, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [action, entityType, entityId, tpsId, actorUsername, JSON.stringify(metadata || {})]
    );
  } catch (err) {
    console.error('Audit log error:', err.message);
  }
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
    if (!er.length) return res.json({ election_id: null, total_tps: 0, reported_tps: 0, pending_count: 0, votes: [] });
    const eid = er[0].id;

    const { rows: totals } = await pool.query(`
      SELECT
        COUNT(DISTINCT t.id) as total_tps,
        COUNT(DISTINCT te.tps_id) FILTER (WHERE te.status = 'confirmed') as reported_tps,
        COUNT(te.id) FILTER (WHERE te.status = 'pending') as pending_count
      FROM tps t
      LEFT JOIN tps_entries te ON te.tps_id = t.id AND te.election_id = $1
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
      pending_count: parseInt(totals[0].pending_count),
      votes,
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
        COUNT(DISTINCT CASE WHEN te.status = 'confirmed' THEN te.tps_id END) as reported_tps,
        COUNT(DISTINCT CASE WHEN te.status = 'flagged' THEN te.tps_id END) as flagged_count,
        COUNT(DISTINCT CASE WHEN te.status = 'disputed' THEN te.tps_id END) as disputed_count
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
    res.json(rows.map(r => ({
      ...r,
      total_tps: parseInt(r.total_tps),
      reported_tps: parseInt(r.reported_tps),
      flagged_count: parseInt(r.flagged_count),
      disputed_count: parseInt(r.disputed_count),
      votes: vm[r.id] || {},
    })));
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
        COUNT(DISTINCT CASE WHEN te.status = 'confirmed' THEN te.tps_id END) as reported_tps,
        COUNT(DISTINCT CASE WHEN te.status = 'flagged' THEN te.tps_id END) as flagged_count,
        COUNT(DISTINCT CASE WHEN te.status = 'disputed' THEN te.tps_id END) as disputed_count
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
      cities: cities.map(r => ({
        ...r,
        total_tps: parseInt(r.total_tps),
        reported_tps: parseInt(r.reported_tps),
        flagged_count: parseInt(r.flagged_count),
        disputed_count: parseInt(r.disputed_count),
        votes: vm[r.id] || {},
      })),
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
        COUNT(DISTINCT CASE WHEN te.status = 'confirmed' THEN te.tps_id END) as reported_tps,
        COUNT(DISTINCT CASE WHEN te.status = 'flagged' THEN te.tps_id END) as flagged_count,
        COUNT(DISTINCT CASE WHEN te.status = 'disputed' THEN te.tps_id END) as disputed_count
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
      districts: districts.map(r => ({
        ...r,
        total_tps: parseInt(r.total_tps),
        reported_tps: parseInt(r.reported_tps),
        flagged_count: parseInt(r.flagged_count),
        disputed_count: parseInt(r.disputed_count),
        votes: vm[r.id] || {},
      })),
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
        WHERE tps_id = t.id AND election_id = $1
          AND status IN ('pending','confirmed','flagged','disputed')
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
      tps_list: tpsList.map(t => ({ ...t, votes: t.entry_id ? (voteMap[t.entry_id] || {}) : {} })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Results trend (public) ----

app.get('/api/results/trend', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json([]);
    const eid = er[0].id;

    const { rows } = await pool.query(`
      SELECT DATE_TRUNC('hour', confirmed_at) as hour, COUNT(*)::integer as count
      FROM tps_entries
      WHERE election_id = $1 AND status = 'confirmed'
        AND confirmed_at >= NOW() - INTERVAL '24 hours'
      GROUP BY hour
      ORDER BY hour
    `, [eid]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Results compare (public) ----

app.get('/api/results/compare', async (req, res) => {
  const { aType, aId, bType, bId } = req.query;
  if (!aType || !aId || !bType || !bId) return res.status(400).json({ error: 'Missing params' });

  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json({ a: null, b: null });
    const eid = er[0].id;

    async function fetchSide(type, id) {
      let nameQ, tpsQ, votesQ;
      if (type === 'province') {
        nameQ = { text: 'SELECT name FROM geo_provinces WHERE id=$1', values: [id] };
        tpsQ = {
          text: `SELECT COUNT(DISTINCT t.id) as total_tps,
            COUNT(DISTINCT CASE WHEN te.status='confirmed' THEN te.tps_id END) as reported_tps
            FROM geo_provinces p
            JOIN geo_cities c ON c.province_id=p.id
            JOIN geo_districts d ON d.city_id=c.id
            JOIN tps t ON t.district_id=d.id
            LEFT JOIN tps_entries te ON te.tps_id=t.id AND te.election_id=$2
            WHERE p.id=$1`,
          values: [id, eid],
        };
        votesQ = {
          text: `SELECT tev.candidate_id, SUM(tev.votes)::integer as total_votes
            FROM geo_provinces p
            JOIN geo_cities c ON c.province_id=p.id
            JOIN geo_districts d ON d.city_id=c.id
            JOIN tps t ON t.district_id=d.id
            JOIN tps_entries te ON te.tps_id=t.id AND te.election_id=$2 AND te.status='confirmed'
            JOIN tps_entry_votes tev ON tev.entry_id=te.id
            WHERE p.id=$1
            GROUP BY tev.candidate_id`,
          values: [id, eid],
        };
      } else if (type === 'city') {
        nameQ = { text: 'SELECT name FROM geo_cities WHERE id=$1', values: [id] };
        tpsQ = {
          text: `SELECT COUNT(DISTINCT t.id) as total_tps,
            COUNT(DISTINCT CASE WHEN te.status='confirmed' THEN te.tps_id END) as reported_tps
            FROM geo_cities c
            JOIN geo_districts d ON d.city_id=c.id
            JOIN tps t ON t.district_id=d.id
            LEFT JOIN tps_entries te ON te.tps_id=t.id AND te.election_id=$2
            WHERE c.id=$1`,
          values: [id, eid],
        };
        votesQ = {
          text: `SELECT tev.candidate_id, SUM(tev.votes)::integer as total_votes
            FROM geo_cities c
            JOIN geo_districts d ON d.city_id=c.id
            JOIN tps t ON t.district_id=d.id
            JOIN tps_entries te ON te.tps_id=t.id AND te.election_id=$2 AND te.status='confirmed'
            JOIN tps_entry_votes tev ON tev.entry_id=te.id
            WHERE c.id=$1
            GROUP BY tev.candidate_id`,
          values: [id, eid],
        };
      } else {
        nameQ = { text: 'SELECT name FROM geo_districts WHERE id=$1', values: [id] };
        tpsQ = {
          text: `SELECT COUNT(DISTINCT t.id) as total_tps,
            COUNT(DISTINCT CASE WHEN te.status='confirmed' THEN te.tps_id END) as reported_tps
            FROM geo_districts d
            JOIN tps t ON t.district_id=d.id
            LEFT JOIN tps_entries te ON te.tps_id=t.id AND te.election_id=$2
            WHERE d.id=$1`,
          values: [id, eid],
        };
        votesQ = {
          text: `SELECT tev.candidate_id, SUM(tev.votes)::integer as total_votes
            FROM geo_districts d
            JOIN tps t ON t.district_id=d.id
            JOIN tps_entries te ON te.tps_id=t.id AND te.election_id=$2 AND te.status='confirmed'
            JOIN tps_entry_votes tev ON tev.entry_id=te.id
            WHERE d.id=$1
            GROUP BY tev.candidate_id`,
          values: [id, eid],
        };
      }

      const [{ rows: nr }, { rows: tr }, { rows: vr }] = await Promise.all([
        pool.query(nameQ),
        pool.query(tpsQ),
        pool.query(votesQ),
      ]);
      if (!nr.length) return null;
      const votes = {};
      for (const v of vr) votes[v.candidate_id] = parseInt(v.total_votes);
      return {
        name: nr[0].name,
        type,
        id: parseInt(id),
        total_tps: parseInt(tr[0].total_tps),
        reported_tps: parseInt(tr[0].reported_tps),
        votes,
      };
    }

    const [a, b] = await Promise.all([fetchSide(aType, aId), fetchSide(bType, bId)]);
    res.json({ a, b });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Anomalies (public) ----

app.get('/api/anomalies', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    if (!er.length) return res.json({ summary: { perlu_ditinjau: 0, sengketa: 0, backlog: 0 }, items: [] });
    const eid = er[0].id;

    const { rows: summary } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status = 'flagged') as perlu_ditinjau,
        COUNT(*) FILTER (WHERE status = 'disputed') as sengketa,
        COUNT(*) FILTER (WHERE status = 'pending') as backlog
      FROM tps_entries
      WHERE election_id = $1
    `, [eid]);

    const { rows: items } = await pool.query(`
      SELECT te.id, te.tps_id, te.status, te.submitted_at,
        t.number as tps_number, d.name as district_name, c.name as city_name, p.name as province_name,
        ar.type as anomaly_type, ar.description as anomaly_desc
      FROM tps_entries te
      JOIN tps t ON t.id = te.tps_id
      JOIN geo_districts d ON d.id = t.district_id
      JOIN geo_cities c ON c.id = d.city_id
      JOIN geo_provinces p ON p.id = c.province_id
      LEFT JOIN anomaly_reports ar ON ar.tps_id = te.tps_id AND ar.status = 'terbuka'
      WHERE te.election_id = $1 AND te.status IN ('flagged','disputed')
      ORDER BY te.submitted_at DESC
      LIMIT 10
    `, [eid]);

    res.json({
      summary: {
        perlu_ditinjau: parseInt(summary[0].perlu_ditinjau),
        sengketa: parseInt(summary[0].sengketa),
        backlog: parseInt(summary[0].backlog),
      },
      items,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Audit log (public) ----

app.get('/api/audit-log', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT al.id, al.action, al.entity_type, al.entity_id, al.tps_id,
        al.actor_username, al.metadata, al.created_at,
        t.number as tps_number, d.name as district_name, c.name as city_name, p.name as province_name
      FROM audit_log al
      LEFT JOIN tps t ON t.id = al.tps_id
      LEFT JOIN geo_districts d ON d.id = t.district_id
      LEFT JOIN geo_cities c ON c.id = d.city_id
      LEFT JOIN geo_provinces p ON p.id = c.province_id
      ORDER BY al.created_at DESC
      LIMIT 20
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- TPS detail (public) ----

app.get('/api/public/tps/:id/detail', async (req, res) => {
  try {
    const { rows: er } = await pool.query("SELECT id FROM elections WHERE status = 'active' LIMIT 1");
    const eid = er.length ? er[0].id : null;

    const { rows: tpsRows } = await pool.query(`
      SELECT t.id, t.number, t.registered_voters,
        d.id as district_id, d.name as district_name, d.code as district_code,
        c.id as city_id, c.name as city_name,
        p.id as province_id, p.name as province_name
      FROM tps t
      JOIN geo_districts d ON d.id = t.district_id
      JOIN geo_cities c ON c.id = d.city_id
      JOIN geo_provinces p ON p.id = c.province_id
      WHERE t.id = $1
    `, [req.params.id]);
    if (!tpsRows.length) return res.status(404).json({ error: 'Not found' });

    let entry = null, votes = [];
    if (eid) {
      const { rows: entryRows } = await pool.query(
        `SELECT * FROM tps_entries WHERE tps_id = $1 AND election_id = $2
         AND status IN ('pending','confirmed','flagged','disputed')
         ORDER BY submitted_at DESC LIMIT 1`,
        [req.params.id, eid]
      );
      if (entryRows.length) {
        entry = entryRows[0];
        const { rows: voteRows } = await pool.query(
          'SELECT candidate_id, votes FROM tps_entry_votes WHERE entry_id = $1',
          [entry.id]
        );
        votes = voteRows;
      }
    }

    const { rows: anomalyReports } = await pool.query(
      `SELECT id, type, description, reporter_username, status, created_at
       FROM anomaly_reports WHERE tps_id = $1 ORDER BY created_at DESC`,
      [req.params.id]
    );

    res.json({ tps: tpsRows[0], entry, votes, anomaly_reports: anomalyReports });
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
      "SELECT * FROM tps_entries WHERE tps_id = $1 AND election_id = $2 AND status IN ('pending','confirmed','flagged','disputed') ORDER BY submitted_at DESC LIMIT 1",
      [req.params.id, eid]
    );
    if (!rows.length) return res.json({ entry: null, election_id: eid, is_own_entry: false });

    const entry = rows[0];
    const { rows: voteRows } = await pool.query('SELECT candidate_id, votes FROM tps_entry_votes WHERE entry_id = $1', [entry.id]);
    res.json({ entry, votes: voteRows, election_id: eid, is_own_entry: entry.submitted_by_user_id === req.user?.id });
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
      "SELECT * FROM tps_entries WHERE tps_id = $1 AND election_id = $2 AND status IN ('pending','confirmed','flagged','disputed')",
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
    logAudit('entry_submitted', 'entry', newEntry[0].id, tps_id, req.user.username, {});
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
    logAudit('entry_confirmed', 'entry', rows[0].id, rows[0].tps_id, req.user.username, {});
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

// ---- Anomaly reports ----

app.post('/api/anomaly-reports', async (req, res) => {
  const { tps_id, entry_id, type, description } = req.body;
  const validTypes = ['foto_tidak_jelas', 'data_tidak_sesuai', 'duplikat', 'lainnya'];
  if (!validTypes.includes(type)) return res.status(400).json({ error: 'Invalid type' });
  if (!tps_id) return res.status(400).json({ error: 'tps_id required' });

  try {
    const { rows: reportRows } = await pool.query(
      `INSERT INTO anomaly_reports (tps_id, entry_id, type, description, reporter_user_id, reporter_username)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [tps_id, entry_id || null, type, description || '', req.user.id, req.user.username]
    );
    if (entry_id) {
      await pool.query(
        "UPDATE tps_entries SET status = 'flagged' WHERE id = $1 AND status = 'pending'",
        [entry_id]
      );
    }
    logAudit('anomaly_filed', 'anomaly', reportRows[0].id, tps_id, req.user.username, { type });
    res.json({ ok: true, id: reportRows[0].id });
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
    const { rows } = await pool.query('SELECT * FROM tps_entries WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    await pool.query(
      "UPDATE tps_entries SET status = 'confirmed', confirmed_by_user_id = $1, confirmed_by_username = $2, confirmed_at = NOW() WHERE id = $3 AND status = 'pending'",
      [req.user.id, req.user.username, req.params.id]
    );
    logAudit('entry_confirmed', 'entry', rows[0].id, rows[0].tps_id, req.user.username, {});
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

app.post('/api/admin/entries/:id/dispute', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tps_entries WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    await pool.query("UPDATE tps_entries SET status = 'disputed' WHERE id = $1", [req.params.id]);
    logAudit('entry_disputed', 'entry', rows[0].id, rows[0].tps_id, req.user.username, {});
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/entries/:id/flag', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tps_entries WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    await pool.query(
      "UPDATE tps_entries SET status = 'flagged' WHERE id = $1 AND status IN ('pending','confirmed')",
      [req.params.id]
    );
    logAudit('entry_flagged', 'entry', rows[0].id, rows[0].tps_id, req.user.username, {});
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/anomaly-reports', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ar.*, t.number as tps_number, d.name as district_name, c.name as city_name, p.name as province_name
      FROM anomaly_reports ar
      JOIN tps t ON t.id = ar.tps_id
      JOIN geo_districts d ON d.id = t.district_id
      JOIN geo_cities c ON c.id = d.city_id
      JOIN geo_provinces p ON p.id = c.province_id
      ORDER BY ar.created_at DESC
      LIMIT 100
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  if (!req.user) {
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Buka di Usernode</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Buka aplikasi ini di dalam Usernode</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">Halaman ini memerlukan autentikasi platform.</p>
    <a href="https://social-vibecoding.usernodelabs.org" style="display:inline-block;padding:0.5rem 1rem;background:#7c3aed;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Buka Usernode</a>
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
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tps_entries_election_status ON tps_entries(election_id, status)`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tps_entry_votes (
      id SERIAL PRIMARY KEY,
      entry_id INTEGER NOT NULL REFERENCES tps_entries(id),
      candidate_id INTEGER NOT NULL REFERENCES candidates(id),
      votes INTEGER NOT NULL DEFAULT 0
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tps_entry_votes_entry ON tps_entry_votes(entry_id)`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username VARCHAR(255) NOT NULL UNIQUE,
      added_by_username VARCHAR(255),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS admins_user_id_unique ON admins(user_id) WHERE user_id IS NOT NULL`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS anomaly_reports (
      id SERIAL PRIMARY KEY,
      tps_id INTEGER NOT NULL REFERENCES tps(id),
      entry_id INTEGER REFERENCES tps_entries(id),
      type VARCHAR(50) NOT NULL,
      description TEXT,
      reporter_user_id INTEGER,
      reporter_username VARCHAR(255),
      status VARCHAR(20) DEFAULT 'terbuka',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_anomaly_reports_tps ON anomaly_reports(tps_id)`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      action VARCHAR(50) NOT NULL,
      entity_type VARCHAR(20),
      entity_id INTEGER,
      tps_id INTEGER,
      actor_username VARCHAR(255),
      metadata JSONB DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC)`);
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
      { seq: 1, name: 'Budi Santoso', mate: 'Dewi Rahayu', color: '#2563eb', photo: 'https://ui-avatars.com/api/?name=Budi+Santoso&background=2563eb&color=fff&size=128' },
      { seq: 2, name: 'Agus Wijaya', mate: 'Sri Mulyani', color: '#dc2626', photo: 'https://ui-avatars.com/api/?name=Agus+Wijaya&background=dc2626&color=fff&size=128' },
      { seq: 3, name: 'Cahyo Prabowo', mate: 'Rina Susanti', color: '#16a34a', photo: 'https://ui-avatars.com/api/?name=Cahyo+Prabowo&background=16a34a&color=fff&size=128' },
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

    // Confirmed entries: Alpha-1-1 (5), Alpha-1-2 (5), Alpha-2-1 (5) with staggered timestamps for trend chart
    const confirmedData = [
      { dCode: 'ST-A-1-1', votes: [[120,105,65],[115,110,70],[130,95,60],[100,125,65],[125,100,70]], hoursAgo: [22,20,18,16,14], withPhoto: true },
      { dCode: 'ST-A-1-2', votes: [[110,115,60],[135,90,65],[105,120,70],[120,105,60],[115,110,65]], hoursAgo: [12,10,8,6,4], withPhoto: true },
      { dCode: 'ST-A-2-1', votes: [[108,118,74],[122,98,80],[115,105,80],[130,88,82],[118,112,70]], hoursAgo: [3,2,2,1,1], withPhoto: false },
    ];

    for (const { dCode, votes: allVotes, hoursAgo, withPhoto } of confirmedData) {
      for (let i = 0; i < tpsIds[dCode].length; i++) {
        const tpsId = tpsIds[dCode][i];
        const vd = allVotes[i];
        const hAgo = hoursAgo[i];
        const photoUrl = withPhoto ? `https://picsum.photos/seed/tps-${dCode}-${i+1}/800/1100` : null;

        const { rows: [entry] } = await client.query(
          `INSERT INTO tps_entries (tps_id, election_id, submitted_by_user_id, submitted_by_username, status, photo_url, submitted_at, confirmed_by_user_id, confirmed_by_username, confirmed_at)
           VALUES ($1, $2, 0, 'staging-seed-user', 'confirmed', $3, NOW() - INTERVAL '${hAgo + 1} hours', -1, 'staging-seed-confirmer', NOW() - INTERVAL '${hAgo} hours') RETURNING id`,
          [tpsId, eid, photoUrl]
        );
        for (let j = 0; j < candidateIds.length; j++) {
          await client.query(
            'INSERT INTO tps_entry_votes (entry_id, candidate_id, votes) VALUES ($1, $2, $3)',
            [entry.id, candidateIds[j], vd[j]]
          );
        }
        await client.query(
          `INSERT INTO audit_log (action, entity_type, entity_id, tps_id, actor_username, created_at)
           VALUES ('entry_confirmed', 'entry', $1, $2, 'staging-seed-confirmer', NOW() - INTERVAL '${hAgo} hours')`,
          [entry.id, tpsId]
        );
      }
    }

    // Pending entries: Beta-1-1 (5)
    const pendingVotes = [[90,100,80],[95,105,75],[100,95,80],[88,112,78],[102,98,82]];
    for (let i = 0; i < tpsIds['ST-B-1-1'].length; i++) {
      const tpsId = tpsIds['ST-B-1-1'][i];
      const { rows: [entry] } = await client.query(
        `INSERT INTO tps_entries (tps_id, election_id, submitted_by_user_id, submitted_by_username, status, submitted_at)
         VALUES ($1, $2, 0, 'staging-seed-user', 'pending', NOW() - INTERVAL '30 minutes') RETURNING id`,
        [tpsId, eid]
      );
      for (let j = 0; j < candidateIds.length; j++) {
        await client.query('INSERT INTO tps_entry_votes (entry_id, candidate_id, votes) VALUES ($1, $2, $3)',
          [entry.id, candidateIds[j], pendingVotes[i][j]]);
      }
      await client.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, tps_id, actor_username, created_at)
         VALUES ('entry_submitted', 'entry', $1, $2, 'staging-seed-user', NOW() - INTERVAL '30 minutes')`,
        [entry.id, tpsId]
      );
    }

    // Flagged entries: Beta-1-2 (first 3)
    const flaggedVotes = [[95,88,75],[102,91,70],[88,110,72]];
    const flaggedDescs = [
      { type: 'foto_tidak_jelas', desc: 'Gambar formulir C1 buram dan tidak dapat dibaca dengan jelas' },
      { type: 'data_tidak_sesuai', desc: 'Jumlah suara pada formulir tidak sesuai dengan data yang diinput' },
      { type: 'duplikat', desc: 'TPS ini tampaknya sudah pernah dimasukkan sebelumnya dengan data berbeda' },
    ];
    for (let i = 0; i < 3; i++) {
      const tpsId = tpsIds['ST-B-1-2'][i];
      const { rows: [entry] } = await client.query(
        `INSERT INTO tps_entries (tps_id, election_id, submitted_by_user_id, submitted_by_username, status, submitted_at)
         VALUES ($1, $2, 0, 'staging-seed-user', 'flagged', NOW() - INTERVAL '2 hours') RETURNING id`,
        [tpsId, eid]
      );
      for (let j = 0; j < candidateIds.length; j++) {
        await client.query('INSERT INTO tps_entry_votes (entry_id, candidate_id, votes) VALUES ($1, $2, $3)',
          [entry.id, candidateIds[j], flaggedVotes[i][j]]);
      }
      const { rows: [ar] } = await client.query(
        `INSERT INTO anomaly_reports (tps_id, entry_id, type, description, reporter_user_id, reporter_username, created_at)
         VALUES ($1, $2, $3, $4, 0, 'staging-seed-user', NOW() - INTERVAL '1 hour') RETURNING id`,
        [tpsId, entry.id, flaggedDescs[i].type, flaggedDescs[i].desc]
      );
      await client.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, tps_id, actor_username, created_at)
         VALUES ('anomaly_filed', 'anomaly', $1, $2, 'staging-seed-user', NOW() - INTERVAL '1 hour')`,
        [ar.id, tpsId]
      );
    }

    // Disputed entries: Beta-2-1 (first 2)
    const disputedVotes = [[88,105,67],[92,98,70]];
    const disputedDescs = [
      { type: 'data_tidak_sesuai', desc: 'Data suara tidak cocok dengan formulir C1 yang difoto' },
      { type: 'duplikat', desc: 'Entri ini adalah duplikat dari TPS yang sudah dikonfirmasi sebelumnya' },
    ];
    for (let i = 0; i < 2; i++) {
      const tpsId = tpsIds['ST-B-2-1'][i];
      const { rows: [entry] } = await client.query(
        `INSERT INTO tps_entries (tps_id, election_id, submitted_by_user_id, submitted_by_username, status, submitted_at)
         VALUES ($1, $2, 0, 'staging-seed-user', 'disputed', NOW() - INTERVAL '3 hours') RETURNING id`,
        [tpsId, eid]
      );
      for (let j = 0; j < candidateIds.length; j++) {
        await client.query('INSERT INTO tps_entry_votes (entry_id, candidate_id, votes) VALUES ($1, $2, $3)',
          [entry.id, candidateIds[j], disputedVotes[i][j]]);
      }
      const { rows: [ar] } = await client.query(
        `INSERT INTO anomaly_reports (tps_id, entry_id, type, description, reporter_user_id, reporter_username, status, created_at)
         VALUES ($1, $2, $3, $4, 0, 'staging-seed-user', 'ditinjau', NOW() - INTERVAL '2 hours') RETURNING id`,
        [tpsId, entry.id, disputedDescs[i].type, disputedDescs[i].desc]
      );
      await client.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, tps_id, actor_username, created_at)
         VALUES ('entry_disputed', 'entry', $1, $2, 'staging-seed-confirmer', NOW() - INTERVAL '1 hour')`,
        [entry.id, tpsId]
      );
      await client.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, tps_id, actor_username, created_at)
         VALUES ('anomaly_filed', 'anomaly', $1, $2, 'staging-seed-user', NOW() - INTERVAL '2 hours')`,
        [ar.id, tpsId]
      );
    }

    await client.query('COMMIT');
    console.log('Staging demo data seeded (KawalPemilu platform)');
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
