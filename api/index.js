require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const supabase  = require('../lib/supabase');
const { signToken, requireAuth, requireAdmin, requireCanDelete } = require('../lib/auth');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── CORS ────────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (mobile apps, curl, same-origin)
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));

// ─── SECURITY HEADERS ────────────────────────────────────────────────────────
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const _loginAttempts = new Map(); // ip → { count, resetAt }
function loginRateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const WINDOW = 15 * 60 * 1000; // 15 minutes
  const MAX = 10;
  let rec = _loginAttempts.get(ip);
  if (!rec || now > rec.resetAt) rec = { count: 0, resetAt: now + WINDOW };
  rec.count++;
  _loginAttempts.set(ip, rec);
  if (rec.count > MAX) {
    const retryAfter = Math.ceil((rec.resetAt - now) / 1000);
    res.setHeader('Retry-After', retryAfter);
    return res.status(429).json({ error: `Too many login attempts — retry in ${Math.ceil(retryAfter/60)} minutes` });
  }
  next();
}
// Clean up stale entries every 15 minutes
setInterval(() => {
  const now = Date.now();
  _loginAttempts.forEach((v, k) => { if (now > v.resetAt) _loginAttempts.delete(k); });
}, 15 * 60 * 1000);

// ─── HEALTH ──────────────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ─── AUDIT LOG ───────────────────────────────────────────────────────────────

async function auditLog(actor, action, tableName, recordId, changes) {
  try {
    await supabase.from('audit_log').insert({
      actor_id:   actor?.sub  || null,
      actor_name: actor?.name || 'unknown',
      action,
      table_name: tableName,
      record_id:  String(recordId),
      changes:    changes || {},
    });
  } catch(e) {
    console.warn('Audit log failed:', e.message);
  }
}

// ─── LOCK HELPERS ─────────────────────────────────────────────────────────────

// Returns the deal if it is locked (invoice_status = paid), else null
async function getLockedDeal(dealId) {
  const { data } = await supabase.from('deals').select('id,name,invoice_status').eq('id', dealId).single();
  return data?.invoice_status === 'paid' ? data : null;
}

// Returns true if the expense's project is complete OR payouts finalized
async function isExpenseLocked(expenseId) {
  const { data: exp } = await supabase.from('expenses').select('project_id').eq('id', expenseId).single();
  if (!exp?.project_id) return false;
  const { data: proj } = await supabase.from('projects').select('status,payouts_finalized').eq('id', exp.project_id).single();
  return proj?.payouts_finalized || proj?.status === 'complete';
}

// Returns true if any profit share has been paid for this member
async function isProfitSharePaid(memberId) {
  const { data } = await supabase.from('profit_share_status').select('id').eq('member_id', memberId).eq('paid', true).limit(1);
  return (data?.length || 0) > 0;
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// Public — load team list for login screen (no PINs or hashes exposed)
// Public — only exposes the minimum needed for the login member picker.
// auth_role is intentionally excluded from this unauthenticated endpoint.
app.get('/api/team', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('team_members')
      .select('id, name, color, active')
      .eq('active', true)
      .order('name');
    if (error) throw error;
    res.json(data.map(m => ({ id: m.id, name: m.name, color: m.color })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Public — PIN login
app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const { memberId, pin } = req.body || {};
  if (!memberId || !pin) return res.status(400).json({ error: 'memberId and pin required' });

  try {
    const { data: member, error } = await supabase
      .from('team_members')
      .select('id, name, auth_role, color, active, pin_hash')
      .eq('id', memberId)
      .single();

    if (error || !member) return res.status(401).json({ error: 'Member not found' });
    if (!member.active)   return res.status(403).json({ error: 'Account is inactive' });

    const valid = await bcrypt.compare(String(pin), member.pin_hash);
    if (!valid) return res.status(401).json({ error: 'Incorrect PIN' });

    const token = signToken(member);
    res.json({
      token,
      member: {
        id:       member.id,
        name:     member.name,
        authRole: member.auth_role,
        color:    member.color,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── BOOTSTRAP — single call to hydrate all state after login ─────────────────
app.get('/api/bootstrap', requireAuth, async (req, res) => {
  try {
    const [
      teamRes, dealsRes, projectsRes, tasksRes,
      expensesRes, payStatusRes, psStatusRes, payLogRes,
    ] = await Promise.all([
      supabase.from('team_members').select('id,name,role,color,profit_share_pct,active,auth_role').order('name'),
      supabase.from('deals').select('*').order('created_at', { ascending: false }),
      supabase.from('projects').select('*').order('created_at', { ascending: false }),
      supabase.from('tasks').select('*').order('created_at', { ascending: false }),
      supabase.from('expenses').select('*').order('date', { ascending: false }),
      supabase.from('pay_status').select('*'),
      supabase.from('profit_share_status').select('*'),
      supabase.from('pay_log').select('*').order('paid_at', { ascending: false }).limit(500),
    ]);

    for (const r of [teamRes, dealsRes, projectsRes, tasksRes, expensesRes, payStatusRes, psStatusRes, payLogRes]) {
      if (r.error) throw r.error;
    }

    // Reshape payStatus into the key-value map the frontend expects
    // Uses pay_key column (new) or falls back to project_id_member_id (legacy rows)
    const payStatus = {};
    (payStatusRes.data || []).forEach(r => {
      const k = r.pay_key || `${r.project_id}_${r.member_id}`;
      payStatus[k] = r.paid;
    });

    // Reshape profitSharePaidStatus — include snapshot data for paid quarters
    const profitSharePaidStatus = {};
    (psStatusRes.data || []).forEach(r => {
      profitSharePaidStatus[`${r.quarter_key}_${r.member_id}`] = {
        paid: r.paid,
        psPct: r.ps_pct ?? null,
        allocationAmount: r.allocation_amount ?? null,
      };
    });

    res.json({
      team:                 teamRes.data.map(mapTeamMember),
      deals:                dealsRes.data.map(mapDeal),
      projects:             projectsRes.data.map(mapProject),
      tasks:                tasksRes.data.map(mapTask),
      expenses:             expensesRes.data.map(mapExpense),
      payStatus,
      profitSharePaidStatus,
      payLog:               payLogRes.data || [],
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── INDIVIDUAL TABLE ENDPOINTS (used by realtime refresh) ────────────────────

app.get('/api/deals', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('deals').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(mapDeal));
});

app.get('/api/projects', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('projects').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(mapProject));
});

app.get('/api/tasks', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('tasks').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(mapTask));
});

app.get('/api/expenses', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('expenses').select('*').order('date', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(mapExpense));
});

app.get('/api/pay-status', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('pay_status').select('*');
  if (error) return res.status(500).json({ error: error.message });
  const out = {};
  // Support both old schema (project_id + member_id) and new schema (pay_key)
  data.forEach(r => {
    if (r.pay_key) {
      out[r.pay_key] = r.paid;
    } else {
      out[`${r.project_id}_${r.member_id}`] = r.paid;
    }
  });
  res.json(out);
});

app.get('/api/profit-share-status', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('profit_share_status').select('*');
  if (error) return res.status(500).json({ error: error.message });
  // Return full record so frontend can use snapshotted ps_pct for paid quarters
  const out = {};
  data.forEach(r => {
    out[`${r.quarter_key}_${r.member_id}`] = {
      paid: r.paid,
      psPct: r.ps_pct ?? null,
      allocationAmount: r.allocation_amount ?? null,
    };
  });
  res.json(out);
});

// ─── DEALS ───────────────────────────────────────────────────────────────────

app.post('/api/deals', requireAuth, requireAdmin, async (req, res) => {
  try {
    const row = dealToRow(req.body);
    const { data, error } = await supabase.from('deals').insert(row).select().single();
    if (error) throw error;
    res.status(201).json(mapDeal(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/deals/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    // Fetch current deal to check lock status and build audit diff
    const { data: current, error: fetchErr } = await supabase.from('deals').select('*').eq('id', req.params.id).single();
    if (fetchErr) throw fetchErr;

    // Financial fields only lock when the linked project's payouts are finalized
    const FINANCIAL_FIELDS = ['value','buckets','prob'];
    const attemptedFinancial = FINANCIAL_FIELDS.filter(f => req.body[f] !== undefined);
    if (attemptedFinancial.length > 0) {
      const { data: proj } = await supabase.from('projects').select('payouts_finalized,name').eq('deal_id', req.params.id).maybeSingle();
      if (proj?.payouts_finalized) {
        await auditLog(req.user, 'BLOCKED_EDIT_FINALIZED_DEAL', 'deals', req.params.id, {
          attempted: attemptedFinancial, reason: 'project payouts finalized'
        });
        return res.status(403).json({ error: `Project "${proj.name}" payouts are finalized — financial fields are permanently locked.` });
      }
    }

    const row = dealToRow(req.body, true);
    const { data, error } = await supabase.from('deals').update(row).eq('id', req.params.id).select().single();
    if (error) throw error;

    // Audit: record what changed
    const changes = {};
    Object.keys(row).forEach(k => { if (JSON.stringify(current[k]) !== JSON.stringify(data[k])) changes[k] = { from: current[k], to: data[k] }; });
    if (Object.keys(changes).length) await auditLog(req.user, 'EDIT_DEAL', 'deals', req.params.id, changes);

    res.json(mapDeal(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/deals/:id', requireAuth, requireCanDelete, async (req, res) => {
  try {
    const { data: deal } = await supabase.from('deals').select('*').eq('id', req.params.id).single();
    // Block deletion if the linked project has finalized payouts
    const { data: proj } = await supabase.from('projects').select('payouts_finalized,name').eq('deal_id', req.params.id).maybeSingle();
    if (proj?.payouts_finalized) {
      await auditLog(req.user, 'BLOCKED_DELETE_FINALIZED_DEAL', 'deals', req.params.id, { name: deal?.name });
      return res.status(403).json({ error: `Cannot delete — project "${proj.name}" payouts are finalized.` });
    }
    await auditLog(req.user, 'DELETE_DEAL', 'deals', req.params.id, { name: deal?.name });
    const { error } = await supabase.from('deals').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── PROJECTS ────────────────────────────────────────────────────────────────

app.post('/api/projects', requireAuth, async (req, res) => {
  // Admin, Class A, and VA can create projects
  if (!['admin','class_a','va'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Creating projects requires Admin, Class A, or VA access.' });
  }
  try {
    const { name, dealId, client, startDate, endDate, status } = req.body;
    const { data, error } = await supabase.from('projects').insert({
      name, deal_id: dealId || null, client: client || '',
      start_date: startDate || null, end_date: endDate || null,
      status: status || 'active', archived: false,
    }).select().single();
    if (error) throw error;
    res.status(201).json(mapProject(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    // If payouts are finalized, nothing can be changed — ever
    const { data: current } = await supabase.from('projects').select('payouts_finalized,name').eq('id', req.params.id).single();
    if (current?.payouts_finalized && req.body.payoutsFinalized !== false) {
      return res.status(403).json({ error: `"${current.name}" has finalized payouts — this project is permanently locked.` });
    }
    const updates = {};
    if (req.body.status           !== undefined) updates.status            = req.body.status;
    if (req.body.archived         !== undefined) updates.archived          = req.body.archived;
    if (req.body.name             !== undefined) updates.name              = req.body.name;
    if (req.body.startDate        !== undefined) updates.start_date        = req.body.startDate;
    if (req.body.endDate          !== undefined) updates.end_date          = req.body.endDate;
    if (req.body.payoutsFinalized !== undefined) updates.payouts_finalized = req.body.payoutsFinalized;
    const { data, error } = await supabase.from('projects').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(mapProject(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── TASKS ───────────────────────────────────────────────────────────────────

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { title, projectId, assigneeId, dueDate, priority, status, estHours, tag } = req.body;
    const { data, error } = await supabase.from('tasks').insert({
      title, project_id: projectId, assignee_id: assigneeId || null,
      due_date: dueDate || null, priority: priority || 'med',
      status: status || 'todo', est_hours: estHours || 0,
      tag: tag || null,
    }).select().single();
    if (error) throw error;
    res.status(201).json(mapTask(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    // Check if task's project is locked (payouts finalized = permanent lock)
    if (req.body.estHours !== undefined || req.body.status !== undefined || req.body.title !== undefined) {
      const { data: task } = await supabase.from('tasks').select('project_id').eq('id', req.params.id).single();
      if (task?.project_id) {
        const { data: proj } = await supabase.from('projects').select('payouts_finalized').eq('id', task.project_id).single();
        if (proj?.payouts_finalized) {
          return res.status(403).json({ error: 'Task is permanently locked — project payouts have been finalized.' });
        }
      }
    }
    const updates = {};
    if (req.body.title      !== undefined) updates.title       = req.body.title;
    if (req.body.projectId  !== undefined) updates.project_id  = req.body.projectId;
    if (req.body.assigneeId !== undefined) updates.assignee_id = req.body.assigneeId;
    if (req.body.dueDate    !== undefined) updates.due_date    = req.body.dueDate;
    if (req.body.priority   !== undefined) updates.priority    = req.body.priority;
    if (req.body.status     !== undefined) updates.status      = req.body.status;
    if (req.body.estHours   !== undefined) updates.est_hours   = req.body.estHours;
    if (req.body.tag        !== undefined) updates.tag         = req.body.tag || null;
    const { data, error } = await supabase.from('tasks').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(mapTask(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tasks/:id', requireAuth, requireCanDelete, async (req, res) => {
  try {
    const { error } = await supabase.from('tasks').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── EXPENSES ────────────────────────────────────────────────────────────────

app.post('/api/expenses', requireAuth, async (req, res) => {
  try {
    const { description, amount, projectId, category, date, submittedBy, paymentType, receiptUrl } = req.body;
    if (projectId) {
      const { data: proj } = await supabase.from('projects').select('status,name,payouts_finalized').eq('id', projectId).single();
      if (proj?.payouts_finalized) {
        return res.status(403).json({ error: `Project "${proj.name}" payouts are finalized — it is permanently locked.` });
      }
      if (proj?.status === 'complete') {
        return res.status(403).json({ error: `Project "${proj.name}" is complete — expenses are locked.` });
      }
    }
    const { data, error } = await supabase.from('expenses').insert({
      description, amount, project_id: projectId,
      category: category || 'other', date: date || new Date().toISOString().split('T')[0],
      submitted_by: submittedBy || null, payment_type: paymentType || 'company',
      receipt_url: receiptUrl || null, reimbursed: false,
    }).select().single();
    if (error) throw error;
    res.status(201).json(mapExpense(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/expenses/:id', requireAuth, async (req, res) => {
  try {
    // Admins can always update reimbursed status — payments happen after project finalization
    const isReimbursedOnlyUpdate = Object.keys(req.body).length === 1 && req.body.reimbursed !== undefined;
    if (!isReimbursedOnlyUpdate || req.user.role !== 'admin') {
      if (await isExpenseLocked(req.params.id)) {
        return res.status(403).json({ error: 'Expense is locked — project is complete.' });
      }
    }
    const updates = {};
    const map = {
      description:'description', amount:'amount', projectId:'project_id',
      category:'category', date:'date', submittedBy:'submitted_by',
      paymentType:'payment_type', receiptUrl:'receipt_url', reimbursed:'reimbursed',
    };
    Object.keys(map).forEach(k => { if (req.body[k] !== undefined) updates[map[k]] = req.body[k]; });
    const { data, error } = await supabase.from('expenses').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(mapExpense(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/expenses/:id', requireAuth, requireCanDelete, async (req, res) => {
  try {
    if (await isExpenseLocked(req.params.id)) {
      return res.status(403).json({ error: 'Expense is locked — project is complete.' });
    }
    const { error } = await supabase.from('expenses').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── PAY STATUS ───────────────────────────────────────────────────────────────

app.post('/api/pay-status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { projectId, memberId, paid } = req.body;
    // Composite key supports both production keys (uuid_uuid) and fee keys (uuid_fee_name_uuid)
    const payKey = `${projectId}_${memberId}`;
    const { error } = await supabase
      .from('pay_status')
      .upsert({ pay_key: payKey, paid }, { onConflict: 'pay_key' });
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── PROFIT SHARE STATUS ──────────────────────────────────────────────────────

app.post('/api/profit-share-status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { quarterKey, memberId, paid, psPct, allocationAmount } = req.body;
    const row = { quarter_key: quarterKey, member_id: memberId, paid };
    // Snapshot % and amount when marking paid so historical quarters stay accurate
    if (paid && psPct !== undefined) row.ps_pct = psPct;
    if (paid && allocationAmount !== undefined) row.allocation_amount = allocationAmount;
    // Clear snapshot when unmarking
    if (!paid) { row.ps_pct = null; row.allocation_amount = null; }
    const { data, error } = await supabase
      .from('profit_share_status')
      .upsert(row, { onConflict: 'quarter_key,member_id' })
      .select().single();
    if (error) throw error;
    res.json({ ok: true, data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


// ─── PAY LOG ──────────────────────────────────────────────────────────────────

app.get('/api/pay-log', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('pay_log')
      .select('*')
      .order('paid_at', { ascending: false })
      .limit(500);
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pay-log', requireAuth, requireAdmin, async (req, res) => {
  try {
    const {
      memberId, memberName, payType, amount,
      projectId, projectName, dealId, dealName, dealValue, dealNet,
      quarterKey, sourceKey, notes, isManual, paidAt,
    } = req.body;

    if (!memberId || !payType || amount === undefined) {
      return res.status(400).json({ error: 'memberId, payType, and amount are required' });
    }

    const { data, error } = await supabase.from('pay_log').insert({
      member_id:       memberId,
      member_name:     memberName || null,
      pay_type:        payType,
      amount:          amount,
      project_id:      projectId || null,
      project_name:    projectName || null,
      deal_id:         dealId || null,
      deal_name:       dealName || null,
      deal_value:      dealValue || null,
      deal_net:        dealNet || null,
      quarter_key:     quarterKey || null,
      source_key:      sourceKey || null,
      notes:           notes || null,
      created_by_id:   req.user.sub,
      created_by_name: req.user.name,
      is_manual:       isManual || false,
      paid_at:         paidAt || new Date().toISOString(),
    }).select().single();

    if (error) throw error;
    await auditLog(req.user, 'PAY_LOG_ENTRY', 'pay_log', data.id, {
      member: memberName, type: payType, amount, isManual: isManual || false
    });
    res.status(201).json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/pay-log/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { data: entry } = await supabase.from('pay_log').select('*').eq('id', req.params.id).single();
    if (entry && !entry.is_manual) {
      return res.status(403).json({ error: 'Auto-generated pay log entries cannot be deleted. Unmark the payment as paid instead.' });
    }
    await auditLog(req.user, 'DELETE_PAY_LOG', 'pay_log', req.params.id, {
      member: entry?.member_name, amount: entry?.amount
    });
    const { error } = await supabase.from('pay_log').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── AUDIT LOG ENDPOINT ──────────────────────────────────────────────────────

app.get('/api/audit-log', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('audit_log')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── TEAM MEMBERS ─────────────────────────────────────────────────────────────

app.post('/api/team', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { name, role, profitSharePct, active, color, pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'PIN is required for new members' });
    const pin_hash = await bcrypt.hash(String(pin), 10);
    const { data, error } = await supabase.from('team_members').insert({
      name, role: role || '', profit_share_pct: profitSharePct || 0,
      active: active !== false, color: color || '#c9a84c',
      auth_role: 'member', pin_hash,
    }).select().single();
    if (error) throw error;
    res.status(201).json(mapTeamMember(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/team/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    // Prevent admins from demoting themselves
    if (req.params.id === req.user.sub && req.body.authRole && req.body.authRole !== 'admin') {
      return res.status(400).json({ error: "You cannot remove your own admin access" });
    }
    // Block profit share % changes if this member has any paid profit share
    if (req.body.profitSharePct !== undefined) {
      const { data: current } = await supabase.from('team_members').select('profit_share_pct,name').eq('id', req.params.id).single();
      if (current && current.profit_share_pct !== req.body.profitSharePct) {
        const locked = await isProfitSharePaid(req.params.id);
        if (locked) {
          await auditLog(req.user, 'BLOCKED_PS_PCT_CHANGE', 'team_members', req.params.id, {
            from: current.profit_share_pct, to: req.body.profitSharePct,
            reason: 'profit share already paid out'
          });
          return res.status(403).json({ error: `${current.name}'s profit share % is locked — they have a paid profit share distribution. Unmark it as paid first.` });
        }
      }
    }
    const updates = {};
    if (req.body.name           !== undefined) updates.name             = req.body.name;
    if (req.body.role           !== undefined) updates.role             = req.body.role;
    if (req.body.profitSharePct !== undefined) updates.profit_share_pct = req.body.profitSharePct;
    if (req.body.active         !== undefined) updates.active           = req.body.active;
    if (req.body.authRole !== undefined) {
      const validRoles = ['admin','class_a','class_b','va'];
      if (!validRoles.includes(req.body.authRole)) return res.status(400).json({ error: 'Invalid role' });
      updates.auth_role = req.body.authRole;
    }
    if (req.body.pin) updates.pin_hash = await bcrypt.hash(String(req.body.pin), 10);
    const { data: current } = await supabase.from('team_members').select('*').eq('id', req.params.id).single();
    const { data, error } = await supabase.from('team_members').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    // Audit profit share % changes even when allowed
    if (updates.profit_share_pct !== undefined && current?.profit_share_pct !== updates.profit_share_pct) {
      await auditLog(req.user, 'EDIT_TEAM_PS_PCT', 'team_members', req.params.id, {
        name: data.name, from: current.profit_share_pct, to: updates.profit_share_pct
      });
    }
    res.json(mapTeamMember(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/team/:id', requireAuth, requireAdmin, async (req, res) => {
  // Prevent self-deletion
  if (req.params.id === req.user.sub) return res.status(400).json({ error: "You cannot remove yourself" });
  try {
    const { error } = await supabase.from('team_members').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── PENDING EXPENSES (bulk import from Drive) ────────────────────────────────

/**
 * Preview a Drive folder — lists all receipt-eligible files so the UI can show
 * a count before the user confirms processing.
 * Body: { folderUrl: "https://drive.google.com/drive/folders/..." }
 * Returns: { folderId, folderName, files: [{ id, name, mimeType, size }], skipped }
 */
app.post('/api/expenses/bulk-preview', requireAuth, async (req, res) => {
  try {
    const { folderUrl } = req.body || {};
    if (!folderUrl) return res.status(400).json({ error: 'folderUrl is required' });

    const folderId = parseDriveFolderId(folderUrl);
    if (!folderId) return res.status(400).json({ error: 'Could not parse folder ID from URL' });

    const drive = await getDriveClient();

    // Get folder name for UI display
    let folderName = folderId;
    try {
      const meta = await drive.files.get({ fileId: folderId, fields: 'name', supportsAllDrives: true });
      folderName = meta.data.name || folderId;
    } catch (ex) {
      return res.status(404).json({ error: 'Folder not found or service account does not have access' });
    }

    // List files in folder (non-recursive for v1)
    const listResp = await drive.files.list({
      q: `'${folderId}' in parents and trashed=false`,
      fields: 'files(id,name,mimeType,size)',
      pageSize: 200,
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
    });

    const allFiles = listResp.data.files || [];
    const files = allFiles.filter(f =>
      f.mimeType && (f.mimeType.startsWith('image/') || f.mimeType === 'application/pdf')
    );
    const skipped = allFiles.length - files.length;

    res.json({ folderId, folderName, files, skipped });
  } catch (e) {
    console.error('Bulk preview error:', e);
    res.status(500).json({ error: e.message });
  }
});

/**
 * Process a batch of Drive file IDs — for each: download, AI-extract,
 * create a pending_expenses row.
 * Body: { fileIds: [string], defaultProjectId?: string, submittedBy?: string }
 * Returns: { processed: [{fileId, pendingId, vendor, amount, error?}], failed: [...] }
 */
app.post('/api/expenses/bulk-import', requireAuth, async (req, res) => {
  try {
    const { fileIds, defaultProjectId, submittedBy } = req.body || {};
    if (!Array.isArray(fileIds) || !fileIds.length) {
      return res.status(400).json({ error: 'fileIds array required' });
    }
    if (fileIds.length > 50) {
      return res.status(400).json({ error: 'Maximum 50 files per batch' });
    }

    const drive = await getDriveClient();
    const processed = [];
    const failed = [];

    // Process in series — Vision calls are sequential to avoid rate limiting
    for (const fileId of fileIds) {
      try {
        // Get metadata
        const metaResp = await drive.files.get({
          fileId,
          fields: 'id,name,mimeType,size,webViewLink,createdTime',
          supportsAllDrives: true,
        });
        const meta = metaResp.data;

        // Download file bytes
        const bytesResp = await drive.files.get(
          { fileId, alt: 'media', supportsAllDrives: true },
          { responseType: 'arraybuffer' }
        );
        const base64 = Buffer.from(bytesResp.data).toString('base64');

        // AI-extract
        let extracted = { vendor: null, amount: null, expense_date: null, category: null, notes: null, confidence: 'low' };
        if (process.env.ANTHROPIC_API_KEY) {
          try {
            extracted = await extractReceiptDetails({
              base64,
              mimeType: meta.mimeType,
              emailSubject: meta.name,
              emailBody: '',
            });
          } catch (ex) {
            console.error(`AI extraction failed for ${meta.name}:`, ex.message);
          }
        }

        // Make Drive file shareable so the review link works
        try {
          await drive.permissions.create({
            fileId,
            requestBody: { role: 'reader', type: 'anyone' },
            supportsAllDrives: true,
          });
        } catch (ex) {
          // Non-fatal: link may still work if user has Drive access
        }

        // Create pending row
        const { data, error } = await supabase.from('pending_expenses').insert({
          source: 'drive-bulk',
          sender_email: null,
          sender_name: null,
          subject: meta.name,
          body_snippet: `Imported from Drive${defaultProjectId ? ` · default project pre-set` : ''}`,
          vendor: extracted.vendor,
          amount: extracted.amount,
          expense_date: extracted.expense_date,
          category: extracted.category,
          suggested_notes: extracted.notes,
          ai_confidence: extracted.confidence,
          receipt_url: meta.webViewLink,
          receipt_filename: meta.name,
          status: 'pending',
        }).select().single();
        if (error) throw error;

        processed.push({
          fileId,
          pendingId: data.id,
          filename: meta.name,
          vendor: extracted.vendor,
          amount: extracted.amount,
          confidence: extracted.confidence,
        });
      } catch (ex) {
        console.error(`Bulk import failed for file ${fileId}:`, ex.message);
        failed.push({ fileId, error: ex.message });
      }
    }

    // If defaultProjectId was provided, tag newly created rows (stored in suggested_notes for now;
    // the UI pre-fills the project dropdown with this)
    if (defaultProjectId && processed.length) {
      // We don't have a project_id column on pending_expenses by design (project is assigned at approval).
      // The UI honors defaultProjectId client-side to pre-fill the dropdowns after bulk import.
    }

    await auditLog(req.user, 'BULK_IMPORT_RECEIPTS', 'pending_expenses', null, {
      processed: processed.length, failed: failed.length,
    });

    res.json({ processed, failed, defaultProjectId });
  } catch (e) {
    console.error('Bulk import error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Parse a Drive folder ID from either a full URL or raw ID
function parseDriveFolderId(input) {
  if (!input) return null;
  const trimmed = String(input).trim();
  // Bare ID
  if (/^[a-zA-Z0-9_-]{20,}$/.test(trimmed)) return trimmed;
  // URL forms:
  //   https://drive.google.com/drive/folders/<ID>
  //   https://drive.google.com/drive/folders/<ID>?usp=sharing
  //   https://drive.google.com/drive/u/0/folders/<ID>
  const m = trimmed.match(/\/folders\/([a-zA-Z0-9_-]+)/);
  if (m) return m[1];
  // id= query param fallback
  const q = trimmed.match(/[?&]id=([a-zA-Z0-9_-]+)/);
  if (q) return q[1];
  return null;
}

app.get('/api/pending-expenses', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('pending_expenses')
      .select('*')
      .eq('status', 'pending')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data.map(mapPendingExpense));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/pending-expenses/:id', requireAuth, async (req, res) => {
  try {
    const updates = {};
    if (req.body.vendor         !== undefined) updates.vendor          = req.body.vendor;
    if (req.body.amount         !== undefined) updates.amount          = req.body.amount;
    if (req.body.expenseDate    !== undefined) updates.expense_date    = req.body.expenseDate;
    if (req.body.category       !== undefined) updates.category        = req.body.category;
    if (req.body.suggestedNotes !== undefined) updates.suggested_notes = req.body.suggestedNotes;
    const { data, error } = await supabase
      .from('pending_expenses')
      .update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(mapPendingExpense(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/**
 * Promote a pending expense into the real expenses table.
 * Body: { projectId, submittedBy, paymentType, description?, category?, amount?, date? }
 * The pending row gets marked approved with a reference to the new expense.
 */
app.post('/api/pending-expenses/:id/approve', requireAuth, async (req, res) => {
  try {
    const { data: pending, error: fetchErr } = await supabase
      .from('pending_expenses').select('*').eq('id', req.params.id).single();
    if (fetchErr || !pending) return res.status(404).json({ error: 'Pending expense not found' });
    if (pending.status !== 'pending') return res.status(400).json({ error: 'Already reviewed' });

    const { projectId, submittedBy, paymentType } = req.body;
    if (!projectId || !submittedBy || !paymentType) {
      return res.status(400).json({ error: 'projectId, submittedBy, paymentType required' });
    }
    // Block if project is finalized
    const { data: proj } = await supabase.from('projects').select('name,payouts_finalized').eq('id', projectId).single();
    if (proj?.payouts_finalized) {
      return res.status(403).json({ error: `Project "${proj.name}" is finalized — cannot add expenses.` });
    }

    const description = req.body.description || pending.vendor || pending.subject || 'Receipt';
    const ALLOWED_CATEGORIES = ['software','contractor','assets','advertising','printing','travel','equipment','other'];
    const rawCategory = req.body.category || pending.category || 'other';
    const category = ALLOWED_CATEGORIES.includes(rawCategory) ? rawCategory : 'other';
    const amount      = req.body.amount != null ? req.body.amount : pending.amount;
    const date        = req.body.date        || pending.expense_date || new Date().toISOString().split('T')[0];
    if (amount == null) return res.status(400).json({ error: 'amount is required' });

    const { data: expense, error: insErr } = await supabase.from('expenses').insert({
      description, amount, project_id: projectId, category, date,
      submitted_by: submittedBy, payment_type: paymentType,
      receipt_url: pending.receipt_url, reimbursed: false,
    }).select().single();
    if (insErr) throw insErr;

    await supabase.from('pending_expenses').update({
      status: 'approved',
      reviewed_by: req.user.sub,
      reviewed_at: new Date().toISOString(),
      promoted_expense_id: expense.id,
    }).eq('id', req.params.id);

    await auditLog(req.user, 'APPROVE_PENDING_EXPENSE', 'pending_expenses', req.params.id, {
      expense_id: expense.id, amount, description,
    });

    res.json(mapExpense(expense));
  } catch (e) {
    console.error('Approve error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/pending-expenses/:id/reject', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('pending_expenses').update({
      status: 'rejected',
      reviewed_by: req.user.sub,
      reviewed_at: new Date().toISOString(),
      reject_reason: req.body.reason || null,
    }).eq('id', req.params.id);
    if (error) throw error;
    await auditLog(req.user, 'REJECT_PENDING_EXPENSE', 'pending_expenses', req.params.id, { reason: req.body.reason });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── DRIVE + AI HELPERS ──────────────────────────────────────────────────────

let _driveClient = null;
let _driveRootFolderId = null;
async function getDriveClient() {
  if (_driveClient) return _driveClient;
  const { google } = require('googleapis');
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON not set');
  }
  const creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  const auth = new google.auth.JWT({
    email: creds.client_email,
    key: creds.private_key,
    scopes: ['https://www.googleapis.com/auth/drive'],
  });
  _driveClient = google.drive({ version: 'v3', auth });
  _driveRootFolderId = process.env.DRIVE_RECEIPTS_ROOT_ID;
  if (!_driveRootFolderId) throw new Error('DRIVE_RECEIPTS_ROOT_ID not set');
  return _driveClient;
}

async function ensureDriveSubfolder(path) {
  const drive = await getDriveClient();
  const parts = path.split('/').filter(Boolean);
  let parentId = _driveRootFolderId;
  for (const part of parts) {
    const q = `'${parentId}' in parents and name='${part}' and mimeType='application/vnd.google-apps.folder' and trashed=false`;
    const list = await drive.files.list({ q, fields: 'files(id,name)' });
    if (list.data.files && list.data.files.length) {
      parentId = list.data.files[0].id;
    } else {
      const created = await drive.files.create({
        requestBody: {
          name: part, mimeType: 'application/vnd.google-apps.folder', parents: [parentId],
        },
        fields: 'id',
      });
      parentId = created.data.id;
    }
  }
  return parentId;
}

async function uploadToDrive({ filename, mimeType, base64, subfolder }) {
  const drive = await getDriveClient();
  const folderId = await ensureDriveSubfolder(subfolder);
  const buffer = Buffer.from(base64, 'base64');
  const { Readable } = require('stream');
  const stream = Readable.from(buffer);
  const { data } = await drive.files.create({
    requestBody: { name: filename, parents: [folderId] },
    media: { mimeType, body: stream },
    fields: 'id,webViewLink',
  });
  // Make link-shareable
  await drive.permissions.create({
    fileId: data.id,
    requestBody: { role: 'reader', type: 'anyone' },
  });
  return { id: data.id, webViewLink: data.webViewLink };
}

async function extractReceiptDetails({ base64, mimeType, emailSubject, emailBody }) {
  const Anthropic = require('@anthropic-ai/sdk');
  const client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });

  const EXPENSE_CATEGORIES = ['software','contractor','assets','advertising','printing','travel','equipment','other'];

  const systemPrompt = `You are an accounting assistant. Extract expense details from a receipt image.
Return ONLY a JSON object with these fields (no markdown, no prose):
{
  "vendor": string or null,
  "amount": number or null (total including tax, in USD),
  "expense_date": string or null (YYYY-MM-DD),
  "category": one of ${JSON.stringify(EXPENSE_CATEGORIES)} or null,
  "notes": short string summarizing what was purchased or null,
  "confidence": "high" | "medium" | "low"
}
If you cannot determine a field, use null. Only use "high" confidence when the amount and vendor are clearly legible.`;

  const content = [];
  if (mimeType === 'application/pdf') {
    content.push({
      type: 'document',
      source: { type: 'base64', media_type: 'application/pdf', data: base64 },
    });
  } else {
    content.push({
      type: 'image',
      source: { type: 'base64', media_type: mimeType, data: base64 },
    });
  }
  content.push({
    type: 'text',
    text: `Email subject: ${emailSubject || '(none)'}\nEmail body excerpt: ${(emailBody || '').substring(0, 500)}\n\nExtract the receipt details.`,
  });

  const resp = await client.messages.create({
    model: 'claude-opus-4-5',
    max_tokens: 500,
    system: systemPrompt,
    messages: [{ role: 'user', content }],
  });

  const text = resp.content.find(c => c.type === 'text')?.text || '{}';
  const clean = text.replace(/```json|```/g, '').trim();
  try {
    const parsed = JSON.parse(clean);
    return {
      vendor:       parsed.vendor || null,
      amount:       typeof parsed.amount === 'number' ? parsed.amount : null,
      expense_date: parsed.expense_date || null,
      category:     parsed.category || null,
      notes:        parsed.notes || null,
      confidence:   parsed.confidence || 'low',
    };
  } catch {
    return { vendor: null, amount: null, expense_date: null, category: null, notes: null, confidence: 'low' };
  }
}

// ─── PAYROLL ──────────────────────────────────────────────────────────────────

/**
 * Return all unpaid line items in a date range, grouped by member.
 * Query: ?from=YYYY-MM-DD&to=YYYY-MM-DD
 *
 * Line items surfaced:
 *   - Production pool allocations (tasks on projects with linked paid deals, grouped by member)
 *   - Special fees (deal buckets with assignedTo)
 *   - Profit share distributions (by month)
 * Only items WITHOUT a matching pay_status entry marked paid are returned.
 */
app.get('/api/payroll/unpaid', requireAuth, requireAdmin, async (req, res) => {
  try {
    const fromStr = req.query.from;
    const toStr   = req.query.to;
    if (!fromStr || !toStr) return res.status(400).json({ error: 'from and to query params required (YYYY-MM-DD)' });

    // Fetch everything we need
    const [{ data: team }, { data: deals }, { data: projects }, { data: tasks }, { data: payStatus }] = await Promise.all([
      supabase.from('team_members').select('id,name,role,color,profit_share_pct').eq('active', true),
      supabase.from('deals').select('*'),
      supabase.from('projects').select('*'),
      supabase.from('tasks').select('*'),
      supabase.from('pay_status').select('*'),
    ]);

    const paidSet = new Set(payStatus.filter(p => p.paid).map(p => p.pay_key || `${p.project_id}_${p.member_id}`));

    const items = []; // { memberId, memberName, type, label, amount, payKey, projectId?, projectName? }

    // Production pool + special fees per completed+paid project in range
    for (const proj of projects) {
      const deal = deals.find(d => d.id === proj.deal_id);
      if (!deal) continue;
      if (deal.stage !== 'Closed Won' || deal.invoice_status !== 'paid') continue;
      if (proj.status !== 'complete') continue;
      // Only include if project was completed (end_date or close_date) in range
      // Using close_date as the proxy since project lacks a completed_at
      const ref = deal.close_date || proj.end_date;
      if (!ref) continue;
      const refDate = ref.length === 7 ? ref + '-01' : ref;
      if (refDate < fromStr || refDate > toStr) continue;

      const projTasks = tasks.filter(t => t.project_id === proj.id);
      const totalHours = projTasks.reduce((s, t) => s + (t.est_hours || 0), 0);
      const netRev = Number(deal.value || 0) - Number(deal.expenses || 0);
      const pb = (deal.buckets || []).find(b => b.name === 'Production Pool');
      const pool = pb ? netRev * pb.pct / 100 : 0;

      // Production pool — by member hours share
      if (totalHours > 0 && pool > 0) {
        const memberHours = {};
        projTasks.forEach(t => {
          if (!t.assignee_id) return;
          memberHours[t.assignee_id] = (memberHours[t.assignee_id] || 0) + (t.est_hours || 0);
        });
        for (const [mid, hrs] of Object.entries(memberHours)) {
          const payKey = `${proj.id}_${mid}`;
          if (paidSet.has(payKey)) continue;
          const member = team.find(m => m.id === mid);
          if (!member) continue;
          items.push({
            memberId: mid, memberName: member.name,
            type: 'production',
            label: `${proj.name} — production pool (${hrs}h)`,
            projectId: proj.id, projectName: proj.name,
            amount: Math.round(pool * (hrs / totalHours) * 100) / 100,
            payKey,
          });
        }
      }

      // Special fees
      const fees = (deal.buckets || []).filter(b => b.isPersonal && b.assignedTo);
      for (const fee of fees) {
        const amt = netRev * (fee.pct || 0) / 100;
        if (amt <= 0) continue;
        const feeKeyBase = fee.name.replace(/\s/g, '_');
        const payKey = `${proj.id}_fee_${feeKeyBase}_${fee.assignedTo}`;
        if (paidSet.has(payKey)) continue;
        const member = team.find(m => m.id === fee.assignedTo);
        if (!member) continue;
        items.push({
          memberId: fee.assignedTo, memberName: member.name,
          type: 'fee',
          label: `${proj.name} — ${fee.name}`,
          projectId: proj.id, projectName: proj.name,
          amount: Math.round(amt * 100) / 100,
          payKey,
        });
      }
    }

    // Group by member
    const grouped = {};
    for (const it of items) {
      if (!grouped[it.memberId]) grouped[it.memberId] = { memberId: it.memberId, memberName: it.memberName, items: [], total: 0 };
      grouped[it.memberId].items.push(it);
      grouped[it.memberId].total += it.amount;
    }
    Object.values(grouped).forEach(g => { g.total = Math.round(g.total * 100) / 100; });

    res.json({ from: fromStr, to: toStr, members: Object.values(grouped) });
  } catch (e) {
    console.error('Payroll unpaid error:', e);
    res.status(500).json({ error: e.message });
  }
});

/**
 * Batch-mark a list of pay keys as paid and create a pay_log entry for each.
 * Body: { items: [{ memberId, payKey, amount, projectId?, label }] }
 */
app.post('/api/payroll/mark-paid', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { items } = req.body || {};
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'items array required' });

    const results = [];
    for (const it of items) {
      if (!it.payKey || !it.memberId || it.amount == null) continue;
      // pay_status upsert
      const parts = it.payKey.split('_');
      const projectId = it.projectId || parts[0];
      await supabase.from('pay_status').upsert({
        pay_key: it.payKey, project_id: projectId, member_id: it.memberId, paid: true,
      }, { onConflict: 'pay_key' });

      // pay_log entry
      const member = it.memberName || '';
      const { data: logRow } = await supabase.from('pay_log').insert({
        member_id: it.memberId, member_name: member,
        pay_type: it.type || 'production',
        amount: it.amount,
        project_id: projectId,
        project_name: it.projectName || null,
        source_key: it.payKey,
        notes: it.label || 'Payroll batch',
        is_manual: false,
        created_by_id: req.user.sub,
        created_by_name: req.user.name,
      }).select().single();

      await auditLog(req.user, 'PAYROLL_MARK_PAID', 'pay_status', it.payKey, {
        amount: it.amount, member_id: it.memberId, project_id: projectId,
      });
      results.push({ payKey: it.payKey, payLogId: logRow?.id });
    }

    res.json({ ok: true, processed: results.length, results });
  } catch (e) {
    console.error('Mark paid error:', e);
    res.status(500).json({ error: e.message });
  }
});

/**
 * Generate per-member docx pay stubs for a list of items.
 * Body: { from, to, members: [{ memberName, items: [{ label, amount, type }], total }] }
 * Returns: { files: [{ memberName, filename, base64 }] }
 */
app.post('/api/payroll/generate-docx', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { from, to, members } = req.body || {};
    if (!Array.isArray(members) || !members.length) {
      return res.status(400).json({ error: 'members array required' });
    }

    const docx = require('docx');
    const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, HeadingLevel, AlignmentType, BorderStyle, WidthType } = docx;

    const files = [];
    for (const mem of members) {
      const rows = [new TableRow({
        children: [
          new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: 'Description', bold: true })] })], width: { size: 70, type: WidthType.PERCENTAGE } }),
          new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: 'Type', bold: true })] })], width: { size: 15, type: WidthType.PERCENTAGE } }),
          new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: 'Amount', bold: true })], alignment: AlignmentType.RIGHT })], width: { size: 15, type: WidthType.PERCENTAGE } }),
        ],
      })];
      for (const it of (mem.items || [])) {
        rows.push(new TableRow({
          children: [
            new TableCell({ children: [new Paragraph(it.label || '')] }),
            new TableCell({ children: [new Paragraph(it.type || '')] }),
            new TableCell({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun(`$${Number(it.amount || 0).toFixed(2)}`)] })] }),
          ],
        }));
      }
      rows.push(new TableRow({
        children: [
          new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: 'Total', bold: true })] })] }),
          new TableCell({ children: [new Paragraph('')] }),
          new TableCell({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: `$${Number(mem.total || 0).toFixed(2)}`, bold: true })] })] }),
        ],
      }));

      const doc = new Document({
        sections: [{
          children: [
            new Paragraph({ children: [new TextRun({ text: 'Creative Juice Agency', bold: true, size: 32 })] }),
            new Paragraph({ children: [new TextRun({ text: 'Pay Summary', size: 24 })] }),
            new Paragraph({ children: [new TextRun({ text: ' ' })] }),
            new Paragraph({ children: [new TextRun({ text: `Paid to: ${mem.memberName || ''}`, bold: true })] }),
            new Paragraph({ children: [new TextRun({ text: `Period: ${from || ''} to ${to || ''}` })] }),
            new Paragraph({ children: [new TextRun({ text: `Generated: ${new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' })}` })] }),
            new Paragraph({ children: [new TextRun({ text: ' ' })] }),
            new Table({ rows, width: { size: 100, type: WidthType.PERCENTAGE } }),
            new Paragraph({ children: [new TextRun({ text: ' ' })] }),
            new Paragraph({ children: [new TextRun({ text: 'Thank you for your work.', italics: true })] }),
          ],
        }],
      });
      const buffer = await Packer.toBuffer(doc);
      const safe = String(mem.memberName || 'member').replace(/[^A-Za-z0-9_-]/g, '_');
      files.push({
        memberName: mem.memberName,
        filename: `PayStub_${safe}_${from}_to_${to}.docx`,
        base64: buffer.toString('base64'),
      });
    }

    res.json({ files });
  } catch (e) {
    console.error('Payroll docx error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── DATA MAPPERS — DB row → frontend object ──────────────────────────────────

function mapTeamMember(m) {
  return {
    id:             m.id,
    name:           m.name,
    role:           m.role,
    color:          m.color,
    profitSharePct: m.profit_share_pct,
    active:         m.active,
    authRole:       m.auth_role,
  };
}

function mapDeal(d) {
  return {
    id:            d.id,
    name:          d.name,
    client:        d.client,
    value:         d.value,
    expenses:      0,  // always computed client-side from expenses table via syncDealExpenses()
    stage:         d.stage,
    owner:         d.owner,
    closeDate:     d.close_date,
    invoiceStatus: d.invoice_status || 'none',
    buckets:       d.buckets || [],
    prob:          d.prob || 0,
  };
}

function mapProject(p) {
  return {
    id:               p.id,
    name:             p.name,
    dealId:           p.deal_id,
    client:           p.client,
    startDate:        p.start_date,
    endDate:          p.end_date,
    status:           p.status,
    archived:         p.archived || false,
    payoutsFinalized: p.payouts_finalized || false,
  };
}

function mapTask(t) {
  return {
    id:         t.id,
    title:      t.title,
    projectId:  t.project_id,
    assigneeId: t.assignee_id,
    due:        t.due_date,
    priority:   t.priority,
    status:     t.status,
    estHours:   t.est_hours || 0,
    tag:        t.tag || null,
  };
}

function mapExpense(e) {
  return {
    id:          e.id,
    description: e.description,
    amount:      e.amount,
    projectId:   e.project_id,
    category:    e.category,
    date:        e.date,
    submittedBy: e.submitted_by,
    paymentType: e.payment_type,
    receiptUrl:  e.receipt_url,
    reimbursed:  e.reimbursed || false,
  };
}

function mapPendingExpense(p) {
  return {
    id:               p.id,
    createdAt:        p.created_at,
    source:           p.source,
    senderEmail:      p.sender_email,
    senderName:       p.sender_name,
    subject:          p.subject,
    bodySnippet:      p.body_snippet,
    vendor:           p.vendor,
    amount:           p.amount,
    expenseDate:      p.expense_date,
    category:         p.category,
    suggestedNotes:   p.suggested_notes,
    aiConfidence:     p.ai_confidence,
    receiptUrl:       p.receipt_url,
    receiptFilename:  p.receipt_filename,
    status:           p.status,
    reviewedBy:       p.reviewed_by,
    reviewedAt:       p.reviewed_at,
    rejectReason:     p.reject_reason,
  };
}

// ─── DEAL ROW BUILDER ─────────────────────────────────────────────────────────

function dealToRow(body, partial = false) {
  const row = {};
  if (!partial || body.name          !== undefined) row.name           = body.name;
  if (!partial || body.client        !== undefined) row.client         = body.client;
  if (!partial || body.value         !== undefined) row.value          = body.value;
  if (!partial || body.expenses      !== undefined) row.expenses       = body.expenses || 0;
  if (!partial || body.stage         !== undefined) row.stage          = body.stage;
  if (!partial || body.owner         !== undefined) row.owner          = body.owner;
  if (!partial || body.closeDate     !== undefined) row.close_date     = body.closeDate || null;
  if (!partial || body.invoiceStatus !== undefined) row.invoice_status = body.invoiceStatus || 'none';
  if (!partial || body.buckets       !== undefined) row.buckets        = body.buckets || [];
  if (!partial || body.prob          !== undefined) row.prob           = body.prob || 0;
  return row;
}

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`CJ Agency API running on :${PORT}`));

module.exports = app;
