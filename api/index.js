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
app.use(express.json());

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

// Returns true if any profit share has been paid for this member
async function isProfitSharePaid(memberId) {
  const { data } = await supabase.from('profit_share_status').select('id').eq('member_id', memberId).eq('paid', true).limit(1);
  return (data?.length || 0) > 0;
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// Public — load team list for login screen (no PINs or hashes exposed)
app.get('/api/team', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('team_members')
      .select('id, name, auth_role, color, active')
      .order('name');
    if (error) throw error;
    // Map snake_case → camelCase for frontend
    res.json(data.map(m => ({
      id:       m.id,
      name:     m.name,
      authRole: m.auth_role,
      color:    m.color,
      active:   m.active,
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Public — PIN login
app.post('/api/auth/login', async (req, res) => {
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

    // Reshape profitSharePaidStatus
    const profitSharePaidStatus = {};
    (psStatusRes.data || []).forEach(r => {
      profitSharePaidStatus[`${r.quarter_key}_${r.member_id}`] = r.paid;
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
  const out = {};
  data.forEach(r => { out[`${r.quarter_key}_${r.member_id}`] = r.paid; });
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

    const isPaid = current.invoice_status === 'paid';
    const FINANCIAL_FIELDS = ['value','buckets','prob'];
    const attemptedFinancial = FINANCIAL_FIELDS.filter(f => req.body[f] !== undefined);

    // Block financial edits on paid deals (allow invoice_status change so admin can unlock)
    if (isPaid && attemptedFinancial.length > 0) {
      await auditLog(req.user, 'BLOCKED_EDIT_PAID_DEAL', 'deals', req.params.id, {
        attempted: attemptedFinancial, reason: 'deal is paid'
      });
      return res.status(403).json({ error: 'Deal is marked Paid — financial fields (value, buckets) are locked. Change invoice status first.' });
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
    if (deal?.invoice_status === 'paid') {
      await auditLog(req.user, 'BLOCKED_DELETE_PAID_DEAL', 'deals', req.params.id, { name: deal.name });
      return res.status(403).json({ error: 'Cannot delete a deal marked as Paid.' });
    }
    await auditLog(req.user, 'DELETE_DEAL', 'deals', req.params.id, { name: deal?.name });
    const { error } = await supabase.from('deals').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── PROJECTS ────────────────────────────────────────────────────────────────

app.post('/api/projects', requireAuth, requireAdmin, async (req, res) => {
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
    const allowed = ['name','status','archived','start_date','end_date','deal_id','client'];
    const updates = {};
    if (req.body.status    !== undefined) updates.status    = req.body.status;
    if (req.body.archived  !== undefined) updates.archived  = req.body.archived;
    if (req.body.name      !== undefined) updates.name      = req.body.name;
    if (req.body.startDate !== undefined) updates.start_date= req.body.startDate;
    if (req.body.endDate   !== undefined) updates.end_date  = req.body.endDate;
    const { data, error } = await supabase.from('projects').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(mapProject(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── TASKS ───────────────────────────────────────────────────────────────────

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { title, projectId, assigneeId, dueDate, priority, status, estHours } = req.body;
    const { data, error } = await supabase.from('tasks').insert({
      title, project_id: projectId, assignee_id: assigneeId || null,
      due_date: dueDate || null, priority: priority || 'med',
      status: status || 'todo', est_hours: estHours || 0,
    }).select().single();
    if (error) throw error;
    res.status(201).json(mapTask(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    // Check if task's project is locked (complete + paid)
    if (req.body.estHours !== undefined) {
      const { data: task } = await supabase.from('tasks').select('project_id').eq('id', req.params.id).single();
      if (task?.project_id) {
        const { data: proj } = await supabase.from('projects').select('status,deal_id').eq('id', task.project_id).single();
        if (proj?.status === 'complete' && proj?.deal_id) {
          const locked = await getLockedDeal(proj.deal_id);
          if (locked) {
            await auditLog(req.user, 'BLOCKED_EDIT_TASK_HOURS', 'tasks', req.params.id, {
              attempted_hours: req.body.estHours, reason: 'project complete + deal paid'
            });
            return res.status(403).json({ error: 'Task hours are locked — project is complete and deal is paid.' });
          }
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
    const { quarterKey, memberId, paid } = req.body;
    const { data, error } = await supabase
      .from('profit_share_status')
      .upsert({ quarter_key: quarterKey, member_id: memberId, paid },
               { onConflict: 'quarter_key,member_id' })
      .select().single();
    if (error) throw error;
    res.json({ ok: true });
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
    invoiceStatus:   d.invoice_status || 'none',
    amountCollected: d.amount_collected || 0,
    buckets:         d.buckets || [],
    prob:            d.prob || 0,
  };
}

function mapProject(p) {
  return {
    id:        p.id,
    name:      p.name,
    dealId:    p.deal_id,
    client:    p.client,
    startDate: p.start_date,
    endDate:   p.end_date,
    status:    p.status,
    archived:  p.archived || false,
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
  if (!partial || body.invoiceStatus    !== undefined) row.invoice_status    = body.invoiceStatus || 'none';
  if (!partial || body.amountCollected !== undefined) row.amount_collected = body.amountCollected || 0;
  if (!partial || body.buckets         !== undefined) row.buckets          = body.buckets || [];
  if (!partial || body.prob          !== undefined) row.prob           = body.prob || 0;
  return row;
}

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`CJ Agency API running on :${PORT}`));

module.exports = app;
