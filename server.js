const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const SECRET = process.env.JWT_SECRET || 'change-me-en-production';
const db = new Database(process.env.DB_PATH || 'data.db');

db.exec(`
CREATE TABLE IF NOT EXISTS schools (id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL, name TEXT,
  email TEXT UNIQUE, password_hash TEXT, role TEXT, student_id INTEGER);
CREATE TABLE IF NOT EXISTS classes (id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL, name TEXT, capacity INTEGER);
CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL, class_id INTEGER,
  name TEXT, parent_id INTEGER, absences INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL, student_id INTEGER,
  amount_due REAL, amount_paid REAL);
CREATE TABLE IF NOT EXISTS grades (id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL, student_id INTEGER,
  subject TEXT, term INTEGER, score REAL);
`);

// ---------- Données de démonstration : 2 écoles ----------
function seed() {
  if (db.prepare('SELECT COUNT(*) c FROM schools').get().c > 0) return;
  const hash = bcrypt.hashSync('Demo@2026', 8);
  const insSchool = db.prepare('INSERT INTO schools (name) VALUES (?)');
  const insUser = db.prepare('INSERT INTO users (school_id,name,email,password_hash,role,student_id) VALUES (?,?,?,?,?,?)');
  const insClass = db.prepare('INSERT INTO classes (school_id,name,capacity) VALUES (?,?,?)');
  const insStu = db.prepare('INSERT INTO students (school_id,class_id,name,parent_id,absences) VALUES (?,?,?,?,?)');
  const insPay = db.prepare('INSERT INTO payments (school_id,student_id,amount_due,amount_paid) VALUES (?,?,?,?)');
  const insGrade = db.prepare('INSERT INTO grades (school_id,student_id,subject,term,score) VALUES (?,?,?,?,?)');

  ['A', 'B'].forEach((L, si) => {
    const sid = insSchool.run('École ' + L).lastInsertRowid;
    const l = L.toLowerCase();
    const parentId = insUser.run(sid, 'Parent ' + L, `parent.${l}@demo.tn`, hash, 'parent', null).lastInsertRowid;
    const c1 = insClass.run(sid, '1ère année', 4).lastInsertRowid;
    const c2 = insClass.run(sid, '2ème année', 8).lastInsertRowid;
    let firstStudent = null;
    for (let i = 1; i <= 10; i++) {
      const cls = i <= 5 ? c1 : c2;
      const abs = (i * 3 + si) % 9;
      const stuId = insStu.run(sid, cls, `${L}-Élève${i}`, i <= 2 ? parentId : null, abs).lastInsertRowid;
      if (i === 1) firstStudent = stuId;
      const due = 1200;
      insPay.run(sid, stuId, due, [1200, 900, 600, 300, 0][(i + si) % 5]);
      ['Maths', 'Français', 'Sciences'].forEach((sub, k) => {
        insGrade.run(sid, stuId, sub, 1, 6 + ((i * 5 + k * 3 + si) % 13));
        insGrade.run(sid, stuId, sub, 2, 5 + ((i * 7 + k * 2 + si) % 13));
      });
    }
    insUser.run(sid, 'Admin ' + L, `admin.${l}@demo.tn`, hash, 'admin', null);
    insUser.run(sid, 'Directeur ' + L, `directeur.${l}@demo.tn`, hash, 'director', null);
    insUser.run(sid, 'Enseignant ' + L, `enseignant.${l}@demo.tn`, hash, 'teacher', null);
    insUser.run(sid, 'Comptable ' + L, `comptable.${l}@demo.tn`, hash, 'accountant', null);
    insUser.run(sid, 'Élève ' + L, `eleve.${l}@demo.tn`, hash, 'student', firstStudent);
  });
}
seed();

// ---------- Application ----------
const app = express();
app.use(express.json());
app.use(express.static('public'));

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(password || '', u.password_hash))
    return res.status(401).json({ error: 'Identifiants invalides' });
  // L'école vient du token signé par le serveur, jamais du navigateur.
  const token = jwt.sign({ id: u.id, school_id: u.school_id, role: u.role, student_id: u.student_id }, SECRET, { expiresIn: '8h' });
  const school = db.prepare('SELECT name FROM schools WHERE id=?').get(u.school_id).name;
  res.json({ token, name: u.name, role: u.role, school });
});

function auth(roles) {
  return (req, res, next) => {
    try {
      req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    } catch { return res.status(401).json({ error: 'Non connecté' }); }
    if (roles && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Accès refusé' });
    next();
  };
}

// Liste des élèves : toujours filtrée par école + par rôle
app.get('/api/students', auth(), (req, res) => {
  const { school_id, role, id, student_id } = req.user;
  let sql = `SELECT s.id, s.name, c.name AS classe, s.absences FROM students s
             LEFT JOIN classes c ON c.id = s.class_id WHERE s.school_id = ?`;
  const p = [school_id];
  if (role === 'parent') { sql += ' AND s.parent_id = ?'; p.push(id); }
  if (role === 'student') { sql += ' AND s.id = ?'; p.push(student_id); }
  res.json(db.prepare(sql).all(...p));
});

// Un élève précis : "introuvable" s'il est dans une autre école
app.get('/api/students/:id', auth(), (req, res) => {
  const s = db.prepare('SELECT * FROM students WHERE id=? AND school_id=?').get(req.params.id, req.user.school_id);
  if (!s) return res.status(404).json({ error: 'Introuvable' });
  if (req.user.role === 'parent' && s.parent_id !== req.user.id) return res.status(404).json({ error: 'Introuvable' });
  if (req.user.role === 'student' && s.id !== req.user.student_id) return res.status(404).json({ error: 'Introuvable' });
  s.grades = db.prepare('SELECT subject, term, score FROM grades WHERE student_id=? AND school_id=?').all(s.id, req.user.school_id);
  res.json(s);
});

// Ajout d'un élève (admin) : school_id pris dans le token
app.post('/api/students', auth(['admin']), (req, res) => {
  const { name, class_id } = req.body;
  const cls = db.prepare('SELECT id FROM classes WHERE id=? AND school_id=?').get(class_id, req.user.school_id);
  if (!name || !cls) return res.status(400).json({ error: 'Données invalides' });
  const r = db.prepare('INSERT INTO students (school_id,class_id,name) VALUES (?,?,?)').run(req.user.school_id, class_id, name);
  res.status(201).json({ id: r.lastInsertRowid });
});

const BI = ['admin', 'director'];

// Dashboard 1 : général
app.get('/api/dashboard/general', auth(BI), (req, res) => {
  const sid = req.user.school_id;
  const classes = db.prepare(`SELECT c.name, c.capacity, COUNT(s.id) AS effectif FROM classes c
    LEFT JOIN students s ON s.class_id = c.id AND s.school_id = c.school_id
    WHERE c.school_id = ? GROUP BY c.id`).all(sid);
  const alerts = classes.filter(c => c.effectif > c.capacity).map(c => `Classe surchargée : ${c.name} (${c.effectif}/${c.capacity})`)
    .concat(classes.filter(c => c.effectif < c.capacity * 0.5).map(c => `Classe sous-remplie : ${c.name} (${c.effectif}/${c.capacity})`));
  res.json({ totalEleves: db.prepare('SELECT COUNT(*) c FROM students WHERE school_id=?').get(sid).c, classes, alerts });
});

// Dashboard 2 : financier
app.get('/api/dashboard/finance', auth([...BI, 'accountant']), (req, res) => {
  const sid = req.user.school_id;
  const t = db.prepare('SELECT SUM(amount_due) due, SUM(amount_paid) paid FROM payments WHERE school_id=?').get(sid);
  const retards = db.prepare(`SELECT s.name, p.amount_due - p.amount_paid AS reste FROM payments p
    JOIN students s ON s.id = p.student_id WHERE p.school_id = ? AND p.amount_paid < p.amount_due ORDER BY reste DESC`).all(sid);
  res.json({ attendu: t.due, encaisse: t.paid, reste: t.due - t.paid,
    tauxRecouvrement: Math.round(100 * t.paid / t.due), retards });
});

// Dashboard 3 : Early Warning System (règles simples, expliquez-les à l'oral)
app.get('/api/dashboard/risques', auth(BI), (req, res) => {
  const sid = req.user.school_id;
  const rows = db.prepare(`SELECT s.id, s.name, s.absences,
      (SELECT AVG(score) FROM grades g WHERE g.student_id = s.id AND g.school_id = s.school_id) AS moyenne,
      (SELECT 100.0 * amount_paid / amount_due FROM payments p WHERE p.student_id = s.id AND p.school_id = s.school_id) AS pctPaye
    FROM students s WHERE s.school_id = ?`).all(sid);
  const out = rows.map(r => {
    const flags = [];
    if (r.moyenne < 10) flags.push('Risque d\'échec');
    if (r.absences >= 5) flags.push('Absences répétées');
    if (r.moyenne < 10 && r.absences >= 5) flags.push('ABANDON POSSIBLE');
    if (r.pctPaye < 50) flags.push('Risque d\'impayé');
    return { name: r.name, moyenne: +r.moyenne.toFixed(1), absences: r.absences, pctPaye: Math.round(r.pctPaye), flags };
  }).filter(r => r.flags.length);
  res.json(out);
});

app.listen(process.env.PORT || 3000, () => console.log('Serveur démarré'));
