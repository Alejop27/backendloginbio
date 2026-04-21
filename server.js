/**
 * server.js — Backend Seg4 
 */

require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const axios   = require('axios');
const sqlite3 = require('sqlite3').verbose();
const helmet  = require('helmet');

// ─── CONFIG ─────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'seg4_secret_key';
const JWT_EXPIRES = '2h';
const NPOINT_URL = 'https://api.npoint.io/4bcd8e73c1067cb36360';

// ─── DB ─────────────────────────────────────────────

const db = new sqlite3.Database('./seg4.db');

function initDatabase() {
  db.serialize(() => {

    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS articulos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        articulo TEXT,
        precio REAL,
        descuento REAL,
        urlimagen TEXT,
        valoracion REAL,
        calificaciones INTEGER,
        descripcion TEXT
      )
    `);

    db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
      if (err) return console.error(err);

      if (!row) {
        const hash = bcrypt.hashSync('1234', 10);
        db.run(
          'INSERT INTO users (username, password_hash) VALUES (?, ?)',
          ['admin', hash]
        );
        console.log('✅ Usuario creado: admin / 1234');
      }
    });

    console.log('✅ DB lista');
  });
}

// ─── SYNC ───────────────────────────────────────────

async function syncArticulos() {
  try {
    const { data } = await axios.get(NPOINT_URL);

    if (!data.articulos || !Array.isArray(data.articulos)) {
      throw new Error('Formato inválido de API');
    }

    db.serialize(() => {

      db.run('BEGIN TRANSACTION');

      db.run('DELETE FROM articulos');

      const stmt = db.prepare(`
        INSERT INTO articulos 
        (articulo, precio, descuento, urlimagen, valoracion, calificaciones, descripcion)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);

      data.articulos.forEach(item => {
        stmt.run(
          item.articulo,
          parseFloat(item.precio) || 0,
          parseFloat(item.descuento) || 0,
          item.urlimagen || '',
          parseFloat(item.valoracion) || 0,
          parseInt(item.calificaciones) || 0,
          item.descripcion || ''
        );
      });

      stmt.finalize();
      db.run('COMMIT');

      console.log('✅ Sync OK');
    });

  } catch (error) {
    console.error('❌ Sync error:', error.message);
  }
}

// ─── APP ────────────────────────────────────────────

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

// ─── AUTH MIDDLEWARE ────────────────────────────────

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;
    next();

  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// ─── LOGIN ──────────────────────────────────────────

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Datos incompletos' });
  }

  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username],
    (err, user) => {

      if (err) {
        return res.status(500).json({ error: 'Error DB' });
      }

      if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: 'Credenciales incorrectas' });
      }

      const token = jwt.sign(
        { userId: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES }
      );

      res.json({ token });
    }
  );
});

// ─── RUTAS ──────────────────────────────────────────

app.get('/api/articulos', requireAuth, (req, res) => {
  db.all('SELECT * FROM articulos', [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Error DB' });
    }
    res.json({ articulos: rows });
  });
});

app.get('/api/ofertas', requireAuth, (req, res) => {
  db.all(
    'SELECT * FROM articulos WHERE descuento > 0',
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Error DB' });
      }
      res.json({ ofertas: rows });
    }
  );
});

app.post('/api/sync', requireAuth, async (req, res) => {
  await syncArticulos();
  res.json({ message: 'Datos sincronizados' });
});

// ─── SERVER ─────────────────────────────────────────

initDatabase();

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`🚀 http://localhost:${PORT}`);
  await syncArticulos();
});