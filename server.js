/**
 * server.js — Backend principal para Seg4
 *
 * Responsabilidades:
 *  - Autenticación JWT (login, biométrico, deshabilitar).
 *  - Almacenamiento relacional (SQLite) de usuarios y artículos.
 *  - Consumo de la API externa npoint y sincronización a BD.
 *  - Validación del JWT de sesión en cada solicitud protegida.
 *
 * Tablas:
 *  users     → credenciales + token biométrico activo
 *  articulos → caché relacional del JSON de npoint
 */

const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const axios   = require('axios');
const Database = require('better-sqlite3');

// ─── Configuración ───────────────────────────────────────────────────────────

const PORT              = process.env.PORT || 3000;
const JWT_SESSION_SECRET    = process.env.JWT_SESSION_SECRET    || 'seg4_session_secret_key_2024';
const JWT_BIOMETRIC_SECRET  = process.env.JWT_BIOMETRIC_SECRET  || 'seg4_biometric_secret_key_2024';
const JWT_SESSION_EXPIRES   = '2h';   // Token de sesión: corta vida
const JWT_BIOMETRIC_EXPIRES = '365d'; // Token biométrico: larga vida
const NPOINT_URL = 'https://api.npoint.io/4bcd8e73c1067cb36360';

// ─── Base de Datos ────────────────────────────────────────────────────────────

const db = new Database('seg4.db');

/**
 * Inicializa el esquema relacional.
 * Se ejecuta una sola vez al arrancar el servidor.
 */
function initDatabase() {
  // Tabla de usuarios
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      username        TEXT    NOT NULL UNIQUE,
      password_hash   TEXT    NOT NULL,
      biometric_token TEXT,            -- JWT de larga vida; NULL = biometría deshabilitada
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Tabla de artículos (almacenamiento obligatorio del JSON de npoint)
  db.exec(`
    CREATE TABLE IF NOT EXISTS articulos (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      articulo    TEXT    NOT NULL,
      precio      REAL    NOT NULL,
      descuento   REAL    NOT NULL DEFAULT 0,
      urlimagen   TEXT,
      valoracion  REAL    NOT NULL DEFAULT 0,
      calificaciones INTEGER NOT NULL DEFAULT 0,
      descripcion TEXT,
      synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Usuario de prueba (admin / 1234)
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!existing) {
    const hash = bcrypt.hashSync('1234', 10);
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('admin', hash);
    console.log('✅ Usuario de prueba creado: admin / 1234');
  }

  console.log('✅ Base de datos inicializada');
}

// ─── Sincronización de Artículos ──────────────────────────────────────────────

/**
 * Descarga el JSON de npoint y lo persiste en la tabla `articulos`.
 * Si ya hay datos, los reemplaza para mantener sincronía.
 */
async function syncArticulos() {
  try {
    const { data } = await axios.get(NPOINT_URL, { timeout: 10000 });
    if (!data?.articulos?.length) return;

    // Limpia la tabla y reinsertar (estrategia simple de sincronización)
    db.exec('DELETE FROM articulos');

    const insert = db.prepare(`
      INSERT INTO articulos (articulo, precio, descuento, urlimagen, valoracion, calificaciones, descripcion)
      VALUES (@articulo, @precio, @descuento, @urlimagen, @valoracion, @calificaciones, @descripcion)
    `);

    const insertMany = db.transaction((items) => {
      for (const item of items) {
        insert.run({
          articulo:      item.articulo,
          precio:        parseFloat(item.precio)      || 0,
          descuento:     parseFloat(item.descuento)   || 0,
          urlimagen:     item.urlimagen               || '',
          valoracion:    parseFloat(item.valoracion)  || 0,
          calificaciones: parseInt(item.calificaciones) || 0,
          descripcion:   item.descripcion             || '',
        });
      }
    });

    insertMany(data.articulos);
    console.log(`✅ ${data.articulos.length} artículos sincronizados desde npoint`);
  } catch (err) {
    console.error('⚠️  No se pudo sincronizar artículos:', err.message);
  }
}

// ─── Middlewares ──────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json());

/**
 * Middleware de autenticación de sesión.
 * Extrae y verifica el JWT de sesión (corta vida) del header Authorization.
 * Si es válido, adjunta el payload a req.user.
 */
function requireSessionAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token de sesión requerido' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SESSION_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token de sesión inválido o expirado' });
  }
}

// ─── Rutas de Autenticación ───────────────────────────────────────────────────

/**
 * POST /auth/login
 * Autenticación clásica usuario + clave.
 * Retorna un JWT de sesión (corta vida, NO se persiste en la app).
 *
 * Body: { username: string, password: string }
 * Response: { sessionToken: string, biometricToken: string|null }
 */
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y clave son requeridos' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  const sessionToken = jwt.sign(
    { userId: user.id, username: user.username, type: 'session' },
    JWT_SESSION_SECRET,
    { expiresIn: JWT_SESSION_EXPIRES }
  );

  // Devuelve también el token biométrico si ya existe
  res.json({
    sessionToken,
    biometricToken: user.biometric_token || null
  });
});

/**
 * POST /auth/enable-biometric
 * Habilita la autenticación biométrica para el usuario.
 * Requiere usuario + clave válidos. Genera y almacena el JWT de larga vida.
 *
 * Body: { username: string, password: string }
 * Response: { biometricToken: string }
 */
app.post('/auth/enable-biometric', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y clave son requeridos' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  const biometricToken = jwt.sign(
    { userId: user.id, username: user.username, type: 'biometric' },
    JWT_BIOMETRIC_SECRET,
    { expiresIn: JWT_BIOMETRIC_EXPIRES }
  );

  db.prepare('UPDATE users SET biometric_token = ? WHERE id = ?').run(biometricToken, user.id);

  res.json({ biometricToken });
});

/**
 * POST /auth/login-biometric
 */
app.post('/auth/login-biometric', (req, res) => {
  const { biometricToken } = req.body;
  if (!biometricToken) {
    return res.status(400).json({ error: 'Token biométrico requerido' });
  }

  let payload;
  try {
    payload = jwt.verify(biometricToken, JWT_BIOMETRIC_SECRET);
  } catch {
    return res.status(401).json({ error: 'Token biométrico inválido o expirado' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.userId);
  if (!user || user.biometric_token !== biometricToken) {
    return res.status(401).json({ error: 'Autenticación biométrica no habilitada o token revocado' });
  }

  const sessionToken = jwt.sign(
    { userId: user.id, username: user.username, type: 'session' },
    JWT_SESSION_SECRET,
    { expiresIn: JWT_SESSION_EXPIRES }
  );

  res.json({ sessionToken });
});

/**
 * POST /auth/disable-biometric
 */
app.post('/auth/disable-biometric', requireSessionAuth, (req, res) => {
  db.prepare('UPDATE users SET biometric_token = NULL WHERE id = ?').run(req.user.userId);
  res.json({ message: 'Autenticación biométrica deshabilitada exitosamente' });
});

// ─── Rutas protegidas ─────────────────────────────────────────────────────────

app.get('/api/articulos', requireSessionAuth, (req, res) => {
  const articulos = db.prepare('SELECT * FROM articulos ORDER BY articulo ASC').all();
  res.json({ articulos });
});

app.get('/api/ofertas', requireSessionAuth, (req, res) => {
  const ofertas = db.prepare('SELECT * FROM articulos WHERE descuento > 0 ORDER BY descuento DESC').all();
  res.json({ ofertas });
});

app.post('/api/sync', requireSessionAuth, async (req, res) => {
  await syncArticulos();
  const count = db.prepare('SELECT COUNT(*) as total FROM articulos').get();
  res.json({ message: 'Sincronización completada', total: count.total });
});

// ─── Arranque ─────────────────────────────────────────────────────────────────

initDatabase();
syncArticulos().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  });
});