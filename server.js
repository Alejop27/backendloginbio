/**
 * Seg4 Backend Completo
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

/* ================= CONFIG ================= */

const PORT = process.env.PORT || 3000;

const JWT_SESSION_SECRET =
  process.env.JWT_SESSION_SECRET ||
  'seg4_session_secret';

const JWT_BIOMETRIC_SECRET =
  process.env.JWT_BIOMETRIC_SECRET ||
  'seg4_biometric_secret';

const SESSION_EXPIRES = '15m';
const BIOMETRIC_EXPIRES = '30d';

const NPOINT_URL =
  'https://api.npoint.io/4bcd8e73c1067cb36360';

/* ================= MIDDLEWARE ================= */

app.use(helmet());

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: [
    'Authorization',
    'Content-Type'
  ]
}));

app.use(express.json());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
  })
);

/* ================= DATABASE ================= */

const db = new Database('seg4.db');

function initDB() {

  db.exec(`
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE NOT NULL,
password_hash TEXT NOT NULL,
biometric_enabled INTEGER DEFAULT 0,
token_version INTEGER DEFAULT 1,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
updated_at DATETIME,
last_login DATETIME
)
`);

  db.exec(`
CREATE TABLE IF NOT EXISTS articulos(
id INTEGER PRIMARY KEY AUTOINCREMENT,
articulo TEXT,
precio REAL,
descuento REAL DEFAULT 0,
urlimagen TEXT,
valoracion REAL DEFAULT 0,
calificaciones INTEGER DEFAULT 0,
descripcion TEXT,
synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`);

  const admin = db
    .prepare(
      `SELECT id FROM users WHERE username=?`
    )
    .get('admin');

  if (!admin) {

    const hash = bcrypt.hashSync(
      '1234',
      10
    );

    db.prepare(`
INSERT INTO users(
username,
password_hash
)
VALUES(?,?)
`)
      .run(
        'admin',
        hash
      );

    console.log(
      'usuario admin creado'
    );
  }

}

/* ================= TOKENS ================= */

function createSessionToken(user) {

  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      tokenVersion: user.token_version,
      scope: 'access'
    },
    JWT_SESSION_SECRET,
    {
      expiresIn: SESSION_EXPIRES
    }
  );

}

function createBiometricToken(user) {

  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      tokenVersion: user.token_version,
      scope: 'biometric'
    },
    JWT_BIOMETRIC_SECRET,
    {
      expiresIn: BIOMETRIC_EXPIRES
    }
  );

}

/* ================= AUTH MIDDLEWARE ================= */

function requireSessionAuth(
  req,
  res,
  next
) {

  const auth =
    req.headers.authorization;

  if (
    !auth ||
    !auth.startsWith(
      'Bearer '
    )
  ) {
    return res.status(401).json({
      error: 'Token requerido'
    });
  }

  try {

    const token =
      auth.split(' ')[1];

    const decoded =
      jwt.verify(
        token,
        JWT_SESSION_SECRET
      );

    if (
      decoded.scope !== 'access'
    ) {
      return res.status(401).json({
        error: 'Token inválido'
      });
    }

    const user = db.prepare(`
SELECT *
FROM users
WHERE id=?
`).get(
      decoded.sub
    );

    if (!user) {
      return res.status(401).json({
        error: 'Usuario no existe'
      });
    }

    if (
      decoded.tokenVersion !==
      user.token_version
    ) {
      return res.status(401).json({
        error: 'Token revocado'
      });
    }

    req.user = user;

    next();

  } catch (e) {

    return res.status(401).json({
      error: 'Token inválido o expirado'
    });

  }

}

/* ================= SYNC ================= */

async function syncArticulos() {

  try {

    const response =
      await axios.get(
        NPOINT_URL,
        {
          timeout: 10000
        }
      );

    const data = response.data;

    if (
      !data?.articulos?.length
    ) {
      return;
    }

    db.exec(
      'DELETE FROM articulos'
    );

    const insert =
      db.prepare(`
INSERT INTO articulos(
articulo,
precio,
descuento,
urlimagen,
valoracion,
calificaciones,
descripcion
)
VALUES(
@articulo,
@precio,
@descuento,
@urlimagen,
@valoracion,
@calificaciones,
@descripcion
)
`);

    const tx =
      db.transaction(
        (items) => {

          for (
            const item of items
          ) {

            insert.run({
              articulo:
                item.articulo || '',

              precio:
                parseFloat(
                  item.precio
                ) || 0,

              descuento:
                parseFloat(
                  item.descuento
                ) || 0,

              urlimagen:
                item.urlimagen || '',

              valoracion:
                parseFloat(
                  item.valoracion
                ) || 0,

              calificaciones:
                parseInt(
                  item.calificaciones
                ) || 0,

              descripcion:
                item.descripcion || ''
            });

          }

        }
      );

    tx(
      data.articulos
    );

    console.log(
      'articulos sincronizados'
    );

  } catch (e) {

    console.log(
      'error sync',
      e.message
    );

  }

}

/* ================= AUTH ROUTES ================= */

/* login clásico */
app.post(
  '/auth/login',
  (req, res) => {

    const {
      username,
      password
    } = req.body;

    if (
      !username ||
      !password
    ) {
      return res.status(400).json({
        error:
          'usuario y clave requeridos'
      });
    }

    const user =
      db.prepare(`
SELECT *
FROM users
WHERE username=?
`)
        .get(username);

    if (
      !user ||
      !bcrypt.compareSync(
        password,
        user.password_hash
      )
    ) {
      return res.status(401).json({
        error:
          'Credenciales incorrectas'
      });
    }

    db.prepare(`
UPDATE users
SET
last_login=CURRENT_TIMESTAMP
WHERE id=?
`).run(
      user.id
    );

    const sessionToken =
      createSessionToken(
        user
      );

    res.json({
      sessionToken,
      biometricEnabled:
        !!user.biometric_enabled
    });

  }
);

/* habilitar biometría */
app.post(
  '/auth/enable-biometric',
  (req, res) => {

    const {
      username,
      password
    } = req.body;

    const user =
      db.prepare(`
SELECT *
FROM users
WHERE username=?
`).get(
        username
      );

    if (
      !user ||
      !bcrypt.compareSync(
        password,
        user.password_hash
      )
    ) {
      return res.status(401).json({
        error:
          'Credenciales incorrectas'
      });
    }

    db.prepare(`
UPDATE users
SET
biometric_enabled=1,
updated_at=CURRENT_TIMESTAMP
WHERE id=?
`).run(
      user.id
    );

    const biometricToken =
      createBiometricToken(
        user
      );

    res.json({
      biometricToken
    });

  }
);

/* login biométrico */
app.post(
  '/auth/login-biometric',
  (req, res) => {

    const {
      biometricToken
    } = req.body;

    if (!biometricToken) {
      return res.status(400).json({
        error:
          'Token biométrico requerido'
      });
    }

    try {

      const decoded =
        jwt.verify(
          biometricToken,
          JWT_BIOMETRIC_SECRET
        );

      if (
        decoded.scope !== 'biometric'
      ) {
        return res.status(401).json({
          error: 'Token inválido'
        });
      }

      const user =
        db.prepare(`
SELECT *
FROM users
WHERE id=?
`).get(
          decoded.sub
        );

      if (
        !user ||
        !user.biometric_enabled
      ) {
        return res.status(401).json({
          error:
            'Biometría deshabilitada'
        });
      }

      if (
        decoded.tokenVersion
        !== user.token_version
      ) {
        return res.status(401).json({
          error:
            'Token revocado'
        });
      }

      const sessionToken =
        createSessionToken(
          user
        );

      res.json({
        sessionToken
      });

    } catch (e) {

      res.status(401).json({
        error:
          'Token biométrico inválido'
      });

    }

  }
);

/* deshabilitar biometría */
app.post(
  '/auth/disable-biometric',
  requireSessionAuth,
  (req, res) => {

    db.prepare(`
UPDATE users
SET
biometric_enabled=0,
token_version=
token_version+1
WHERE id=?
`).run(
      req.user.id
    );

    res.json({
      message:
        'Biometría deshabilitada'
    });

  }
);

/* logout */
app.post(
  '/auth/logout',
  requireSessionAuth,
  (req, res) => {

    db.prepare(`
UPDATE users
SET token_version=
token_version+1
WHERE id=?
`).run(
      req.user.id
    );

    res.json({
      message: 'logout ok'
    });

  }
);

/* ================= APIs PROTEGIDAS ================= */

app.get(
  '/api/articulos',
  requireSessionAuth,
  (req, res) => {

    const articulos =
      db.prepare(`
SELECT *,
ROUND(
precio-(precio*descuento/100),
2
) as precio_final
FROM articulos
ORDER BY articulo ASC
`).all();

    res.json({
      articulos
    });

  }
);

app.get(
  '/api/ofertas',
  requireSessionAuth,
  (req, res) => {

    const ofertas =
      db.prepare(`
SELECT *,
ROUND(
precio-(precio*descuento/100),
2
) as precio_final
FROM articulos
WHERE descuento>0
ORDER BY descuento DESC
`).all();

    res.json({
      ofertas
    });

  }
);

app.get(
  '/api/articulos/:id',
  requireSessionAuth,
  (req, res) => {

    const articulo =
      db.prepare(`
SELECT *,
ROUND(
precio-(precio*descuento/100),
2
) as precio_final
FROM articulos
WHERE id=?
`).get(
        req.params.id
      );

    if (!articulo) {
      return res.status(404).json({
        error: 'No encontrado'
      });
    }

    res.json(
      articulo
    );

  }
);

app.post(
  '/api/sync',
  requireSessionAuth,
  async (req, res) => {

    await syncArticulos();

    const count =
      db.prepare(`
SELECT COUNT(*) total
FROM articulos
`).get();

    res.json({
      message:
        'sync ok',
      total:
        count.total
    });

  }
);

/* ================= HEALTH ================= */

app.get(
  '/health',
  (req, res) => {
    res.json({
      status: 'ok'
    });
  }
);

/* ================= START ================= */

initDB();

syncArticulos()
  .then(() => {

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `Servidor puerto ${PORT}`
        );
      }
    );

  });