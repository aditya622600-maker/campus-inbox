import session from "express-session";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import pg from "pg";

const { Pool } = pg;
const sessionLifetimeMs = 7 * 24 * 60 * 60 * 1000;

function expiresAtFor(value) {
  return value.cookie?.expires
    ? new Date(value.cookie.expires).getTime()
    : Date.now() + (value.cookie?.maxAge || sessionLifetimeMs);
}

class SQLiteSessionStore extends session.Store {
  constructor(database) {
    super();
    this.database = database;
    this.cleanupExpired();
    const timer = setInterval(() => this.cleanupExpired(), 15 * 60 * 1000);
    timer.unref();
  }

  cleanupExpired() {
    this.database.prepare("DELETE FROM user_sessions WHERE expires_at <= ?").run(Date.now());
  }

  get(sid, callback) {
    try {
      const row = this.database.prepare("SELECT session_json, expires_at FROM user_sessions WHERE sid = ?").get(sid);
      if (!row || Number(row.expires_at) <= Date.now()) {
        if (row) this.destroy(sid, () => {});
        return callback(null, null);
      }
      callback(null, JSON.parse(row.session_json));
    } catch (error) {
      callback(error);
    }
  }

  set(sid, value, callback = () => {}) {
    try {
      this.database.prepare(`
        INSERT INTO user_sessions (sid, session_json, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET session_json = excluded.session_json, expires_at = excluded.expires_at
      `).run(sid, JSON.stringify(value), expiresAtFor(value));
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  destroy(sid, callback = () => {}) {
    try {
      this.database.prepare("DELETE FROM user_sessions WHERE sid = ?").run(sid);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  touch(sid, value, callback = () => {}) {
    this.set(sid, value, callback);
  }
}

class PostgresSessionStore extends session.Store {
  constructor(pool) {
    super();
    this.pool = pool;
    this.cleanupExpired();
    const timer = setInterval(() => this.cleanupExpired(), 15 * 60 * 1000);
    timer.unref();
  }

  cleanupExpired() {
    this.pool.query("DELETE FROM user_sessions WHERE expires_at <= $1", [Date.now()]).catch(error => {
      console.warn("Session cleanup failed:", error.message);
    });
  }

  get(sid, callback) {
    this.pool.query("SELECT session_json, expires_at FROM user_sessions WHERE sid = $1", [sid])
      .then(({ rows }) => {
        const row = rows[0];
        if (!row || Number(row.expires_at) <= Date.now()) {
          if (row) this.destroy(sid, () => {});
          return callback(null, null);
        }
        callback(null, row.session_json);
      })
      .catch(callback);
  }

  set(sid, value, callback = () => {}) {
    this.pool.query(`
      INSERT INTO user_sessions (sid, session_json, expires_at)
      VALUES ($1, $2::jsonb, $3)
      ON CONFLICT(sid) DO UPDATE SET session_json = excluded.session_json, expires_at = excluded.expires_at
    `, [sid, JSON.stringify(value), expiresAtFor(value)])
      .then(() => callback(null))
      .catch(callback);
  }

  destroy(sid, callback = () => {}) {
    this.pool.query("DELETE FROM user_sessions WHERE sid = $1", [sid])
      .then(() => callback(null))
      .catch(callback);
  }

  touch(sid, value, callback = () => {}) {
    this.set(sid, value, callback);
  }
}

function mapRows(rows) {
  return Object.fromEntries(rows.map(row => [row.id, {
    id:row.id,
    sender:row.sender,
    subject:row.subject,
    preview:row.preview,
    date:row.received_at,
    initials:row.initials,
    priority:row.priority,
    reason:row.reason,
  }]));
}

function createSQLiteStorage(dataDirectory) {
  fs.mkdirSync(dataDirectory, { recursive:true });
  const database = new DatabaseSync(path.join(dataDirectory, "campus-inbox.db"));
  database.exec("PRAGMA journal_mode = WAL");
  database.exec("PRAGMA foreign_keys = ON");
  database.exec(`
    CREATE TABLE IF NOT EXISTS email_cache (
      owner_id TEXT NOT NULL,
      id TEXT NOT NULL,
      sender TEXT NOT NULL,
      subject TEXT NOT NULL,
      preview TEXT NOT NULL,
      received_at TEXT NOT NULL,
      initials TEXT NOT NULL,
      priority TEXT NOT NULL CHECK (priority IN ('critical', 'moderate', 'low')),
      reason TEXT NOT NULL,
      cached_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (owner_id, id)
    );
    CREATE INDEX IF NOT EXISTS idx_email_cache_owner_received ON email_cache(owner_id, received_at DESC);
    CREATE TABLE IF NOT EXISTS user_sessions (
      sid TEXT PRIMARY KEY,
      session_json TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
  `);

  return {
    kind:"SQLite",
    sessionStore:new SQLiteSessionStore(database),
    async health() { database.prepare("SELECT 1").get(); },
    async readEmailCache(ownerId) {
      return mapRows(database.prepare("SELECT id, sender, subject, preview, received_at, initials, priority, reason FROM email_cache WHERE owner_id = ?").all(ownerId));
    },
    async writeEmailCache(ownerId, cache) {
      const insert = database.prepare(`
        INSERT INTO email_cache (owner_id, id, sender, subject, preview, received_at, initials, priority, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare("DELETE FROM email_cache WHERE owner_id = ?").run(ownerId);
        for (const email of Object.values(cache)) insert.run(ownerId, email.id, email.sender, email.subject, email.preview, email.date, email.initials, email.priority, email.reason);
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
    },
    async deleteOwnerData(ownerId) {
      return Number(database.prepare("DELETE FROM email_cache WHERE owner_id = ?").run(ownerId).changes);
    },
    async close() { database.close(); },
  };
}

async function createPostgresStorage(connectionString) {
  const pool = new Pool({ connectionString, max:5, idleTimeoutMillis:30_000 });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_cache (
      owner_id TEXT NOT NULL,
      id TEXT NOT NULL,
      sender TEXT NOT NULL,
      subject TEXT NOT NULL,
      preview TEXT NOT NULL,
      received_at TEXT NOT NULL,
      initials TEXT NOT NULL,
      priority TEXT NOT NULL CHECK (priority IN ('critical', 'moderate', 'low')),
      reason TEXT NOT NULL,
      cached_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (owner_id, id)
    );
    CREATE INDEX IF NOT EXISTS idx_email_cache_owner_received ON email_cache(owner_id, received_at DESC);
    CREATE TABLE IF NOT EXISTS user_sessions (
      sid TEXT PRIMARY KEY,
      session_json JSONB NOT NULL,
      expires_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
  `);

  return {
    kind:"PostgreSQL",
    sessionStore:new PostgresSessionStore(pool),
    async health() { await pool.query("SELECT 1"); },
    async readEmailCache(ownerId) {
      const { rows } = await pool.query("SELECT id, sender, subject, preview, received_at, initials, priority, reason FROM email_cache WHERE owner_id = $1", [ownerId]);
      return mapRows(rows);
    },
    async writeEmailCache(ownerId, cache) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("DELETE FROM email_cache WHERE owner_id = $1", [ownerId]);
        for (const email of Object.values(cache)) {
          await client.query(`
            INSERT INTO email_cache (owner_id, id, sender, subject, preview, received_at, initials, priority, reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
          `, [ownerId, email.id, email.sender, email.subject, email.preview, email.date, email.initials, email.priority, email.reason]);
        }
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    },
    async deleteOwnerData(ownerId) {
      const result = await pool.query("DELETE FROM email_cache WHERE owner_id = $1", [ownerId]);
      return result.rowCount;
    },
    async close() { await pool.end(); },
  };
}

export async function createStorage({ dataDirectory, databaseUrl }) {
  return databaseUrl
    ? createPostgresStorage(databaseUrl)
    : createSQLiteStorage(dataDirectory);
}
