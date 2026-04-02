import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { sanitizeEntry, validateEntry } from "./src/totp.js";

function rowToEntry(row) {
  return sanitizeEntry(row);
}

export class EntryStore {
  constructor(dbPath) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS entries (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        account TEXT NOT NULL,
        issuer TEXT NOT NULL,
        secret TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        digits INTEGER NOT NULL,
        period INTEGER NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        website TEXT NOT NULL DEFAULT '',
        createdAt INTEGER NOT NULL,
        updatedAt INTEGER NOT NULL
      );
    `);

    this.selectAllStatement = this.db.prepare(`
      SELECT id, label, account, issuer, secret, algorithm, digits, period, notes, website, createdAt, updatedAt
      FROM entries
      ORDER BY
        CASE WHEN issuer = '' THEN 1 ELSE 0 END,
        issuer COLLATE NOCASE,
        label COLLATE NOCASE,
        createdAt ASC
    `);
    this.deleteAllStatement = this.db.prepare("DELETE FROM entries");
    this.insertStatement = this.db.prepare(`
      INSERT INTO entries (
        id, label, account, issuer, secret, algorithm, digits, period, notes, website, createdAt, updatedAt
      ) VALUES (
        @id, @label, @account, @issuer, @secret, @algorithm, @digits, @period, @notes, @website, @createdAt, @updatedAt
      )
    `);
  }

  listEntries() {
    return this.selectAllStatement.all().map((row) => rowToEntry(row));
  }

  replaceEntries(entries) {
    const normalizedEntries = entries.map((entry) => {
      const normalizedEntry = sanitizeEntry(entry);
      validateEntry(normalizedEntry);
      return normalizedEntry;
    });

    this.db.exec("BEGIN");
    try {
      this.deleteAllStatement.run();
      for (const entry of normalizedEntries) {
        this.insertStatement.run(entry);
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }

    return this.listEntries();
  }

  close() {
    this.db.close();
  }
}
