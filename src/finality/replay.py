"""SQLite-backed single-use state with atomic reservation and completion."""

from __future__ import annotations

import sqlite3
import threading
import time

from .profile import ReplayDetected


class ReplayStore:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("CREATE TABLE IF NOT EXISTS consumed (scope TEXT NOT NULL, nonce BLOB NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL, PRIMARY KEY(scope, nonce))")
        self._db.execute("CREATE TABLE IF NOT EXISTS effects (transaction_id TEXT PRIMARY KEY, body BLOB NOT NULL, committed_at INTEGER NOT NULL)")
        self._lock = threading.Lock()

    def reserve(self, scope: str, nonce: bytes, expires: int, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("DELETE FROM consumed WHERE expires < ?", (now,))
                self._db.execute("INSERT INTO consumed(scope,nonce,expires,state) VALUES(?,?,?,'reserved')", (scope, nonce, expires))
                self._db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._db.execute("ROLLBACK")
                raise ReplayDetected("execution handle already consumed") from exc
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def complete(self, scope: str, nonce: bytes) -> None:
        with self._lock:
            changed = self._db.execute("UPDATE consumed SET state='complete' WHERE scope=? AND nonce=? AND state='reserved'", (scope, nonce)).rowcount
            if changed != 1:
                raise RuntimeError("replay reservation is absent or invalid")

    def effectuate(self, scope: str, nonce: bytes, expires: int, transaction_id: str, body: bytes, now: int | None = None) -> None:
        """Atomically consume authority and commit the protected test effect."""
        now = int(time.time()) if now is None else now
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("DELETE FROM consumed WHERE expires < ?", (now,))
                self._db.execute("INSERT INTO consumed(scope,nonce,expires,state) VALUES(?,?,?,'complete')", (scope, nonce, expires))
                self._db.execute("INSERT INTO effects(transaction_id,body,committed_at) VALUES(?,?,?)", (transaction_id, body, now))
                self._db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._db.execute("ROLLBACK")
                raise ReplayDetected("execution handle or transaction already consumed") from exc
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def effect_count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM effects").fetchone()[0])

    def close(self) -> None:
        self._db.close()
