"""Durable local state, event log and hash-chained evidence.

The portable build never needs a database.  JSON documents are written
atomically, JSONL logs are append-only, and a per-file cross-process lock keeps
two workers from clobbering each other.
"""
from __future__ import annotations

import copy
import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import util

try:  # POSIX
    import fcntl  # type: ignore
except Exception:  # pragma: no cover - Windows
    fcntl = None
try:
    import msvcrt  # type: ignore
except Exception:  # pragma: no cover - POSIX
    msvcrt = None


def _empty_state() -> dict:
    return {
        "ts": util.now(),
        "ips": {},
        "layer_hits": {},
        "total_penetrations": 0,
        "counters": {},
        "campaigns": {},
        "deny": {},
        "novel_payloads": {},
        "last_event": None,
    }


def _empty_memory() -> dict:
    return {
        "ts": util.now(),
        "stats": {},
        "decisions": [],
        "lessons": [],
        "rules": [],
        "methods": [],
        "theories": [],
        "profiles": {},
        "evolutions": [],
        "reflections": [],
    }


class Store:
    def __init__(self, data_dir):
        self.root = Path(data_dir)
        util.ensure_dir(self.root, 0o700)
        for sub in ("logs", "notices", "reports", "web", "exports", "sessions"):
            util.ensure_dir(self.root / sub, 0o700)
        self.state_path = self.root / "state.json"
        self.memory_path = self.root / "memory.json"
        self.events_path = self.root / "logs" / "events.jsonl"
        self.evidence_path = self.root / "logs" / "evidence.jsonl"
        self.deny_path = self.root / "deny.txt"
        self._thread_lock = threading.RLock()
        self._ensure(self.state_path, _empty_state)
        self._ensure(self.memory_path, _empty_memory)

    # ── files / locking ──────────────────────────────────────────
    def _ensure(self, path: Path, factory):
        if not path.exists():
            util.atomic_write_json(path, factory())

    def _backup_corrupt(self, path: Path):
        try:
            if path.exists() and path.stat().st_size:
                os.replace(path, path.with_name(path.name + ".corrupt-" + str(int(time.time()))))
        except OSError:
            pass

    @contextmanager
    def _lock(self, name: str, timeout: float = 8.0):
        lock_path = self.root / (".%s.lock" % name)
        fh = open(lock_path, "a+b")
        deadline = time.time() + timeout
        acquired = False
        try:
            if fcntl is not None:
                while True:
                    try:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except OSError:
                        if time.time() >= deadline:
                            break
                        time.sleep(0.02)
            elif msvcrt is not None:  # pragma: no cover
                while True:
                    try:
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                        acquired = True
                        break
                    except OSError:
                        if time.time() >= deadline:
                            break
                        time.sleep(0.02)
            else:
                acquired = True
            with self._thread_lock:
                yield
        finally:
            if acquired:
                try:
                    if fcntl is not None:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    elif msvcrt is not None:  # pragma: no cover
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            fh.close()

    def _load(self, path: Path, factory):
        try:
            data = util.read_json(path)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        self._backup_corrupt(path)
        data = factory()
        util.atomic_write_json(path, data)
        return data

    # ── state ────────────────────────────────────────────────────
    def load_state(self, with_lock: bool = False) -> dict:
        if with_lock:
            with self._lock("state"):
                return self._load(self.state_path, _empty_state)
        return self._load(self.state_path, _empty_state)

    def save_state(self, state: dict) -> None:
        state["ts"] = util.now()
        util.atomic_write_json(self.state_path, state)

    def update_state(self, mutator, default_factory=_empty_state) -> dict:
        with self._lock("state"):
            state = self._load(self.state_path, default_factory)
            backup = copy.deepcopy(state)
            try:
                out = mutator(state)
                if isinstance(out, dict):
                    state = out
            except Exception:
                state = backup
                raise
            self.save_state(state)
            return state

    # ── memory ───────────────────────────────────────────────────
    def load_memory(self) -> dict:
        return self._load(self.memory_path, _empty_memory)

    def save_memory(self, memory: dict) -> None:
        memory["ts"] = util.now()
        util.atomic_write_json(self.memory_path, memory)

    def update_memory(self, mutator, default_factory=_empty_memory) -> dict:
        with self._lock("memory"):
            memory = self._load(self.memory_path, default_factory)
            backup = copy.deepcopy(memory)
            try:
                out = mutator(memory)
                if isinstance(out, dict):
                    memory = out
            except Exception:
                memory = backup
                raise
            self.save_memory(memory)
            return memory

    # ── logs ─────────────────────────────────────────────────────
    def append_event(self, record: dict) -> None:
        with self._thread_lock:
            util.append_line(self.events_path, json.dumps(record, ensure_ascii=False, separators=(",", ":")))

    def read_events(self, limit: int = 100) -> list:
        lines = util.tail_lines(self.events_path, limit)
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        return out

    def append_evidence(self, record: dict) -> dict:
        """Append to a hash chain: each record commits to the previous hash."""
        with self._lock("evidence"):
            prev = ""
            try:
                lines = util.tail_lines(self.evidence_path, 1)
                if lines:
                    prev = json.loads(lines[-1]).get("hash", "")
            except Exception:
                prev = ""
            body = dict(record)
            body.pop("hash", None)
            body["prev"] = prev
            body["ts"] = body.get("ts") or util.now()
            body["hash"] = util.sha256_text(util.dumps(body))
            util.append_line(self.evidence_path, json.dumps(body, ensure_ascii=False, separators=(",", ":")))
            return body

    def verify_evidence(self) -> dict:
        prev = ""
        count = 0
        bad = []
        try:
            with open(self.evidence_path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    try:
                        rec = json.loads(line)
                    except Exception:
                        bad.append({"line": i, "reason": "json"})
                        continue
                    body = dict(rec)
                    got = body.pop("hash", "")
                    if body.get("prev", "") != prev:
                        bad.append({"line": i, "reason": "prev"})
                    want = util.sha256_text(util.dumps(body))
                    if got != want:
                        bad.append({"line": i, "reason": "hash"})
                    prev = got
                    count += 1
        except FileNotFoundError:
            return {"ok": True, "records": 0, "bad": []}
        return {"ok": not bad, "records": count, "bad": bad[:20]}

    # ── denial list ──────────────────────────────────────────────
    def load_deny(self) -> dict:
        state = self.load_state()
        return dict(state.get("deny") or {})

    def add_deny(self, ip: str, ttl: int = 86400, reason: str = "") -> None:
        ttl = max(0, int(ttl or 0))
        until = util.now() + ttl if ttl else 0

        def _mut(state):
            state.setdefault("deny", {})[ip] = {"until": until, "reason": util.truncate(reason, 120)}
            return state

        self.update_state(_mut)

    def is_denied(self, ip: str) -> bool:
        rec = self.load_deny().get(ip)
        if not rec:
            return False
        until = util.safe_int(rec.get("until"), 0)
        return until == 0 or until > util.now()

    # ── retention ────────────────────────────────────────────────
    def prune(self, limits: dict) -> dict:
        removed = {}
        limits = limits or {}

        def _state(state):
            ips = state.setdefault("ips", {})
            max_ips = util.safe_int(limits.get("max_ips"), 50000)
            if len(ips) > max_ips:
                order = sorted(ips.items(), key=lambda kv: kv[1].get("last_seen", 0))
                drop = len(ips) - max_ips
                for k, _ in order[:drop]:
                    ips.pop(k, None)
                removed["ips"] = drop
            now = util.now()
            deny = state.setdefault("deny", {})
            for ip in [k for k, v in deny.items() if util.safe_int(v.get("until"), 0) and v["until"] <= now]:
                deny.pop(ip, None)
            return state

        self.update_state(_state)

        def _mem(mem):
            for key, limit_key in (("decisions", "max_decisions"),
                                   ("lessons", "max_lessons"),
                                   ("rules", "max_decisions"),
                                   ("theories", "max_lessons"),
                                   ("evolutions", "max_lessons"),
                                   ("reflections", "max_lessons")):
                arr = mem.get(key) or []
                limit = util.safe_int(limits.get(limit_key), 2000)
                if len(arr) > limit:
                    removed[key] = len(arr) - limit
                    mem[key] = arr[-limit:]
            profiles = mem.get("profiles") or {}
            max_profiles = util.safe_int(limits.get("max_profiles"), 5000)
            if len(profiles) > max_profiles:
                order = sorted(profiles.items(), key=lambda kv: kv[1].get("last_seen", 0))
                drop = len(profiles) - max_profiles
                for k, _ in order[:drop]:
                    profiles.pop(k, None)
                removed["profiles"] = drop
            return mem

        self.update_memory(_mem)
        return removed

    # ── notices ──────────────────────────────────────────────────
    def write_notice(self, ip: str, text: str) -> Path:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in ip)[:80] or "unknown"
        path = self.root / "notices" / ("%s_%d.txt" % (safe, int(util.now())))
        util.atomic_write_text(path, text, mode=0o600)
        return path

    def stats(self) -> dict:
        state = self.load_state()
        memory = self.load_memory()
        return {
            "ts": util.now(),
            "ips": len(state.get("ips") or {}),
            "total_attempts": sum(util.safe_int(v.get("total_attempts")) for v in (state.get("ips") or {}).values()),
            "total_penetrations": util.safe_int(state.get("total_penetrations")),
            "denied": len(state.get("deny") or {}),
            "decisions": len(memory.get("decisions") or []),
            "methods": len(memory.get("methods") or []),
            "lessons": len(memory.get("lessons") or []),
            "rules": len(memory.get("rules") or []),
            "theories": len(memory.get("theories") or []),
            "profiles": len(memory.get("profiles") or {}),
            "counters": dict(state.get("counters") or {}),
        }
