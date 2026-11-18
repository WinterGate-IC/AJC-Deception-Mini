"""Optional bounded TCP tarpit / ghost listener.

This is deliberately small: a fixed connection cap, a hard hold deadline, and
no payload parsing.  It never touches another host.  Disabled by default; the
HTTP server has its own bounded application-level tarpit.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

from . import util


def rst_socket(sock) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class TarpitListener:
    def __init__(self, bind: str = "127.0.0.1", port: int = 8788,
                 mode: str = "tarpit", hold_seconds: float = 20.0,
                 max_conns: int = 64, rcvbuf: int = 1024):
        self.bind = bind
        self.port = int(port)
        self.mode = mode if mode in ("tarpit", "ghost", "rst") else "tarpit"
        self.hold_seconds = max(1.0, min(120.0, float(hold_seconds)))
        self.max_conns = max(1, min(1024, int(max_conns)))
        self.rcvbuf = max(256, min(65535, int(rcvbuf)))
        self._stop = threading.Event()
        self._sock = None
        self._sem = threading.Semaphore(self.max_conns)
        self._thread = None
        self.stats = {"accepted": 0, "held": 0, "rejected": 0, "reset": 0, "errors": 0}

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind, self.port))
        s.listen(128)
        s.settimeout(1.0)
        self._sock = s
        self._thread = threading.Thread(target=self._run, name="ajc-tarpit", daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                self.stats["rejected"] += 1
                rst_socket(conn)
                continue
            t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
            t.start()

    def _handle(self, conn, addr):
        try:
            self.stats["accepted"] += 1
            conn.settimeout(1.0)
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
            except OSError:
                pass
            if self.mode == "rst":
                self.stats["reset"] += 1
                rst_socket(conn)
                return
            if self.mode == "ghost":
                try:
                    conn.recv(64)
                except OSError:
                    pass
            # tarpit: never read; the kernel fills the tiny receive window and
            # advertises zero, so the peer blocks.  Hard deadline always applies.
            self.stats["held"] += 1
            end = time.time() + self.hold_seconds
            while time.time() < end and not self._stop.is_set():
                time.sleep(0.25)
            rst_socket(conn)
            self.stats["reset"] += 1
        except Exception:
            self.stats["errors"] += 1
            try:
                conn.close()
            except OSError:
                pass
        finally:
            self._sem.release()

    def stop(self):
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=2.0)
        return self.stats
