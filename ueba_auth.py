"""
ueba_auth.py — SSO login, session and role layer for the UEBA dashboard.

The dashboard has historically had no authentication at all: open `CORS(app)`,
bound to 0.0.0.0:3026, every endpoint anonymous. This module is the first half
of closing that — it accepts a signed JWT minted by the SIEM, provisions the
user on first sight, and issues a server-side session.

SCOPE — HS256 only, for now
---------------------------
Only the shared-secret (HS256) path is implemented and reachable. The RS256 /
JWKS path is what the SIEM team will eventually want, but it needs three things
we do not have yet: the cert PEM carrying `IP:103.252.168.197` in its SAN, a
confirmed JWKS URL, and a confirmed SIEM hostname. `algorithm: RS256` is
therefore rejected at config load with an explicit error rather than silently
falling back to something weaker.

SAFETY — enforcement is OFF by default
--------------------------------------
`auth.enforce` defaults to False. With it off this module registers its own
endpoints and will happily mint sessions, but it does NOT gate any pre-existing
API route. That means deploying this file cannot lock the SOC out of a live
dashboard. Turning enforcement on is a deliberate, separate step once an SSO
round-trip has been proven end to end (`/api/sso/ping` reports readiness).

Degrades gracefully when PyJWT is absent, matching the optional-dependency
convention used across this codebase (hdbscan, geoip2, orjson).
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, current_app, g, jsonify, request

log = logging.getLogger("ueba.auth")

try:
    import jwt as _jwt
    from jwt import PyJWTError
    JWT_AVAILABLE = True
except ImportError:  # pragma: no cover - degrade like the rest of the codebase
    _jwt = None
    PyJWTError = Exception
    JWT_AVAILABLE = False
    log.warning("PyJWT not installed — SSO disabled. Install: pip install 'pyjwt>=2.8,<3.0'")


# ── Role model ────────────────────────────────────────────────────────────────
# Ordered weakest → strongest; `role_at_least` compares by index so a route
# gated on "analyst" also admits "admin".
ROLES = ("viewer", "analyst", "admin")
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}


DEFAULTS = {
    "enabled":          False,      # master switch for the whole module
    "enforce":          False,      # gate pre-existing API routes (see module docstring)
    "algorithm":        "HS256",
    "secret_env":       "UEBA_SSO_SECRET",
    "issuer":           "",         # required when enabled — verified against `iss`
    "audience":         "",         # required when enabled — verified against `aud`
    "leeway_secs":      60,         # clock skew tolerance for exp/nbf/iat
    "max_token_age_secs": 300,      # reject an SSO assertion older than this even if exp is generous
    "session_ttl_secs": 28800,      # 8h
    "session_idle_secs": 3600,      # revoke after 1h of no use
    "cookie_name":      "ueba_session",
    "cookie_secure":    False,      # set true once the dashboard is behind TLS
    "cookie_samesite":  "Lax",
    "auth_db":          "/root/NEW_DRIVE/aditya_ueba/profiles/ueba_auth.db",
    "default_role":     "viewer",
    "role_claim":       "roles",    # claim holding a list[str] or space/comma-joined str
    "role_map":         {},         # {siem_group: ueba_role}
    "allow_jit":        True,       # provision unknown-but-valid subjects on first login
    # Never gated, even with enforce on. /api/health is here so the watchdog
    # (which probes it every 2 min) keeps working without a credential.
    "public_paths": [
        "/api/health",
        "/api/sso/ping",
        "/auth/sso",
        "/api/auth/sso/exchange",
    ],
}


class AuthConfigError(RuntimeError):
    """Raised at startup for a configuration that would be unsafe to run."""


# ── Config ────────────────────────────────────────────────────────────────────

def load_auth_config(raw_cfg: dict | None) -> dict:
    """Layer the `auth:` block of ueba_config.yaml onto DEFAULTS and validate."""
    cfg = dict(DEFAULTS)
    cfg["role_map"] = dict(DEFAULTS["role_map"])
    cfg["public_paths"] = list(DEFAULTS["public_paths"])

    block = {}
    if isinstance(raw_cfg, dict):
        block = raw_cfg.get("auth") or {}
    if isinstance(block, dict):
        for k, v in block.items():
            if k == "role_map" and isinstance(v, dict):
                cfg["role_map"].update(v)
            elif k == "public_paths" and isinstance(v, list):
                cfg["public_paths"] = list(v)
            else:
                cfg[k] = v

    if not cfg["enabled"]:
        return cfg

    alg = str(cfg["algorithm"]).upper()
    if alg != "HS256":
        # Explicitly refuse rather than degrade: an operator who sets RS256
        # expecting asymmetric verification must not silently get something else.
        raise AuthConfigError(
            f"auth.algorithm={alg!r} is not implemented. Only HS256 is supported "
            "today; the RS256/JWKS path is blocked pending the SIEM team's cert "
            "PEM (needs IP:103.252.168.197 in SAN), JWKS URL and SIEM host."
        )
    cfg["algorithm"] = alg

    if not cfg["issuer"] or not cfg["audience"]:
        raise AuthConfigError(
            "auth.issuer and auth.audience are both required when auth.enabled "
            "is true — without them a token minted for any other service would "
            "be accepted here."
        )
    if cfg["default_role"] not in _ROLE_RANK:
        raise AuthConfigError(f"auth.default_role={cfg['default_role']!r} not one of {ROLES}")
    for grp, role in cfg["role_map"].items():
        if role not in _ROLE_RANK:
            raise AuthConfigError(f"auth.role_map[{grp!r}]={role!r} not one of {ROLES}")
    return cfg


def get_secret(cfg: dict) -> str | None:
    """Read the shared signing secret from the environment (never from YAML)."""
    return os.environ.get(cfg.get("secret_env") or "UEBA_SSO_SECRET") or None


# ── Store ─────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    sub          TEXT PRIMARY KEY,
    username     TEXT,
    email        TEXT,
    display_name TEXT,
    role         TEXT NOT NULL DEFAULT 'viewer',
    role_pinned  INTEGER NOT NULL DEFAULT 0,
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    last_login   TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT PRIMARY KEY,
    sub          TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    remote_addr  TEXT,
    user_agent   TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_sub ON sessions(sub);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
-- Replay guard: an SSO assertion is single-use. Rows expire with the token.
CREATE TABLE IF NOT EXISTS used_assertions (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_used_exp ON used_assertions(expires_at);
"""


class AuthStore:
    """SQLite-backed identity + session store.

    Separate DB from profiles/user_profiles.db on purpose: that one holds
    behavioural baselines keyed on observed entity names and is rewritten by
    the engine at speed. Identity has a different lifecycle, a different
    blast radius, and different backup needs.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- users ------------------------------------------------------------
    def get_user(self, sub: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE sub = ?", (sub,)).fetchone()
        return dict(row) if row else None

    def upsert_user(self, sub: str, username: str, email: str,
                    display_name: str, role: str) -> dict:
        """Create on first sight, refresh profile fields on later logins.

        `role_pinned` lets an admin override the SIEM-derived role locally
        (`UPDATE users SET role=?, role_pinned=1`); once pinned, later logins
        keep the local role instead of re-deriving it from the token claims.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute("SELECT sub, role_pinned FROM users WHERE sub = ?", (sub,))
            existing = cur.fetchone()
            if existing is None:
                self._conn.execute(
                    "INSERT INTO users (sub, username, email, display_name, role, "
                    "created_at, last_login) VALUES (?,?,?,?,?,?,?)",
                    (sub, username, email, display_name, role, now, now),
                )
            elif existing["role_pinned"]:
                self._conn.execute(
                    "UPDATE users SET username=?, email=?, display_name=?, last_login=? "
                    "WHERE sub=?", (username, email, display_name, now, sub))
            else:
                self._conn.execute(
                    "UPDATE users SET username=?, email=?, display_name=?, role=?, "
                    "last_login=? WHERE sub=?",
                    (username, email, display_name, role, now, sub))
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM users WHERE sub = ?", (sub,)).fetchone()
        return dict(row)

    # -- sessions ---------------------------------------------------------
    @staticmethod
    def _hash(token: str) -> str:
        # Store only the hash: a leaked DB must not yield usable session cookies.
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, sub: str, ttl: int, remote_addr: str, user_agent: str) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions (token_hash, sub, created_at, expires_at, "
                "last_seen, remote_addr, user_agent) VALUES (?,?,?,?,?,?,?)",
                (self._hash(token), sub, now, now + ttl, now,
                 remote_addr[:64], user_agent[:256]),
            )
            self._conn.commit()
        return token

    def touch_session(self, token: str, idle_secs: int) -> dict | None:
        """Validate a session cookie and slide its idle window."""
        now = int(time.time())
        th = self._hash(token)
        with self._lock:
            row = self._conn.execute(
                "SELECT s.sub, s.expires_at, s.last_seen, u.role, u.username, "
                "u.display_name, u.email, u.active FROM sessions s "
                "JOIN users u ON u.sub = s.sub WHERE s.token_hash = ?", (th,)
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= now:
                self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                self._conn.commit()
                return None
            if idle_secs > 0 and (now - row["last_seen"]) > idle_secs:
                self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                self._conn.commit()
                return None
            if not row["active"]:
                return None
            self._conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
                               (now, th))
            self._conn.commit()
        return {"sub": row["sub"], "role": row["role"], "username": row["username"],
                "display_name": row["display_name"], "email": row["email"]}

    def revoke_session(self, token: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (self._hash(token),))
            self._conn.commit()

    def revoke_all_for(self, sub: str) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM sessions WHERE sub = ?", (sub,))
            self._conn.commit()
            return cur.rowcount

    # -- replay guard ------------------------------------------------------
    def claim_assertion(self, jti: str, expires_at: int) -> bool:
        """Record a one-time-use assertion id. False if already spent."""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO used_assertions (jti, expires_at) VALUES (?,?)",
                    (jti, expires_at))
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_expired(self) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            self._conn.execute("DELETE FROM used_assertions WHERE expires_at <= ?", (now,))
            self._conn.commit()

    def stats(self) -> dict:
        now = int(time.time())
        with self._lock:
            users = self._conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
            live = self._conn.execute(
                "SELECT COUNT(*) c FROM sessions WHERE expires_at > ?", (now,)).fetchone()["c"]
        return {"users": users, "active_sessions": live}


# ── Token verification ────────────────────────────────────────────────────────

def _extract_roles(claims: dict, role_claim: str) -> list[str]:
    """Pull group/role strings out of the claim, tolerating the usual shapes."""
    raw = claims.get(role_claim)
    if raw is None:
        return []
    if isinstance(raw, str):
        return [p for p in raw.replace(",", " ").split() if p]
    if isinstance(raw, (list, tuple)):
        return [str(p) for p in raw if p]
    return []


def map_role(claims: dict, cfg: dict) -> str:
    """Map SIEM groups → a UEBA role, taking the STRONGEST match.

    Unmapped groups fall through to default_role rather than being rejected,
    so adding a new SIEM group cannot lock out its members; it just gives them
    the least privilege until an operator maps it.
    """
    groups = _extract_roles(claims, cfg.get("role_claim") or "roles")
    role_map = cfg.get("role_map") or {}
    best = cfg.get("default_role") or "viewer"
    for grp in groups:
        mapped = role_map.get(grp)
        if mapped and _ROLE_RANK[mapped] > _ROLE_RANK[best]:
            best = mapped
    return best


def verify_sso_token(token: str, cfg: dict, secret: str) -> dict:
    """Verify an HS256 SSO assertion. Raises ValueError with a safe message."""
    if not JWT_AVAILABLE:
        raise ValueError("PyJWT is not installed on this host")
    try:
        claims = _jwt.decode(
            token,
            secret,
            algorithms=["HS256"],          # pinned — never trust the header's alg
            issuer=cfg["issuer"],
            audience=cfg["audience"],
            leeway=int(cfg.get("leeway_secs") or 0),
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except PyJWTError as e:
        # Message is deliberately coarse in the response; detail goes to the log.
        log.warning("SSO token rejected: %s", e)
        raise ValueError("token verification failed") from e

    sub = str(claims.get("sub") or "").strip()
    if not sub:
        raise ValueError("token has an empty sub")

    # Independently bound assertion age. A SIEM that mints exp=+24h would
    # otherwise hand out a token usable as a bearer credential all day.
    max_age = int(cfg.get("max_token_age_secs") or 0)
    if max_age > 0:
        iat = int(claims.get("iat") or 0)
        age = int(time.time()) - iat
        if age > max_age + int(cfg.get("leeway_secs") or 0):
            raise ValueError("assertion too old")
    return claims


# ── Blueprint ─────────────────────────────────────────────────────────────────

bp = Blueprint("ueba_auth", __name__)

_STATE: dict = {"cfg": dict(DEFAULTS), "store": None, "secret": None}


def _cfg() -> dict:
    return _STATE["cfg"]


def _store() -> AuthStore | None:
    return _STATE["store"]


def is_ready() -> tuple[bool, str]:
    """Can we actually complete an SSO exchange right now?"""
    cfg = _cfg()
    if not cfg.get("enabled"):
        return False, "auth.enabled is false"
    if not JWT_AVAILABLE:
        return False, "PyJWT not installed"
    if not _STATE["secret"]:
        return False, f"{cfg.get('secret_env')} is not set in the environment"
    if _store() is None:
        return False, "auth store failed to initialise"
    return True, "ready"


def current_user() -> dict | None:
    """The authenticated user for this request, or None."""
    if hasattr(g, "_ueba_user"):
        return g._ueba_user
    user = None
    store = _store()
    if store is not None and _cfg().get("enabled"):
        tok = request.cookies.get(_cfg().get("cookie_name") or "ueba_session")
        if tok:
            user = store.touch_session(tok, int(_cfg().get("session_idle_secs") or 0))
    g._ueba_user = user
    return user


def role_at_least(user: dict | None, minimum: str) -> bool:
    if not user:
        return False
    return _ROLE_RANK.get(user.get("role", ""), -1) >= _ROLE_RANK.get(minimum, 99)


def require_role(minimum: str = "viewer"):
    """Gate a route on a minimum role.

    A no-op while auth.enforce is off, so the decorator can be applied to
    routes ahead of the cutover without changing behaviour.
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not _cfg().get("enforce"):
                return fn(*a, **kw)
            user = current_user()
            if user is None:
                return jsonify({"error": "authentication required"}), 401
            if not role_at_least(user, minimum):
                return jsonify({"error": "insufficient role",
                                "required": minimum,
                                "have": user.get("role")}), 403
            return fn(*a, **kw)
        return wrapper
    return deco


def _is_public(path: str) -> bool:
    for p in _cfg().get("public_paths") or []:
        if path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    return False


def install_request_gate(flask_app) -> None:
    """Global gate. Only bites when auth.enforce is true."""

    @flask_app.before_request
    def _ueba_auth_gate():
        if not _cfg().get("enforce"):
            return None
        if request.method == "OPTIONS":
            return None
        path = request.path or "/"
        if _is_public(path):
            return None
        # Let the SPA shell and its static assets load unauthenticated; the
        # data endpoints behind them are what actually need gating, and the
        # bundle is not a secret. Blocking these would just yield a blank page
        # with no way to reach the login flow.
        if not path.startswith("/api/"):
            return None
        if current_user() is None:
            return jsonify({"error": "authentication required",
                            "login": "/auth/sso"}), 401
        return None


@bp.route("/api/sso/ping")
def sso_ping():
    """Readiness probe for the SSO path. Reports posture, never the secret."""
    cfg = _cfg()
    ready, reason = is_ready()
    store = _store()
    body = {
        "enabled":       bool(cfg.get("enabled")),
        "enforce":       bool(cfg.get("enforce")),
        "ready":         ready,
        "reason":        reason,
        "algorithm":     cfg.get("algorithm"),
        "issuer":        cfg.get("issuer") or None,
        "audience":      cfg.get("audience") or None,
        "jwt_available": JWT_AVAILABLE,
        "secret_present": bool(_STATE["secret"]),
        "secret_env":    cfg.get("secret_env"),
        "roles":         list(ROLES),
        "default_role":  cfg.get("default_role"),
        "mapped_groups": sorted((cfg.get("role_map") or {}).keys()),
        "jit_provisioning": bool(cfg.get("allow_jit")),
    }
    if store is not None:
        body.update(store.stats())
    return jsonify(body)


@bp.route("/api/auth/sso/exchange", methods=["POST"])
def sso_exchange():
    """Trade a SIEM-minted JWT for a dashboard session cookie."""
    cfg = _cfg()
    ready, reason = is_ready()
    if not ready:
        return jsonify({"error": "sso not available", "reason": reason}), 503

    payload = request.get_json(silent=True) or {}
    token = (payload.get("token") or request.form.get("token") or "").strip()
    if not token:
        return jsonify({"error": "missing token"}), 400

    try:
        claims = verify_sso_token(token, cfg, _STATE["secret"])
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

    store = _store()

    # Single-use: an assertion replayed from a proxy log or browser history
    # must not mint a second session.
    jti = str(claims.get("jti") or "")
    if jti:
        if not store.claim_assertion(jti, int(claims.get("exp") or (time.time() + 300))):
            return jsonify({"error": "assertion already used"}), 401

    sub = str(claims["sub"])
    known = store.get_user(sub)
    if known is None and not cfg.get("allow_jit"):
        return jsonify({"error": "unknown subject and JIT provisioning is disabled"}), 403
    if known is not None and not known.get("active", 1):
        return jsonify({"error": "account disabled"}), 403

    role = map_role(claims, cfg)
    user = store.upsert_user(
        sub=sub,
        username=str(claims.get("preferred_username") or claims.get("username") or sub),
        email=str(claims.get("email") or ""),
        display_name=str(claims.get("name") or claims.get("display_name") or ""),
        role=role,
    )

    ttl = int(cfg.get("session_ttl_secs") or 28800)
    sess = store.create_session(
        sub=sub, ttl=ttl,
        remote_addr=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        user_agent=request.headers.get("User-Agent", ""),
    )
    store.purge_expired()

    resp = jsonify({
        "ok": True,
        "user": {"sub": user["sub"], "username": user["username"],
                 "display_name": user["display_name"], "email": user["email"],
                 "role": user["role"]},
        "expires_in": ttl,
        "provisioned": known is None,
    })
    resp.set_cookie(
        cfg.get("cookie_name") or "ueba_session", sess,
        max_age=ttl,
        httponly=True,                                   # not readable from JS
        secure=bool(cfg.get("cookie_secure")),
        samesite=cfg.get("cookie_samesite") or "Lax",
        path="/",
    )
    log.info("SSO login sub=%s role=%s jit=%s", sub, user["role"], known is None)
    return resp


@bp.route("/api/auth/me")
def auth_me():
    user = current_user()
    if user is None:
        return jsonify({"authenticated": False, "enforce": bool(_cfg().get("enforce"))}), 200
    return jsonify({"authenticated": True, "user": user,
                    "enforce": bool(_cfg().get("enforce"))})


@bp.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    cfg = _cfg()
    name = cfg.get("cookie_name") or "ueba_session"
    tok = request.cookies.get(name)
    store = _store()
    if tok and store is not None:
        store.revoke_session(tok)
    resp = jsonify({"ok": True})
    resp.delete_cookie(name, path="/")
    return resp


# The landing page the SIEM redirects to. Kept dependency-free and inline so it
# works before the Vite bundle loads and regardless of build state.
_LANDING_HTML = """<!doctype html>
<meta charset="utf-8">
<title>CyberSentinel UEBA — Signing in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         background:#0b0f17; color:#e6edf6;
         font:15px/1.5 "IBM Plex Sans", system-ui, sans-serif; }
  .card { width:min(92vw,420px); padding:32px; border-radius:14px;
          background:#111826; border:1px solid #1f2a3c; text-align:center; }
  h1 { margin:0 0 6px; font-size:17px; letter-spacing:.02em; }
  p  { margin:0; color:#8b9ab0; font-size:13px; }
  .err { color:#ff6b6b; margin-top:14px; font-size:13px; word-break:break-word; }
  .spin { width:26px; height:26px; margin:0 auto 18px; border-radius:50%;
          border:2px solid #23324a; border-top-color:#4da3ff;
          animation:s .8s linear infinite; }
  @keyframes s { to { transform:rotate(360deg); } }
</style>
<div class="card">
  <div class="spin" id="sp"></div>
  <h1>Signing you in</h1>
  <p id="msg">Verifying your SIEM assertion…</p>
  <div class="err" id="err"></div>
</div>
<script>
(function () {
  // Accept the assertion from the URL fragment first: unlike the query string,
  // a fragment is never sent to the server and so never lands in access logs
  // or proxy logs. ?token= is still honoured for SIEMs that cannot do better.
  var frag = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  var qs   = new URLSearchParams(location.search);
  var token = frag.get("token") || qs.get("token") || "";
  var next  = frag.get("next")  || qs.get("next")  || "/";
  // Only ever redirect somewhere on this origin.
  if (!/^\\/(?!\\/)/.test(next)) next = "/";

  function fail(m) {
    document.getElementById("sp").style.display = "none";
    document.getElementById("msg").textContent = "Sign-in failed";
    document.getElementById("err").textContent = m;
  }
  if (!token) { fail("No SSO assertion was supplied."); return; }

  fetch("/api/auth/sso/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ token: token })
  }).then(function (r) {
    return r.json().then(function (b) { return { ok: r.ok, body: b }; });
  }).then(function (res) {
    if (!res.ok) { fail(res.body.error || "Verification failed."); return; }
    // Drop the assertion from the address bar before navigating on, so it
    // does not persist in browser history.
    history.replaceState(null, "", "/auth/sso");
    location.replace(next);
  }).catch(function (e) { fail(String(e)); });
})();
</script>
"""


@bp.route("/auth/sso")
def sso_landing():
    return Response(_LANDING_HTML, mimetype="text/html")


def init_auth(flask_app, raw_cfg: dict | None) -> dict:
    """Wire the auth module into a Flask app. Returns the effective config.

    Raises AuthConfigError for an unsafe config — that is deliberate: a
    misconfigured auth layer should stop the server at boot, not run open.
    """
    cfg = load_auth_config(raw_cfg)
    _STATE["cfg"] = cfg
    _STATE["secret"] = get_secret(cfg)

    if cfg.get("enabled"):
        try:
            _STATE["store"] = AuthStore(cfg["auth_db"])
        except Exception as e:
            log.error("auth store init failed (%s): SSO will report not-ready", e)
            _STATE["store"] = None

        if cfg.get("enforce") and not is_ready()[0]:
            # Refuse to run "enforcing but unable to authenticate anyone" —
            # that is a self-inflicted outage, not a security posture.
            raise AuthConfigError(
                f"auth.enforce is true but SSO is not ready: {is_ready()[1]}. "
                "Fix that first, or set auth.enforce: false."
            )

    flask_app.register_blueprint(bp)
    install_request_gate(flask_app)

    ready, reason = is_ready()
    log.info("auth: enabled=%s enforce=%s ready=%s (%s)",
             cfg.get("enabled"), cfg.get("enforce"), ready, reason)
    return cfg
