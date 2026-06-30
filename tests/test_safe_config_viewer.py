"""Regression + security coverage for the safe config.yaml viewer (#2929).

Salvaged from PR #3228 (author @AJV20) and extended with the three
maintainer-required fixes plus a redaction-completeness pass:

  fix #1  numeric/bool secrets under a sensitive key path are masked (the
          key-path check runs BEFORE the numeric/bool passthrough). This is
          covered by a NON-VACUOUS test that fails if the two branches are
          reordered.
  fix #2  the endpoint returns only the config basename (``filename``) and
          never the absolute server path.
  fix #3  a UI note documents that the value-level scrub of secrets pasted
          into non-secret keys only runs when ``api_redact_enabled`` is on.

Security contract: no credential value — of ANY type — under any sensitive
key path may appear in the /api/config/safe response.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import api.routes as routes

ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
PANELS_JS = (ROOT / "static" / "panels.js").read_text(encoding="utf-8")
STYLE_CSS = (ROOT / "static" / "style.css").read_text(encoding="utf-8")
I18N_JS = (ROOT / "static" / "i18n.js").read_text(encoding="utf-8")
ROUTES_PY = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


# ── FakeHandler (mirrors test_gateway_status_agent_health._FakeHandler) ───────

class _FakeHandler:
    """Minimal BaseHTTPRequestHandler stand-in for routes.handle_get."""

    def __init__(self):
        self.status = None
        self.sent_headers: list[tuple[str, str]] = []
        self.body = bytearray()
        self.wfile = self

    def send_response(self, code):
        self.status = code

    def send_header(self, key, value):
        self.sent_headers.append((key, value))

    def end_headers(self):
        pass

    def write(self, data):
        self.body.extend(data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8"))

    def get_json(self):
        return json.loads(self.body.decode("utf-8"))


def _call_safe_config(monkeypatch, config: dict, config_path: Path | None = None):
    """Invoke handle_get for /api/config/safe and return the FakeHandler.

    As of #5088 the viewer reads the RAW config FILE (not the env-expanded
    ``get_config()``), so write ``config`` to ``config_path`` and point the
    raw loader at it. ``get_config`` is still patched for any incidental caller.
    """
    monkeypatch.setattr(routes, "get_config", lambda: config)
    if config_path is None:
        import tempfile
        config_path = Path(tempfile.mkdtemp()) / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    import yaml as _yaml
    config_path.write_text(_yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(routes, "_get_config_path", lambda: config_path)
    import api.config as _cfg
    monkeypatch.setattr(_cfg, "_get_config_path", lambda: config_path)
    handler = _FakeHandler()
    parsed = urlparse("http://example.com/api/config/safe")
    routes.handle_get(handler, parsed)
    return handler


# ── Unit: the redactor ───────────────────────────────────────────────────────

def test_redact_config_masks_secret_key_paths_and_prefilters_plain_strings(monkeypatch):
    calls = []
    monkeypatch.setattr(
        routes,
        "_redact_text",
        lambda text, *, _enabled=None: calls.append(text) or text.replace("ghp_sensitive", "[REDACTED]"),
    )

    safe: dict[str, Any] = routes._redact_config_for_display({
        "providers": {"openai": {"api_key": "***", "model": "gpt-5.5"}},
        "gateway": {"api_key": 1234567890, "enabled": True},
        "platforms": {"telegram": {"token": False}},
        "webui": {"dashboard": {"public_url": "https://example.test"}},
        "notes": "contains ghp_sensitive token",
        "items": [{"password": "***"}],
    })

    assert safe["providers"]["openai"]["api_key"] == "[REDACTED]"
    assert safe["gateway"]["api_key"] == "[REDACTED]"
    assert safe["gateway"]["enabled"] is True
    assert safe["platforms"]["telegram"]["token"] == "[REDACTED]"
    assert safe["providers"]["openai"]["model"] == "gpt-5.5"
    assert safe["webui"]["dashboard"]["public_url"] == "https://example.test"
    assert safe["notes"] == "contains [REDACTED] token"
    assert safe["items"][0]["password"] == "[REDACTED]"
    # The masked-by-path values must never even be handed to _redact_text.
    assert "***" not in calls


def test_numeric_secret_under_sensitive_path_is_redacted_fix1_nonvacuous():
    """Maintainer fix #1 (NON-VACUOUS).

    A numeric value under a sensitive key path must be masked. With the buggy
    ordering (numeric/bool passthrough before the key-path check) this leaks the
    raw integer 12345 — so this assertion fails without the fix, proving it is
    not vacuous.
    """
    safe = routes._redact_config_for_display({"providers": {"x": {"token": 12345}}})
    assert safe["providers"]["x"]["token"] == "[REDACTED]"
    # The raw number must not survive anywhere in the serialized output.
    assert "12345" not in json.dumps(safe)


def test_bool_secret_under_sensitive_path_is_redacted():
    safe = routes._redact_config_for_display({"x": {"secret": True}})
    assert safe["x"]["secret"] == "[REDACTED]"


def test_empty_and_none_secret_values_are_left_as_is():
    """Empty/absent secrets are not turned into a misleading [REDACTED]."""
    safe = routes._redact_config_for_display({"a": {"api_key": ""}, "b": {"token": None}})
    assert safe["a"]["api_key"] == ""
    assert safe["b"]["token"] is None


def test_redaction_completeness_no_secret_of_any_type_leaks():
    """The security contract: drive a representative config carrying secrets of
    several types under many sensitive key paths and assert none leak."""
    sentinels = {
        "k_api_key": "sk-live-AAAAAAAAAAAA",
        "k_apikey": "AIzaXXXXXXXXXXXX",
        "k_token": "ghp_token_value_zzz",
        "k_token_num": 9988776655,            # numeric secret
        "k_secret": "shhh-secret-value",
        "k_password": "hunter2password",
        "k_passwd": "pwpwpwpw",
        "k_passphrase": "open sesame phrase",
        "k_credential": "cred-blob-value",
        "k_cookie": "session=abc123cookie",
        "k_private_key": "-----BEGIN PRIVATE KEY-----abc",
        "k_client_secret": "cs_live_clientsecret",
        "k_access_key": "AKIAEXAMPLEACCESSKEY",
        "k_refresh_token": "refresh_tok_value",
        "k_bearer": "Bearer aaa.bbb.ccc",
        "k_auth": "Basic dXNlcjpwYXNz",
        "k_webhook": "https://hooks.example/T000/B000/secrettoken",
        "k_session_key": "sesskeyvalue",
        "k_signature": "x-amz-sig-value",
        "k_bool_secret": True,                # bool secret
    }
    config = {
        "providers": {
            "openai": {"api_key": sentinels["k_api_key"], "model": "gpt-5.5"},
            "google": {"apikey": sentinels["k_apikey"]},
        },
        "gateway": {
            "token": sentinels["k_token"],
            "auth_token": sentinels["k_token_num"],
            "secret": sentinels["k_secret"],
            "enabled": True,           # non-secret bool: must survive
            "port": 8080,              # non-secret int: must survive
        },
        "auth": {
            "password": sentinels["k_password"],
            "passwd": sentinels["k_passwd"],
            "passphrase": sentinels["k_passphrase"],
            "bearer": sentinels["k_bearer"],
            "value": sentinels["k_auth"],         # under 'auth' ancestor
        },
        "oauth": {
            "client_secret": sentinels["k_client_secret"],
            "refresh_token": sentinels["k_refresh_token"],
        },
        "aws": {"access_key": sentinels["k_access_key"], "region": "us-east-1"},
        "store": {
            "credential": sentinels["k_credential"],
            "cookie": sentinels["k_cookie"],
            "private_key": sentinels["k_private_key"],
            "session_key": sentinels["k_session_key"],
            "signature": sentinels["k_signature"],
            "x_secret": sentinels["k_bool_secret"],
        },
        "integrations": [
            {"webhook": sentinels["k_webhook"]},
            {"name": "ok", "url": "https://example.test/ping"},
        ],
    }

    safe = routes._redact_config_for_display(config)
    blob = json.dumps(safe)

    leaked = [
        name for name, val in sentinels.items()
        if val is not True and str(val) in blob
    ]
    # Bool True can't be detected via substring (it serializes as `true`);
    # assert the masked location directly instead.
    assert safe["store"]["x_secret"] == "[REDACTED]"
    assert not leaked, f"secret(s) leaked into safe config: {leaked}"

    # Non-secret scalars must survive untouched.
    assert safe["gateway"]["enabled"] is True
    assert safe["gateway"]["port"] == 8080
    assert safe["aws"]["region"] == "us-east-1"
    assert safe["providers"]["openai"]["model"] == "gpt-5.5"
    assert safe["integrations"][1]["url"] == "https://example.test/ping"


def test_non_secret_session_knobs_are_not_over_redacted():
    """The completeness pass must not over-redact non-credential 'session'
    knobs (regression guard against a naive bare 'session' fragment)."""
    safe = routes._redact_config_for_display({
        "gateway": {
            "session_ttl_seconds": 3600,
            "max_live_sessions": 5,
            "group_sessions_per_user": True,
        }
    })
    assert safe["gateway"]["session_ttl_seconds"] == 3600
    assert safe["gateway"]["max_live_sessions"] == 5
    assert safe["gateway"]["group_sessions_per_user"] is True


# ── Endpoint behavior ─────────────────────────────────────────────────────────

def test_endpoint_returns_redacted_yaml_and_basename_only(monkeypatch, tmp_path):
    cfg_path = tmp_path / "deep" / "home" / "config.yaml"
    config = {"providers": {"openai": {"api_key": "sk-live-SECRETVALUE", "model": "gpt"}}}
    handler = _call_safe_config(monkeypatch, config, config_path=cfg_path)
    payload = handler.get_json()

    assert handler.status == 200
    assert payload["ok"] is True
    assert payload["read_only"] is True
    assert payload["filename"] == "config.yaml"
    assert payload["redacted_count"] >= 1
    assert "sk-live-SECRETVALUE" not in payload["text"]
    assert "[REDACTED]" in payload["text"]


def test_endpoint_response_contains_no_absolute_path_fix2(monkeypatch, tmp_path):
    """Maintainer fix #2: the absolute server path must never reach the client."""
    cfg_path = tmp_path / "secret-home-dir" / "config.yaml"
    handler = _call_safe_config(monkeypatch, {"a": 1}, config_path=cfg_path)
    payload = handler.get_json()

    # No 'path' field at all.
    assert "path" not in payload
    # The absolute path string must appear nowhere in the serialized response.
    raw = json.dumps(payload)
    assert str(cfg_path) not in raw
    assert str(cfg_path.parent) not in raw
    assert "secret-home-dir" not in raw


# ── Static wiring assertions (salvaged from #3228, adapted to master) ─────────

def test_safe_config_endpoint_is_get_only_read_only_and_uses_active_config_path():
    assert '"/api/config/safe"' in ROUTES_PY
    endpoint_idx = ROUTES_PY.index('if parsed.path == "/api/config/safe"')
    settings_idx = ROUTES_PY.index('"/api/settings"', endpoint_idx)
    block = ROUTES_PY[endpoint_idx:settings_idx]
    assert "_safe_config_yaml_text()" in block
    assert "_get_config_path()" in block
    assert '"path": str(cfg_path)' not in block
    assert '"read_only": True' in block
    assert '"filename": cfg_path.name' in block


def test_system_settings_mounts_read_only_safe_config_viewer():
    assert 'id="safeConfigText"' in INDEX_HTML
    assert 'onclick="loadSafeConfig(true)"' in INDEX_HTML
    assert 'onclick="copySafeConfig()"' in INDEX_HTML
    assert "read-only" in INDEX_HTML
    assert ".safe-config-viewer" in STYLE_CSS


def test_redaction_disabled_doc_note_present_fix3():
    """The panel documents the redaction contract. As of #5088 the safe-config
    scrub is ALWAYS on (no longer gated by api_redact_enabled), so the note must
    state that secrets in non-secret keys are always scrubbed — and must NOT
    claim dependence on api_redact_enabled."""
    assert 'data-i18n="safe_config_redact_note"' in INDEX_HTML
    assert "always scrubbed" in INDEX_HTML
    # the old caveat (scrub only when api_redact_enabled is on) must be gone
    assert "only runs when API redaction" not in INDEX_HTML


def test_safe_config_frontend_loads_and_copies_redacted_yaml():
    assert "async function loadSafeConfig" in PANELS_JS
    assert "api('/api/config/safe')" in PANELS_JS
    assert "loadSafeConfig();" in PANELS_JS
    assert "async function copySafeConfig" in PANELS_JS
    assert "navigator.clipboard.writeText" in PANELS_JS


def test_safe_config_i18n_and_changelog_entries_exist():
    for key in [
        "safe_config_title",
        "safe_config_desc",
        "safe_config_redact_note",
        "safe_config_refresh",
        "safe_config_copy",
        "safe_config_meta",
        "safe_config_copied",
    ]:
        assert key in I18N_JS
    assert "safe, read-only config.yaml viewer" in CHANGELOG
    assert "#2929" in CHANGELOG


# --- #5088 regressions: inline-credential + env-expansion leaks ---------------

def test_url_userinfo_under_nonsensitive_key_is_scrubbed():
    """A password embedded in a URL/DSN under a NON-sensitive key must not leak.

    The key ("proxy" / "database.dsn") is not in the sensitive-fragment list, so
    the path-based [REDACTED] does not fire; the unconditional scalar scrubber
    must mask the userinfo. Regression for #5088 (reproduced leak).
    """
    safe = routes._redact_config_for_display({
        "proxy": "http://admin:P4ssw0rd@10.0.0.1:8080",
        "database": {"dsn": "postgres://user:HUNTER2pw@host:5432/db"},
    })
    assert "P4ssw0rd" not in json.dumps(safe)
    assert "HUNTER2pw" not in json.dumps(safe)
    # host/scheme preserved (only the credential span is masked)
    assert "10.0.0.1:8080" in safe["proxy"]
    assert "***@" in safe["proxy"]


def test_sensitive_query_param_under_nonsensitive_key_is_scrubbed():
    """A ?token=/&key= secret in a URL under a non-sensitive key must not leak."""
    safe = routes._redact_config_for_display({
        "callback_url": "https://h/cb?token=QUERYSECRET987&page=2",
    })
    blob = json.dumps(safe)
    assert "QUERYSECRET987" not in blob
    assert "token=***" in safe["callback_url"]
    # non-sensitive params preserved
    assert "page=2" in safe["callback_url"]


def test_scrub_is_idempotent_and_noop_on_plain_strings():
    once = routes._scrub_config_scalar_secrets("http://u:pw@h/x?token=ABC")
    twice = routes._scrub_config_scalar_secrets(once)
    assert once == twice
    # no URL shape -> unchanged
    assert routes._scrub_config_scalar_secrets("just a plain note") == "just a plain note"


def test_safe_config_reads_raw_yaml_not_env_expanded(monkeypatch, tmp_path):
    """${VAR} placeholders must stay literal (or be redacted) — never expanded.

    Highest-severity #5088 vector: _safe_config_yaml_text() must build from the
    RAW config file, never get_config() (whose cache expands ${VAR} to the real
    secret). Here the secret sits under a sensitive key (api_key) so it is also
    [REDACTED], but the critical assertion is the EXPANDED value never appears.
    """
    import api.config as cfg
    cfgp = tmp_path / "config.yaml"
    cfgp.write_text(
        "providers:\n  openai:\n    api_key: ${SAFE_VIEWER_TEST_SECRET}\n"
        "misc:\n  endpoint: ${SAFE_VIEWER_TEST_SECRET}\n"
    )
    monkeypatch.setenv("SAFE_VIEWER_TEST_SECRET", "sk-ENV-EXPANDED-LEAK-XYZ")
    monkeypatch.setattr(cfg, "_get_config_path", lambda: cfgp)
    text, _n = routes._safe_config_yaml_text()
    assert "sk-ENV-EXPANDED-LEAK-XYZ" not in text  # the expanded secret must NOT leak


def test_fragment_and_extended_param_credentials_are_scrubbed():
    """#5088 round 2 (Codex re-gate): fragment params (#access_token=) and the
    full credential param vocabulary (x-api-key, access_key, secret_key, ...)
    must be masked under non-sensitive keys; benign params preserved."""
    safe = routes._redact_config_for_display({
        "redirect_url": "https://app/cb#access_token=FRAGTOK123",
        "u2": "https://h/cb?x-api-key=XAPIKEY123",
        "u3": "https://h/cb?access_key=ACCESSKEY123&secret_key=SK999",
        "mixed": "https://h?Token=MIXEDCASE9",
        "benign": "https://host/path?page=2&view=full#section",
        "benign2": "https://host/x?api_version=3&key_count=5",
    })
    blob = json.dumps(safe)
    for leak in ("FRAGTOK123", "XAPIKEY123", "ACCESSKEY123", "SK999", "MIXEDCASE9"):
        assert leak not in blob, f"{leak} leaked"
    # benign params with credential-substring names must NOT be over-masked
    assert "page=2" in safe["benign"] and "view=full" in safe["benign"] and "#section" in safe["benign"]
    assert "api_version=3" in safe["benign2"] and "key_count=5" in safe["benign2"]


def test_capability_url_path_segment_tokens_are_scrubbed(monkeypatch):
    """#5088 round 3 (Codex re-gate): provider webhook URLs embed the secret in
    the PATH (Slack /services/.., Discord /api/webhooks/..), not userinfo/query.
    Mask those known shapes UNCONDITIONALLY (even with _redact_text disabled);
    benign paths must be preserved (no blanket path masking)."""
    # neutralize the setting-gated redactor so we prove the UNCONDITIONAL scrub
    monkeypatch.setattr(routes, "_redact_text", lambda t, *, _enabled=None: t)
    safe = routes._redact_config_for_display({
        "slack": "https://hooks.slack.com/services/T000/B000/PATHSECRETXYZ",
        "discord": "https://discord.com/api/webhooks/123456789/DISCORDTOKENABC",
        "discordapp": "https://discordapp.com/api/webhooks/999/DAPPTOKEN",
        "benign_path": "https://example.com/docs/getting-started/intro",
        "benign_api": "https://api.example.com/v1/users/42/profile",
    })
    blob = json.dumps(safe)
    for leak in ("PATHSECRETXYZ", "DISCORDTOKENABC", "DAPPTOKEN"):
        assert leak not in blob, f"{leak} leaked"
    # provider/structure preserved, secret segment masked
    assert safe["slack"] == "https://hooks.slack.com/services/T000/B000/***"
    # benign paths untouched
    assert safe["benign_path"] == "https://example.com/docs/getting-started/intro"
    assert safe["benign_api"] == "https://api.example.com/v1/users/42/profile"


def test_url_userinfo_all_forms_scrubbed(monkeypatch):
    """#5088 round 4 (Codex re-gate): the userinfo scrubber must cover empty-
    username DSNs (redis://:PW@) and token-as-username URLs (https://TOKEN@),
    not only user:pass@. Proven with _redact_text disabled (unconditional)."""
    monkeypatch.setattr(routes, "_redact_text", lambda t, *, _enabled=None: t)
    safe = routes._redact_config_for_display({
        "redis_url": "redis://:REDIS_PW_LEAK@localhost:6379/0",
        "git_url": "https://ghp_TOKENLEAK5088@github.com/org/repo.git",
        "mongo": "mongodb+srv://admin:M0NGOLEAK@cluster.example.net/db",
        "normal": "https://user:PASSLEAK@host/x",
        "benign": "https://api.example.com/v1/users/42",
        "mailto": "mailto:someone@example.com",
    })
    blob = json.dumps(safe)
    for leak in ("REDIS_PW_LEAK", "ghp_TOKENLEAK5088", "M0NGOLEAK", "PASSLEAK"):
        assert leak not in blob, f"{leak} leaked"
    assert safe["redis_url"] == "redis://:***@localhost:6379/0"
    assert safe["normal"] == "https://user:***@host/x"
    # benign (no userinfo) untouched
    assert safe["benign"] == "https://api.example.com/v1/users/42"
    assert safe["mailto"] == "mailto:someone@example.com"


def test_freetext_token_scrubbed_even_when_api_redaction_disabled(monkeypatch):
    """#5088 round 4 (root): a pasted token under a NON-sensitive key must be
    redacted by the safe-config viewer even when api_redact_enabled is OFF —
    the viewer forces _redact_text(_enabled=True), never deferring to the
    operator's response-redaction setting."""
    # Simulate api_redact_enabled = False at the settings layer.
    monkeypatch.setattr(
        "api.config.load_settings",
        lambda: {"api_redact_enabled": False},
    )
    safe = routes._redact_config_for_display({
        "notes": "operator pasted sk-live-PASTEDLEAK5088 here",
    })
    assert "PASTEDLEAK5088" not in json.dumps(safe)


def test_yaml_alias_shared_secret_is_redacted_everywhere():
    """#5088 round 5 (Codex re-gate): a YAML alias (&pw/*pw) shares one scalar
    between a sensitive key and a benign key. The value-taint pass must redact
    the secret under the benign key too — while short/benign values that merely
    collide are NOT over-masked."""
    safe = routes._redact_config_for_display({
        "auth": {"password": "correct-horse-battery-staple"},
        "notes": {"sample": "correct-horse-battery-staple"},  # alias -> same value
        "ui": {"theme": "dark", "lang": "en"},                 # short benign, must survive
        "port": 8787,
    })
    blob = json.dumps(safe)
    assert "correct-horse-battery-staple" not in blob
    assert safe["notes"]["sample"] == "[REDACTED]"
    # no over-masking of short benign values
    assert safe["ui"]["theme"] == "dark"
    assert safe["ui"]["lang"] == "en"
    assert safe["port"] == 8787


def test_bare_key_segment_and_percent_encoded_params_scrubbed(monkeypatch):
    """#5088 round 6 (Codex re-gate): a bare `key:` segment must redact (without
    masking benign compound names like record_key/theme_key), and percent-encoded
    nested query credentials (%3Ftoken%3D, %26api_key%3D) must be masked."""
    monkeypatch.setattr(routes, "_redact_text", lambda t, *, _enabled=None: t)
    safe = routes._redact_config_for_display({
        "service": {"key": "a1b2c3d4e5f6g7h8i9j0"},
        "ui": {"record_key": "Ctrl+R", "theme_key": "dark"},
        "encoded": {"url": "https://outer/cb?redirect=https%3A%2F%2Finner%2Fcb%3Ftoken%3DENCODEDSECRET"},
        "encoded2": {"url": "https://o?x=1%26api_key%3DENCKEY2"},
    })
    blob = json.dumps(safe)
    assert "a1b2c3d4e5f6g7h8i9j0" not in blob   # bare key: redacted
    assert "ENCODEDSECRET" not in blob          # %3Ftoken%3D masked
    assert "ENCKEY2" not in blob                # %26api_key%3D masked
    # benign compound 'key' names NOT over-masked
    assert safe["ui"]["record_key"] == "Ctrl+R"
    assert safe["ui"]["theme_key"] == "dark"
