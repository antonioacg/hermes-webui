import io
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse


class FakeHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class RouteFakeHandler:
    def __init__(self):
        self.headers = FakeHeaders({"Host": "localhost:8787"})
        self.request = SimpleNamespace()
        self.wfile = io.BytesIO()
        self.status = None
        self.sent_headers = []

    def send_response(self, status):
        self.status = status

    def send_header(self, key, value):
        self.sent_headers.append((key, value))

    def end_headers(self):
        pass

    def json_body(self):
        return json.loads(self.wfile.getvalue().decode("utf-8"))

    def header_values(self, name):
        needle = name.lower()
        return [value for key, value in self.sent_headers if key.lower() == needle]


def test_oidc_start_redirects_with_pkce_state_and_nonce(monkeypatch):
    import api.routes as routes

    captured = {}

    def fake_build_authorization_redirect(request_base_url, next_path):
        captured["request_base_url"] = request_base_url
        captured["next_path"] = next_path
        return (
            "https://idp.example/authorize"
            "?response_type=code"
            "&client_id=webui-client"
            "&redirect_uri=http%3A%2F%2Flocalhost%3A8787%2Fapi%2Fauth%2Foidc%2Fcallback"
            "&scope=openid+profile+email"
            "&state=state-token"
            "&nonce=nonce-token"
            "&code_challenge=challenge-token"
            "&code_challenge_method=S256"
        )

    monkeypatch.setattr(
        "api.auth_oidc.build_authorization_redirect",
        fake_build_authorization_redirect,
    )

    handler = RouteFakeHandler()
    routes.handle_get(
        handler,
        SimpleNamespace(path="/api/auth/oidc/start", query="next=%2Fprojects%3Fview%3Dgrid"),
    )

    assert handler.status == 302
    assert captured == {
        "request_base_url": "http://localhost:8787",
        "next_path": "/projects?view=grid",
    }
    [location] = handler.header_values("Location")
    params = parse_qs(urlparse(location).query)
    assert params["response_type"] == ["code"]
    assert params["state"] == ["state-token"]
    assert params["nonce"] == ["nonce-token"]
    assert params["code_challenge"] == ["challenge-token"]
    assert params["code_challenge_method"] == ["S256"]


def test_oidc_callback_exchanges_code_and_sets_existing_session_cookie(monkeypatch):
    import api.auth as auth
    import api.routes as routes

    captured = {}

    def fake_complete_authorization_code_flow(request_base_url, state, code):
        captured["request_base_url"] = request_base_url
        captured["state"] = state
        captured["code"] = code
        return {"next_path": "/chat/123"}

    monkeypatch.setattr(
        "api.auth_oidc.complete_authorization_code_flow",
        fake_complete_authorization_code_flow,
    )
    monkeypatch.setattr(auth, "create_session", lambda: "session-token.signature")

    handler = RouteFakeHandler()
    routes.handle_get(
        handler,
        SimpleNamespace(
            path="/api/auth/oidc/callback",
            query="state=state-token&code=code-token",
        ),
    )

    assert handler.status == 302
    assert captured == {
        "request_base_url": "http://localhost:8787",
        "state": "state-token",
        "code": "code-token",
    }
    assert handler.header_values("Location") == ["/chat/123"]
    cookie_headers = handler.header_values("Set-Cookie")
    assert len(cookie_headers) == 1
    assert auth.COOKIE_NAME in cookie_headers[0]
    assert "session-token.signature" in cookie_headers[0]


def test_oidc_callback_rejects_invalid_state_without_setting_session_cookie(monkeypatch):
    import api.routes as routes
    from api.auth_oidc import OIDCAuthError

    monkeypatch.setattr(
        "api.auth_oidc.complete_authorization_code_flow",
        lambda *_args: (_ for _ in ()).throw(OIDCAuthError("Invalid OIDC state", status_code=401)),
    )

    handler = RouteFakeHandler()
    routes.handle_get(
        handler,
        SimpleNamespace(
            path="/api/auth/oidc/callback",
            query="state=missing-state&code=code-token",
        ),
    )

    assert handler.status == 401
    assert handler.json_body()["error"] == "Invalid OIDC state"
    assert handler.header_values("Set-Cookie") == []


def test_oidc_callback_rejects_allowlist_failure_without_setting_session_cookie(monkeypatch):
    import api.routes as routes
    from api.auth_oidc import OIDCAuthError

    monkeypatch.setattr(
        "api.auth_oidc.complete_authorization_code_flow",
        lambda *_args: (_ for _ in ()).throw(OIDCAuthError("OIDC identity is not allowed", status_code=403)),
    )

    handler = RouteFakeHandler()
    routes.handle_get(
        handler,
        SimpleNamespace(
            path="/api/auth/oidc/callback",
            query="state=state-token&code=code-token",
        ),
    )

    assert handler.status == 403
    assert handler.json_body()["error"] == "OIDC identity is not allowed"
    assert handler.header_values("Set-Cookie") == []


def test_auth_status_reports_oidc_capability_without_regressing_passkey_fields(monkeypatch):
    import api.auth as auth
    import api.passkeys as passkeys
    import api.routes as routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "is_oidc_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "_passkey_feature_flag_enabled", lambda: False)
    monkeypatch.setattr(auth, "get_password_hash", lambda: None)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: None)
    monkeypatch.setattr(
        auth,
        "verify_session",
        lambda _cookie: (_ for _ in ()).throw(AssertionError("verify_session should not run without a cookie")),
    )
    monkeypatch.setattr(passkeys, "registered_credentials", lambda: [])

    handler = RouteFakeHandler()
    routes.handle_get(handler, urlparse("http://example.com/api/auth/status"))

    assert handler.status == 200
    assert handler.json_body() == {
        "auth_enabled": True,
        "logged_in": False,
        "oidc_enabled": True,
        "password_auth_enabled": False,
        "passwordless_enabled": False,
        "passkeys_enabled": False,
        "passkeys_count": 0,
        "passkey_feature_flag": False,
        "auth_disabled_acknowledged": False,
    }
