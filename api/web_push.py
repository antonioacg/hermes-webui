"""Minimal Web Push support for fully closed WebUI PWAs."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from urllib.parse import quote


logger = logging.getLogger(__name__)
_PUSH_STORE_NAME = "webui_push_subscriptions.json"
_STORE_LOCK = threading.Lock()


def _subscription_store_path() -> Path:
    from api.profiles import _DEFAULT_HERMES_HOME

    base = Path(_DEFAULT_HERMES_HOME).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return base / _PUSH_STORE_NAME


def _load_store() -> dict:
    path = _subscription_store_path()
    if not path.exists():
        return {"subscriptions": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.debug("Failed to read Web Push store %s", path, exc_info=True)
        return {"subscriptions": []}
    subs = data.get("subscriptions")
    if not isinstance(subs, list):
        return {"subscriptions": []}
    return {"subscriptions": [sub for sub in subs if isinstance(sub, dict)]}


def _save_store(store: dict) -> None:
    path = _subscription_store_path()
    payload = json.dumps(store, ensure_ascii=False, indent=2, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".web_push.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _normalize_subscription(subscription: dict) -> dict:
    endpoint = str((subscription or {}).get("endpoint") or "").strip()
    if not endpoint:
        raise ValueError("subscription endpoint is required")
    keys = (subscription or {}).get("keys")
    if not isinstance(keys, dict):
        raise ValueError("subscription keys are required")
    p256dh = str(keys.get("p256dh") or "").strip()
    auth = str(keys.get("auth") or "").strip()
    if not p256dh or not auth:
        raise ValueError("subscription keys.p256dh and keys.auth are required")
    normalized = {
        "endpoint": endpoint,
        "keys": {"p256dh": p256dh, "auth": auth},
    }
    expiration = (subscription or {}).get("expirationTime")
    if expiration not in (None, ""):
        normalized["expirationTime"] = expiration
    return normalized


def list_subscriptions() -> list[dict]:
    return list(_load_store()["subscriptions"])


def _mutate_store(mutator) -> tuple[object, bool]:
    with _STORE_LOCK:
        store = _load_store()
        result, changed = mutator(store)
        if changed:
            _save_store(store)
        return result, changed


def upsert_subscription(subscription: dict) -> dict:
    normalized = _normalize_subscription(subscription)

    def _apply(store: dict) -> tuple[dict, bool]:
        subs = [sub for sub in store["subscriptions"] if sub.get("endpoint") != normalized["endpoint"]]
        subs.append(normalized)
        changed = subs != store["subscriptions"]
        store["subscriptions"] = subs
        return normalized, changed

    result, _ = _mutate_store(_apply)
    return result


def remove_subscription(endpoint: str) -> bool:
    endpoint = str(endpoint or "").strip()
    if not endpoint:
        return False

    def _apply(store: dict) -> tuple[bool, bool]:
        before = len(store["subscriptions"])
        store["subscriptions"] = [sub for sub in store["subscriptions"] if sub.get("endpoint") != endpoint]
        changed = len(store["subscriptions"]) != before
        return changed, changed

    result, _ = _mutate_store(_apply)
    return result


def _get_pywebpush_impl():
    try:
        from pywebpush import WebPushException, webpush
    except ImportError:
        return None, None
    return webpush, WebPushException


def web_push_status() -> dict:
    from api.config import web_push_configured

    webpush_fn, _ = _get_pywebpush_impl()
    configured = web_push_configured()
    dependency_available = webpush_fn is not None
    return {
        "configured": configured,
        "dependency_available": dependency_available,
        "enabled": bool(configured and dependency_available),
    }


def _notification_payload(title: str, body: str, *, session_id: str | None = None) -> dict:
    url = f"/session/{quote(str(session_id or '').strip(), safe='')}" if session_id else "./"
    return {
        "title": str(title or "Hermes"),
        "options": {
            "body": str(body or ""),
            "tag": f"hermes-{session_id}" if session_id else "hermes-webui",
            "renotify": False,
            "icon": "static/favicon-192.png",
            "badge": "static/favicon-32.png",
            "data": {"url": url},
        },
    }


def send_web_push(payload: dict) -> int:
    from api.config import (
        web_push_private_key,
        web_push_subject,
    )

    status = web_push_status()
    if not status["enabled"]:
        return 0
    subscriptions = list_subscriptions()
    if not subscriptions:
        return 0
    webpush_fn, _ = _get_pywebpush_impl()
    if not webpush_fn:
        return 0
    sent = 0
    stale_endpoints: list[str] = []
    claims = {"sub": web_push_subject()}
    data = json.dumps(payload, ensure_ascii=False)
    for subscription in subscriptions:
        try:
            webpush_fn(
                subscription_info=subscription,
                data=data,
                vapid_private_key=web_push_private_key(),
                vapid_claims=claims,
            )
            sent += 1
        except Exception as exc:
            response = getattr(exc, "response", None)
            status_code = getattr(response, "status_code", None) or getattr(response, "status", None)
            if status_code in (404, 410):
                stale_endpoints.append(str(subscription.get("endpoint") or ""))
            logger.debug("Web Push send failed for %s", subscription.get("endpoint"), exc_info=True)
    for endpoint in stale_endpoints:
        remove_subscription(endpoint)
    return sent


def notify_bg_task_complete(session_id: str, payload: dict) -> int:
    title = str((payload or {}).get("title") or "Background task complete")
    body = str((payload or {}).get("message") or "Task finished")
    return send_web_push(_notification_payload(title, body, session_id=session_id))


def notify_response_complete(session_id: str, answer: str) -> int:
    text = str(answer or "").strip()
    body = text[:120] if text else "Task finished"
    return send_web_push(_notification_payload("Response complete", body, session_id=session_id))


def notify_approval_required(session_id: str, approval: dict) -> int:
    body = str((approval or {}).get("description") or "Tool approval needed")
    return send_web_push(_notification_payload("Approval required", body, session_id=session_id))


def notify_clarify_required(session_id: str, clarify: dict) -> int:
    body = str((clarify or {}).get("question") or "Tool clarification needed")
    return send_web_push(_notification_payload("Clarification needed", body, session_id=session_id))
