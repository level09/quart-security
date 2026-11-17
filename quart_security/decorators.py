"""Authentication and authorization decorators."""

import datetime
import time
from functools import wraps
from urllib.parse import quote

from quart import abort, current_app, redirect, request, session

from .proxies import current_user
from .utils import url_for_security


def _is_navigation():
    # Only a page visit may pick where login goes next: an EventSource or XHR
    # that outlived its session would otherwise hand its URL to the next login.
    mode = request.headers.get("Sec-Fetch-Mode")
    if mode and mode != "navigate":
        return False
    return "Accept" not in request.headers or request.accept_mimetypes.accept_html


def session_is_fresh() -> bool:
    """Whether this session signed in within `SECURITY_FRESHNESS`."""
    freshness = current_app.config.get(
        "SECURITY_FRESHNESS", datetime.timedelta(minutes=60)
    )
    age = time.time() - session.get("_auth_at", 0)
    return bool(session.get("_fresh")) and age <= freshness.total_seconds()


def _send_to(endpoint):
    """Send a page visit to login or verify, and anything else a 401."""
    if request.is_json or not _is_navigation():
        abort(401)
    # Only a GET can be replayed afterwards: a form POST would otherwise land
    # on its URL as a GET.
    if request.method != "GET":
        return redirect(url_for_security(endpoint))
    # A path, not request.url: login only follows same-site paths.
    # request.path is decoded; quote it so "%23" stays in the path.
    target = quote(request.script_root + request.path)
    if request.query_string:
        target += "?" + request.query_string.decode()
    return redirect(url_for_security(endpoint, next=target))


def auth_required(*methods, fresh=False):
    """Require an authenticated user for a route."""

    allowed_methods = methods or ("session",)
    if any(method != "session" for method in allowed_methods):
        raise ValueError("Only 'session' auth is supported")

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return _send_to("login")
            if fresh and not session_is_fresh():
                return _send_to("verify")
            return await current_app.ensure_async(func)(*args, **kwargs)

        return wrapper

    return decorator


def roles_required(*roles):
    """Require that the current user has all provided roles."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not all(current_user.has_role(role) for role in roles):
                abort(403)
            return await current_app.ensure_async(func)(*args, **kwargs)

        return wrapper

    return decorator
