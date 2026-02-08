"""Signals emitted by quart-security."""

from blinker import Namespace

_signals = Namespace()

user_authenticated = _signals.signal("user-authenticated")
user_logged_out = _signals.signal("user-logged-out")
password_changed = _signals.signal("password-changed")
tf_profile_changed = _signals.signal("tf-profile-changed")
user_registered = _signals.signal("user-registered")
