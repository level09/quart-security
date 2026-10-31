"""Signals emitted by quart-security."""

from blinker import Namespace

_signals = Namespace()

user_authenticated = _signals.signal("user-authenticated")
user_logged_out = _signals.signal("user-logged-out")
password_changed = _signals.signal("password-changed")
tf_profile_changed = _signals.signal("tf-profile-changed")
user_registered = _signals.signal("user-registered")
# Registration with an email that already has an account. The form answers as if
# it succeeded, so tell the owner out of band; receivers run inside the request,
# so send mail in the background or the delay reveals the account.
user_register_conflict = _signals.signal("user-register-conflict")
