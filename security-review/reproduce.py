"""Run the regression checks for the original security review findings."""

import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    raise SystemExit(
        subprocess.call(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/test_security_regressions.py",
                "tests/test_security_state.py",
                "tests/test_sqlalchemy_security.py",
                "tests/test_sqlalchemy_auth.py",
                "tests/test_webauthn_crypto.py",
            ],
            cwd=root,
        )
    )
