"""Optional local-container integration checks.

These tests never contact an external target. CI supplies a freshly built
application image through ``NETWORKFORGE_SANDBOX_IMAGE``.
"""

import os
import shutil

import pytest

from networkforgeai.sandbox.runner import SandboxRunner


@pytest.mark.integration
def test_sandbox_round_trip_isolated_fixture():
    if not os.getenv("NETWORKFORGE_SANDBOX_IMAGE") or shutil.which("docker") is None:
        pytest.skip("requires Docker and NETWORKFORGE_SANDBOX_IMAGE")
    result = SandboxRunner().run(["sh", "-c", "printf sandbox-ok"], timeout=20)
    assert result.returncode == 0
    assert result.stdout == "sandbox-ok"
