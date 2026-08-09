from __future__ import annotations

import os
import subprocess
import sys
import threading
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from desktop_launcher import (  # noqa: E402
    acquire_single_instance,
    release_single_instance,
    wait_until_ready,
)


class DesktopLauncherTests(unittest.TestCase):
    def tearDown(self) -> None:
        release_single_instance()

    def test_wait_reports_server_thread_exception_immediately(self) -> None:
        stopped_thread = threading.Thread(target=lambda: None)
        stopped_thread.start()
        stopped_thread.join()

        with self.assertRaisesRegex(RuntimeError, "数据库初始化失败"):
            wait_until_ready(
                "http://127.0.0.1:9",
                timeout=5,
                server_thread=stopped_thread,
                server_errors=["RuntimeError: 数据库初始化失败"],
            )

    @unittest.skipUnless(os.name == "nt", "Windows mutex behavior")
    def test_second_desktop_process_is_rejected_by_mutex(self) -> None:
        self.assertTrue(acquire_single_instance())
        code = (
            "from desktop_launcher import acquire_single_instance; "
            "print(int(acquire_single_instance()))"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", code],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.stdout.strip(), "0")


if __name__ == "__main__":
    unittest.main()
