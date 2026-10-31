import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from detector import analyze_event


class TestThreatLensDetector(unittest.TestCase):

    def test_encoded_powershell_is_flagged(self):
        event = {
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "process_id": "0x1234",
            "command_line": "powershell.exe -EncodedCommand VGVzdA==",
            "parent_process": "explorer.exe",
            "timestamp": "2026-10-31T07:00:00Z"
        }

        result = analyze_event(event)

        self.assertEqual(result["status"], "FLAGGED")
        self.assertIn("TL001", result["matched_rules"])

    def test_short_encoded_switch_is_flagged(self):
        event = {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc VGVzdA=="
        }

        result = analyze_event(event)

        self.assertEqual(result["status"], "FLAGGED")

    def test_normal_notepad_is_not_flagged(self):
        event = {
            "process_name": r"C:\Windows\System32\notepad.exe",
            "command_line": "notepad.exe"
        }

        result = analyze_event(event)

        self.assertEqual(result["status"], "NORMAL")
        self.assertEqual(result["matched_rules"], [])

    def test_normal_powershell_is_not_flagged(self):
        event = {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe Get-Process"
        }

        result = analyze_event(event)

        self.assertEqual(result["status"], "NORMAL")

    def test_pwsh_encoded_command_is_flagged(self):
        event = {
            "process_name": "pwsh.exe",
            "command_line": "pwsh.exe -EncodedCommand VGVzdA=="
        }

        result = analyze_event(event)

        self.assertEqual(result["status"], "FLAGGED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
