"""Unit tests for CyberWatch config helpers (scripts/config.py)."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from config import Config, _float, _int, _str  # noqa: E402


class TestIntHelper(unittest.TestCase):
    def test_returns_default_when_unset(self):
        os.environ.pop("CW_TEST_INT", None)
        self.assertEqual(_int("CW_TEST_INT", 7), 7)

    def test_parses_valid_int(self):
        os.environ["CW_TEST_INT"] = "42"
        try:
            self.assertEqual(_int("CW_TEST_INT", 7), 42)
        finally:
            del os.environ["CW_TEST_INT"]

    def test_falls_back_on_invalid_value(self):
        os.environ["CW_TEST_INT"] = "not-an-int"
        try:
            self.assertEqual(_int("CW_TEST_INT", 7), 7)
        finally:
            del os.environ["CW_TEST_INT"]

    def test_falls_back_on_blank_value(self):
        os.environ["CW_TEST_INT"] = "   "
        try:
            self.assertEqual(_int("CW_TEST_INT", 7), 7)
        finally:
            del os.environ["CW_TEST_INT"]


class TestFloatHelper(unittest.TestCase):
    def test_returns_default_when_unset(self):
        os.environ.pop("CW_TEST_FLOAT", None)
        self.assertEqual(_float("CW_TEST_FLOAT", 0.5), 0.5)

    def test_parses_valid_float(self):
        os.environ["CW_TEST_FLOAT"] = "1.25"
        try:
            self.assertEqual(_float("CW_TEST_FLOAT", 0.5), 1.25)
        finally:
            del os.environ["CW_TEST_FLOAT"]

    def test_falls_back_on_invalid_value(self):
        os.environ["CW_TEST_FLOAT"] = "abc"
        try:
            self.assertEqual(_float("CW_TEST_FLOAT", 0.5), 0.5)
        finally:
            del os.environ["CW_TEST_FLOAT"]


class TestStrHelper(unittest.TestCase):
    def test_returns_default_when_unset(self):
        os.environ.pop("CW_TEST_STR", None)
        self.assertEqual(_str("CW_TEST_STR", "fallback"), "fallback")

    def test_returns_env_value_when_set(self):
        os.environ["CW_TEST_STR"] = "custom"
        try:
            self.assertEqual(_str("CW_TEST_STR", "fallback"), "custom")
        finally:
            del os.environ["CW_TEST_STR"]


class TestAlertSeveritySet(unittest.TestCase):
    """Exercises Config.alert_severity_set against fake config-like objects,
    so results don't depend on whatever ALERT_SEVERITIES is set in the
    environment running the tests."""

    def test_parses_single_value(self):
        class FakeConfig:
            alert_severities = "critical"

        self.assertEqual(Config.alert_severity_set.fget(FakeConfig), {"critical"})

    def test_parses_comma_separated_and_strips_whitespace(self):
        class FakeConfig:
            alert_severities = "critical, high ,medium"

        self.assertEqual(
            Config.alert_severity_set.fget(FakeConfig),
            {"critical", "high", "medium"},
        )

    def test_ignores_empty_entries(self):
        class FakeConfig:
            alert_severities = "critical,,high"

        self.assertEqual(
            Config.alert_severity_set.fget(FakeConfig), {"critical", "high"}
        )


if __name__ == "__main__":
    unittest.main()
