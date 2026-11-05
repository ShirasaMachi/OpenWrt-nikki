"""Run with python3 -m unittest discover -s tests -v.

UCI is isolated in a temporary directory. Randomness uses the real hexdump
unless a test injects a failure. NIKKI_TEST_SHELL and NIKKI_TEST_HEXDUMP can
select BusyBox ash and hexdump for OpenWrt-compatible command coverage.
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "nikki/files/uci-defaults/init.sh"
API = "nikki.mixin.api_secret"
PASSWORD = "nikki.@authentication[0].password"
INIT = "nikki.config.init"

MOCK_COMMAND = r'''
import json, os, subprocess, sys
from pathlib import Path

path = Path(os.environ["NIKKI_TEST_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
if Path(sys.argv[0]).name == "hexdump":
    index = state["entropy_calls"]
    state["entropy_calls"] += 1
    path.write_text(json.dumps(state))
    scenarios = json.loads(os.environ.get("NIKKI_TEST_RNG", "[]"))
    mode = scenarios[index] if index < len(scenarios) else "real"
    if mode == "fail":
        sys.exit(1)
    if mode == "short":
        print("ab" * 31, end="")
    elif mode == "malformed":
        print("g" * 64, end="")
    elif mode == "output_then_fail":
        print("ab" * 32, end="")
        sys.exit(1)
    else:
        command = json.loads(os.environ["NIKKI_TEST_RNG_COMMAND"])
        sys.exit(subprocess.run(command + args).returncode)
    sys.exit(0)

if args[0] == "-q":
    args = args[1:]
action = args[0]
if action == "get":
    if args[1] not in state["config"]:
        sys.exit(1)
    print(state["config"][args[1]])
    sys.exit(0)
if action == "set":
    key, value = args[1].split("=", 1)
    state["config"][key] = value
elif action == "del":
    del state["config"][args[1]]
elif action != "commit":
    sys.exit(1)
state["mutations"].append(action)
path.write_text(json.dumps(state))
'''


class CredentialInitializationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="nikki-credentials-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_path = self.root / "state.json"
        include = self.root / "etc/nikki/scripts/include.sh"
        include.parent.mkdir(parents=True)
        include.write_text("# No device state in host-side tests.\n")
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        for name in ("uci", "hexdump"):
            command = binary_dir / name
            command.write_text(f"#!{sys.executable}\n" + MOCK_COMMAND)
            command.chmod(0o700)
        rng = os.environ.get("NIKKI_TEST_HEXDUMP")
        if rng:
            rng_command = shlex.split(rng)
        elif shutil.which("hexdump"):
            rng_command = [shutil.which("hexdump")]
        elif shutil.which("busybox"):
            rng_command = [shutil.which("busybox"), "hexdump"]
        else:
            self.skipTest("hexdump or BusyBox is required")
        self.env = dict(os.environ, IPKG_INSTROOT=str(self.root),
                        PATH=str(binary_dir) + os.pathsep + os.environ["PATH"],
                        NIKKI_TEST_STATE=str(self.state_path),
                        NIKKI_TEST_ENTROPY_WRAPPER=str(binary_dir / "hexdump"),
                        NIKKI_TEST_RNG_COMMAND=json.dumps(rng_command))

    def initialize(self, config, scenarios=()):
        self.state_path.write_text(json.dumps({"config": config,
                                               "mutations": [], "entropy_calls": 0}))
        self.env["NIKKI_TEST_RNG"] = json.dumps(scenarios)
        shell = shlex.split(os.environ.get("NIKKI_TEST_SHELL", "/bin/sh"))
        # BusyBox's standalone shell may prefer its own applets over PATH.
        # A function ensures fault injection also intercepts hexdump there.
        driver = 'hexdump() { "$NIKKI_TEST_ENTROPY_WRAPPER" "$@"; }; . "$1"'
        result = subprocess.run(shell + ["-c", driver, "nikki-init", str(SCRIPT)], env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.stdout, "", "credentials must not be printed")
        return result, json.loads(self.state_path.read_text())

    def fresh_config(self):
        return {INIT: "1", PASSWORD: "", "nikki.@authentication[0].username": "custom",
                "nikki.subscription.url": "https://example.com/profile.yaml",
                "nikki.@authentication[1].password": "keep-another-account"}

    def test_fresh_install_and_repeat_preserve_other_settings(self):
        original = self.fresh_config()
        result, state = self.initialize(original)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["entropy_calls"], 2)
        for key in (API, PASSWORD):
            self.assertRegex(state["config"][key], r"^[0-9a-f]{64}$")
        self.assertNotEqual(state["config"][API], state["config"][PASSWORD])
        expected = {**original, API: state["config"][API], PASSWORD: state["config"][PASSWORD]}
        expected.pop(INIT)
        self.assertEqual(state["config"], expected)
        result, repeated = self.initialize(state["config"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(repeated["config"], state["config"])
        self.assertEqual(repeated["mutations"], [])
        self.assertEqual(repeated["entropy_calls"], 0)

    def test_upgrade_without_init_or_with_disabled_init_keeps_empty_values(self):
        for marker in (None, "0"):
            with self.subTest(marker=marker):
                config = {API: "", PASSWORD: ""}
                if marker is not None:
                    config[INIT] = marker
                result, state = self.initialize(config, ["fail"])
                self.assertEqual(result.returncode, 0)
                self.assertEqual(state["config"], config)
                self.assertEqual(state["mutations"], [])
                self.assertEqual(state["entropy_calls"], 0)

    def test_preconfigured_credentials_survive_init_marker(self):
        config = {**self.fresh_config(), API: "old-api ' $() ;", PASSWORD: 'old proxy " \\'}
        result, state = self.initialize(config, ["fail"])
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = dict(config)
        expected.pop(INIT)
        self.assertEqual(state["config"], expected)
        self.assertEqual(state["entropy_calls"], 0)
        self.assertEqual(state["mutations"], ["del", "commit"])

    def test_only_missing_credential_is_generated(self):
        for existing, missing in ((API, PASSWORD), (PASSWORD, API)):
            with self.subTest(existing=existing):
                config = {**self.fresh_config(), existing: "preserve-this-value"}
                result, state = self.initialize(config)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(state["entropy_calls"], 1)
                self.assertEqual(state["config"][existing], config[existing])
                self.assertRegex(state["config"][missing], r"^[0-9a-f]{64}$")

    def test_entropy_failure_does_not_modify_configuration(self):
        for failed_call in (0, 1):
            for failure in ("fail", "short", "malformed", "output_then_fail"):
                with self.subTest(failed_call=failed_call, failure=failure):
                    config = self.fresh_config()
                    scenarios = ["real"] * failed_call + [failure]
                    result, state = self.initialize(config, scenarios)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(state["config"], config)
                    self.assertEqual(state["mutations"], [])

    def test_failed_initialization_can_be_retried(self):
        result, state = self.initialize(self.fresh_config(), ["real", "fail"])
        self.assertNotEqual(result.returncode, 0)
        result, state = self.initialize(state["config"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(INIT, state["config"])
        self.assertNotEqual(state["config"][API], state["config"][PASSWORD])


if __name__ == "__main__":
    unittest.main()
