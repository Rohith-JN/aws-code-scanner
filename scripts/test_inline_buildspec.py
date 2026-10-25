import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from scanner_source import SCANNER_FILES

spec = importlib.util.spec_from_file_location("inline_buildspec", Path(__file__).with_name("generate-inline-buildspec.py"))
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
REPO = Path(__file__).resolve().parent.parent


class InlineBuildspecTests(unittest.TestCase):
    def test_generated_file_is_current(self):
        self.assertEqual((REPO / "buildspec.inline.yml").read_text(encoding="utf-8"), generator.generate(REPO))

    def test_yaml_preserves_phases_and_environment(self):
        base = yaml.safe_load((REPO / "buildspec.yml").read_text(encoding="utf-8"))
        inline = yaml.safe_load(generator.generate(REPO))
        self.assertEqual(inline["version"], 0.2)
        self.assertEqual(inline["env"], base["env"])
        for phase in ("build", "post_build"):
            self.assertEqual(inline["phases"][phase], base["phases"][phase])
        self.assertEqual(inline["phases"]["install"]["commands"][1:], base["phases"]["install"]["commands"][1:])
        for phase in inline["phases"].values():
            self.assertTrue(all(isinstance(command, str) for command in phase["commands"]))

    @unittest.skipUnless(os.environ.get("SCANNER_TEST_BASH"), "Set SCANNER_TEST_BASH to test bootstrap execution")
    def test_bootstrap_recreates_files_from_an_empty_directory(self):
        inline = yaml.safe_load(generator.generate(REPO))
        command = inline["phases"]["install"]["commands"][0]
        installer = "bash scripts/install-scanners.sh .scanner-tools\n"
        self.assertTrue(command.endswith(installer))
        # Execute the real bootstrap, stopping before tool downloads/install.
        bootstrap = command[:-len(installer)]
        cache = REPO / ".cache"
        cache.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="inline-bootstrap-", dir=cache) as scratch:
            # CodeBuild executes command files. Do the same here, avoiding the
            # Windows command-line length limit for a large Bash -c argument.
            scratch = Path(scratch)
            work = scratch / "source"
            work.mkdir()
            bootstrap_path = scratch / "bootstrap.sh"
            bootstrap_path.write_text(bootstrap, encoding="utf-8", newline="\n")
            result = subprocess.run([os.environ["SCANNER_TEST_BASH"], str(bootstrap_path)], cwd=work, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in SCANNER_FILES:
                self.assertEqual((work / name).read_text(encoding="utf-8"), (REPO / name).read_text(encoding="utf-8"), name)
            self.assertFalse((work / ".scanner-tools").exists())
            for phase in inline["phases"].values():
                for script in phase["commands"]:
                    command_path = scratch / "command.sh"
                    command_path.write_text(script, encoding="utf-8", newline="\n")
                    checked = subprocess.run([os.environ["SCANNER_TEST_BASH"], "-n", str(command_path)], capture_output=True, text=True)
                    self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
