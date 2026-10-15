import unittest

from click.testing import CliRunner

from azul_security import cli_commands
from azul_security import security as se

from . import support


class TestDisplaySetting(unittest.TestCase):
    def setUp(self) -> None:
        support.resetEnv()
        self.sec = se.Security()

    def test_display_safe_to_unsafe(self):
        runner = CliRunner()
        result = runner.invoke(cli_commands.show_role_mapping)
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            """Mapping of Opensearch roles to the security configuration labels:
's-hanoverlap': 'HANOVERLAP'
's-high': 'HIGH'
's-low': 'LOW'
's-low--ly': 'LOW: LY'
's-medium': 'MEDIUM'
's-mod1': 'MOD1'
's-mod2': 'MOD2'
's-mod3': 'MOD3'
's-over': 'OVER'
's-rel-apple': 'REL:APPLE'
's-rel-bee': 'REL:BEE'
's-rel-car': 'REL:CAR'
's-restricted1': 'RESTRICTED1'
's-restricted2': 'RESTRICTED2'
's-tlp-amber': 'TLP:AMBER'
's-tlp-amber-strict': 'TLP:AMBER+STRICT'
's-tlp-clear': 'TLP:CLEAR'
's-tlp-green': 'TLP:GREEN'
's-top-high': 'TOP HIGH'
""",
        )

    def test_display_unsafe_to_safe(self):
        runner = CliRunner()
        result = runner.invoke(cli_commands.show_role_mapping, args="--is-unsafe-to-safe")
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            """Mapping of the Security Configuration labels to the Opensearch roles:
'HANOVERLAP': 's-hanoverlap'
'HIGH': 's-high'
'LOW': 's-low'
'LOW: LY': 's-low--ly'
'MEDIUM': 's-medium'
'MOD1': 's-mod1'
'MOD2': 's-mod2'
'MOD3': 's-mod3'
'OVER': 's-over'
'REL:APPLE': 's-rel-apple'
'REL:BEE': 's-rel-bee'
'REL:CAR': 's-rel-car'
'RESTRICTED1': 's-restricted1'
'RESTRICTED2': 's-restricted2'
'TLP:AMBER': 's-tlp-amber'
'TLP:AMBER+STRICT': 's-tlp-amber-strict'
'TLP:CLEAR': 's-tlp-clear'
'TLP:GREEN': 's-tlp-green'
'TOP HIGH': 's-top-high'
""",
        )

    def test_can_access(self):
        runner = CliRunner()
        # Basic assertions
        result = runner.invoke(cli_commands.can_access, args=["LOW", "LOW"])
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            "true\n",
        )

        result = runner.invoke(cli_commands.can_access, args=["MEDIUM", "MEDIUM"])
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            "true\n",
        )

        result = runner.invoke(cli_commands.can_access, args=["LOW", "MEDIUM"])
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            "false\n",
        )

        result = runner.invoke(cli_commands.can_access, args=["MEDIUM", "LOW"])
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            "true\n",
        )

        result = runner.invoke(cli_commands.can_access, args=["MEDIUM", "LOW MOD1"])
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            "false\n",
        )
