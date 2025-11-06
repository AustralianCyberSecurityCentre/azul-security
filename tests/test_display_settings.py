import json
import os
import unittest

from click.testing import CliRunner

from azul_security import display_settings
from azul_security import security as se

from . import support


class TestDisplaySetting(unittest.TestCase):
    def setUp(self) -> None:
        support.resetEnv()
        self.sec = se.Security()

    def test_display_opensearch_roles_to_be_created(self):
        runner = CliRunner()
        result = runner.invoke(display_settings.show_opensearch_roles)
        print(result.stdout)
        self.assertEqual(
            result.stdout,
            """The following roles must exist in Opensearch for Azul security to work:
azul-fill1
azul-fill2
azul-fill3
azul-fill4
azul-fill5
azul_read
azul_write
s-any
s-hanoverlap
s-high
s-low
s-low--ly
s-medium
s-mod1
s-mod2
s-mod3
s-over
s-rel-apple
s-rel-bee
s-rel-car
s-tlp-amber
s-tlp-amber-strict
s-tlp-clear
s-tlp-green
s-top-high
Admins will need to create these roles and map them to the appropriate backend_role(s) provided by your OIDC system as needed.
""",
        )

    def test_display_safe_to_unsafe(self):
        runner = CliRunner()
        result = runner.invoke(display_settings.show_role_mapping)
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
's-tlp-amber': 'TLP:AMBER'
's-tlp-amber-strict': 'TLP:AMBER+STRICT'
's-tlp-clear': 'TLP:CLEAR'
's-tlp-green': 'TLP:GREEN'
's-top-high': 'TOP HIGH'
""",
        )

    def test_display_unsafe_to_safe(self):
        runner = CliRunner()
        result = runner.invoke(display_settings.show_role_mapping, args="--is-unsafe-to-safe")
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
'TLP:AMBER': 's-tlp-amber'
'TLP:AMBER+STRICT': 's-tlp-amber-strict'
'TLP:CLEAR': 's-tlp-clear'
'TLP:GREEN': 's-tlp-green'
'TOP HIGH': 's-top-high'
""",
        )
