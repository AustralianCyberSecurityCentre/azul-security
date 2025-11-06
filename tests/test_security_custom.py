import json
import os
import unittest

from azul_security import exceptions
from azul_security import security as se
from azul_security import settings

from . import support


class TestCustom(unittest.TestCase):
    def setUp(self) -> None:
        support.resetEnv()

    def test_simple(self):
        sec = se.Security()
        items = ["LOW", "MEDIUM", "HIGH"]
        self.assertEqual("HIGH", sec.string_combine(items))

    def test_unsafe_to_safe(self):
        os.environ["security_default"] = "s"
        os.environ["security_allow_releasability_priority_gte"] = "30"
        os.environ["security_labels"] = json.dumps(
            {
                "classification": {
                    "options": [
                        {"name": "Some_-Data"},
                        {"name": "Thinking  !! #$*(%&( Normal"},
                    ]
                },
                "caveat": {
                    "title": "Required",
                    "options": [
                        {"name": "MOD1"},
                        {"name": "MOD2"},
                        {"name": "MOD3"},
                        {"name": "HANOVERLAP"},
                        {"name": "OVER"},
                    ],
                },
                "releasability": {
                    "options": [
                        {"name": "REL:s"},
                        {"name": "rel:Mercy!!!!"},
                        {"name": "REL:%(&$*(#^(*Yeah"},
                    ]
                },
                "tlp": {
                    "options": [
                        {"name": "1234"},
                        {"name": "!@#$"},
                        {"name": "abcd"},
                    ]
                },
            }
        )
        set = settings.Settings()
        self.assertEqual(set.unsafe_to_safe["SOME_-DATA"], "s-some_-data")
        self.assertEqual(set.unsafe_to_safe["THINKING  !! #$*(%&( NORMAL"], "s-thinking-------------normal")
        self.assertEqual(set.unsafe_to_safe["REL:S"], "s-rel-s")
        self.assertEqual(set.unsafe_to_safe["REL:MERCY!!!!"], "s-rel-mercy----")
        self.assertEqual(set.unsafe_to_safe["REL:%(&$*(#^(*YEAH"], "s-rel-----------yeah")
        self.assertEqual(set.unsafe_to_safe["1234"], "s-1234")
        self.assertEqual(set.unsafe_to_safe["!@#$"], "s-----")
        self.assertEqual(set.unsafe_to_safe["ABCD"], "s-abcd")

    def test_safe_to_unsafe(self):
        os.environ["security_default"] = "s"
        os.environ["security_allow_releasability_priority_gte"] = "30"
        os.environ["security_labels"] = json.dumps(
            {
                "classification": {
                    "options": [
                        {"name": "Some_-Data"},
                        {"name": "Thinking  !! #$*(%&( Normal"},
                    ]
                },
                "caveat": {
                    "title": "Required",
                    "options": [
                        {"name": "MOD1"},
                        {"name": "MOD2"},
                        {"name": "MOD3"},
                        {"name": "HANOVERLAP"},
                        {"name": "OVER"},
                    ],
                },
                "releasability": {
                    "options": [
                        {"name": "REL:s"},
                        {"name": "rel:Mercy!!!!"},
                        {"name": "REL:%(&$*(#^(*Yeah"},
                    ]
                },
                "tlp": {
                    "options": [
                        {"name": "1234"},
                        {"name": "!@#$"},
                        {"name": "abcd"},
                    ]
                },
            }
        )
        set = settings.Settings()
        self.assertEqual(set.safe_to_unsafe["s-some_-data"], "SOME_-DATA")
        self.assertEqual(set.safe_to_unsafe["s-thinking-------------normal"], "THINKING  !! #$*(%&( NORMAL")
        self.assertEqual(set.safe_to_unsafe["s-rel-s"], "REL:S")
        self.assertEqual(set.safe_to_unsafe["s-rel-mercy----"], "REL:MERCY!!!!")
        self.assertEqual(set.safe_to_unsafe["s-rel-----------yeah"], "REL:%(&$*(#^(*YEAH")
        self.assertEqual(set.safe_to_unsafe["s-1234"], "1234")
        self.assertEqual(set.safe_to_unsafe["s-----"], "!@#$")
        self.assertEqual(set.safe_to_unsafe["s-abcd"], "ABCD")
