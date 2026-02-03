import json
import os
import unittest

from azul_security import exceptions
from azul_security import security as se

from . import support


class TestInvalids(unittest.TestCase):
    def setUp(self) -> None:
        support.resetEnv()

    def test_bad_minimum_required_access(self):
        # non existent label
        os.environ["security_minimum_required_access"] = json.dumps(["JUB"])
        self.assertRaises(exceptions.SecurityConfigException, se.Security)

        # marking in security_minimum_required_access
        os.environ["security_minimum_required_access"] = json.dumps(["rouge", "jam"])
        self.assertRaises(exceptions.SecurityConfigException, se.Security)

    def test_dupe_labels(self):
        os.environ["security_minimum_required_access"] = json.dumps([])
        os.environ["security_default"] = "REL:APPLE"
        os.environ["security_presets"] = json.dumps([])
        os.environ["security_allow_releasability_priority_gte"] = "30"
        os.environ["security_labels"] = json.dumps(
            {
                "classification": {
                    "title": "Classifications",
                    "options": [
                        {"name": "MOD1"},
                        {"name": "LOW"},
                        {"name": "LOW: LY"},
                        {"name": "MEDIUM"},
                        {"name": "HIGH"},
                        {"name": "TOP HIGH"},
                    ],
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
                    "title": "Groups",
                    "options": [
                        {"name": "REL:APPLE"},
                        {"name": "REL:BEE"},
                        {"name": "REL:CAR"},
                    ],
                },
                "tlp": {
                    "title": "TLP",
                    "options": [
                        {"name": "TLP:CLEAR"},
                        {"name": "TLP:GREEN"},
                        {"name": "TLP:AMBER"},
                        {"name": "TLP:AMBER+STRICT"},
                    ],
                },
            }
        )

        self.assertRaises(exceptions.SecurityConfigException, se.Security)
        os.environ["security_allow_releasability_priority_gte"] = "30"
        os.environ["security_labels"] = json.dumps(
            {
                "classification": {
                    "title": "Classifications",
                    "options": [
                        {"name": "LOW"},
                        {"name": "LOW: LY"},
                        {"name": "MEDIUM"},
                        {"name": "HIGH"},
                        {"name": "TOP HIGH"},
                    ],
                },
                "caveat": {
                    "title": "Required",
                    "options": [
                        {"name": "MOD1"},
                        {"name": "MOD2"},
                        {"name": "MOD3"},
                        {"name": "HANOVERLAP"},
                        {"name": "OVER"},
                        {"name": "REL:CAR"},
                    ],
                },
                "releasability": {
                    "title": "Groups",
                    "options": [
                        {"name": "REL:APPLE"},
                        {"name": "REL:BEE"},
                        {"name": "REL:CAR"},
                    ],
                },
                "tlp": {
                    "title": "TLP",
                    "options": [
                        {"name": "TLP:CLEAR"},
                        {"name": "TLP:GREEN"},
                        {"name": "TLP:AMBER"},
                        {"name": "TLP:AMBER+STRICT"},
                    ],
                },
            }
        )
        self.assertRaises(exceptions.SecurityConfigException, se.Security)

    def test_bad_rel_tlp_presets(self):
        os.environ["security_presets"] = json.dumps(["TOP HIGH REL:APPLE TLP:CLEAR"])
        se.Security()  # Shouldn't raise an exception
        os.environ["security_presets"] = json.dumps(["LOW REL:APPLE"])
        self.assertRaises(exceptions.SecurityParseException, se.Security)


class TestAnalog(unittest.TestCase):
    def setUp(self) -> None:
        support.resetEnv()
        self.sec = se.Security()
        return super().setUp()

    def test_presets(self):
        os.environ["security_minimum_required_access"] = json.dumps([])
        self.assertEqual("LOW TLP:CLEAR", self.sec._s.presets[0])
        self.assertEqual("HIGH", self.sec._s.presets[1])
        self.assertEqual("MEDIUM REL:APPLE,BEE", self.sec._s.presets[2])
        self.assertEqual("MEDIUM REL:APPLE,BEE,CAR", self.sec._s.presets[3])
        self.assertEqual("TOP HIGH REL:APPLE,BEE,CAR", self.sec._s.presets[4])

    def test_tlp(self):
        items = [
            "LOW TLP:AMBER",
            "LOW TLP:CLEAR",
            "LOW TLP:GREEN",
            "LOW TLP:AMBER+STRICT",
        ]
        self.assertEqual("LOW TLP:AMBER+STRICT", self.sec.string_combine(items))
        items = [
            "LOW TLP:AMBER",
            "LOW TLP:CLEAR",
            "LOW TLP:GREEN",
        ]
        self.assertEqual("LOW TLP:AMBER", self.sec.string_combine(items))
        items = [
            "LOW TLP:CLEAR",
            "LOW TLP:GREEN",
        ]
        self.assertEqual("LOW TLP:GREEN", self.sec.string_combine(items))
        items = [
            "LOW TLP:CLEAR",
        ]
        self.assertEqual("LOW TLP:CLEAR", self.sec.string_combine(items))

    def test_rel_combine(self):
        # combine
        # invalid since no common group
        items = [
            "REL:APPLE",
            "REL:BEE",
            "REL:CAR",
        ]
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_combine, items)
        items = [
            "MEDIUM REL:APPLE",
            "MEDIUM REL:APPLE,BEE",
            "MEDIUM REL:APPLE,BEE,CAR",
        ]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))
        items = [
            "MEDIUM REL:APPLE",
            "MEDIUM REL:APPLE,BEE",
        ]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))
        items = [
            "MEDIUM REL:APPLE",
        ]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))

    def test_rel_render(self):
        self.assertEqual(
            "MEDIUM REL:APPLE,BEE,CAR",
            self.sec.string_normalise("MEDIUM REL:APPLE,BEE,CAR"),
        )
        self.assertEqual(
            "MEDIUM REL:APPLE,BEE",
            self.sec.string_normalise("MEDIUM REL:APPLE,BEE"),
        )
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "REL:BEE,CAR")

    def test_exclusive(self):
        items = [
            "LOW",
            "MEDIUM",
            "LOW: LY",
        ]
        self.assertEqual("MEDIUM", self.sec.string_combine(items))
        items = [
            "TOP HIGH",
            "MEDIUM",
            "LOW: LY",
        ]
        self.assertEqual("TOP HIGH", self.sec.string_combine(items))
        items = [
            "HIGH",
            "MEDIUM",
            "LOW: LY",
            "MEDIUM MOD1",
        ]
        self.assertEqual("HIGH MOD1", self.sec.string_combine(items))

        self.assertEqual(
            "LOW: LY",
            self.sec.string_normalise("LOW: LY"),
        )
        self.assertEqual(
            "LOW: LY MOD1",
            self.sec.string_normalise("LOW: LY MOD1"),
        )

    def test_access_calc_unique(self):
        calc = self.sec._access_calc_unique(["LOW", "LOW: LY", "MEDIUM", "HIGH", "TOP HIGH"])
        self.assertEqual(calc, "b649ae298a22c963b8921d45e2abba21")
        calc = self.sec._access_calc_unique(["LOW", "MEDIUM", "HIGH", "TOP HIGH"])
        self.assertEqual(calc, "bbcaf5bea10d62cc1e8354af4a81b37f")

    def test_safe_to_unsafe(self):
        ret = self.sec.safe_to_unsafe(["s-low", "s-low--ly", "s-rel-apple", "blah"], drop_mismatch=True)
        self.assertEqual(ret, ["LOW", "LOW: LY", "REL:APPLE"])

        self.assertRaises(
            exceptions.SecurityParseException,
            self.sec.safe_to_unsafe,
            ["s-low", "s-low--ly", "s-rel-apple", "blah"],
            drop_mismatch=False,
        )

        ret = self.sec.safe_to_unsafe(["s-low", "s-low--ly", "s-rel-apple"], drop_mismatch=False)
        self.assertEqual(ret, ["LOW", "LOW: LY", "REL:APPLE"])

    def test_unsafe_to_safe(self):
        ret = self.sec.unsafe_to_safe(["LOW", "LOW: LY", "REL:APPLE", "BLAH"], drop_mismatch=True)
        self.assertEqual(ret, ["s-low", "s-low--ly", "s-rel-apple"])

        self.assertRaises(
            exceptions.SecurityParseException,
            self.sec.unsafe_to_safe,
            ["LOW", "LOW: LY", "REL:APPLE", "BLAH"],
            drop_mismatch=False,
        )

        ret = self.sec.unsafe_to_safe(["LOW", "LOW: LY", "REL:APPLE"], drop_mismatch=False)
        self.assertEqual(ret, ["s-low", "s-low--ly", "s-rel-apple"])

    def test_summarise_user_access_large(self):
        ret = self.sec.summarise_user_access(
            [
                "MOD2",
                "MOD1",
                "LOW",
                "LOW: LY",
                "MEDIUM",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
                "HIGH",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
                "TOP HIGH",
            ]
        )
        print(ret)
        self.assertEqual(
            ret.labels,
            [
                "HIGH",
                "LOW",
                "LOW: LY",
                "MEDIUM",
                "MOD1",
                "MOD2",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
                "TOP HIGH",
            ],
        )

        self.assertEqual(ret.labels_inclusive, ["REL:APPLE", "REL:BEE", "REL:CAR"])
        self.assertEqual(
            ret.labels_exclusive,
            ["HIGH", "LOW", "LOW: LY", "MEDIUM", "MOD1", "MOD2", "TOP HIGH"],
        )
        self.assertEqual(ret.labels_markings, ["TLP:AMBER", "TLP:AMBER+STRICT", "TLP:CLEAR", "TLP:GREEN"])

        self.assertEqual(ret.unique, "3c4030fbc1cac2518831a8fa476cd2db")

        self.assertEqual(ret.max_access, "TOP HIGH MOD1 MOD2 REL:APPLE,BEE,CAR")

        self.assertEqual(
            ret.allowed_presets,
            [
                "LOW TLP:CLEAR",
                "HIGH",
                "MEDIUM REL:APPLE,BEE",
                "MEDIUM REL:APPLE,BEE,CAR",
                "TOP HIGH REL:APPLE,BEE,CAR",
            ],
        )

    def test_summarise_user_access_large2(self):
        ret = self.sec.summarise_user_access(
            [
                "MOD2",
                "MOD1",
                "LOW",
                "LOW: LY",
                "MEDIUM",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
                "HIGH",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
                "TOP HIGH",
            ],
            denylist=[
                "MOD2",
                "MOD1",
                "LOW: LY",
                "MEDIUM",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
                "HIGH",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
                "TOP HIGH",
            ],
        )
        print(ret)
        self.assertEqual(ret.labels, ["LOW"])

        self.assertEqual(ret.labels_inclusive, [])
        self.assertEqual(ret.labels_exclusive, ["LOW"])
        self.assertEqual(ret.labels_markings, [])

        self.assertEqual(ret.unique, "41bc94cbd8eebea13ce0491b2ac11b88")
        self.assertEqual(ret.max_access, "LOW")
        self.assertEqual(
            ret.allowed_presets,
            [
                "LOW TLP:CLEAR",
            ],
        )

    def test_summarise_user_access_drop_all_classifications_that_allow_rels(self):
        """Edge case where RELs are present but all the classifications that allow RELs have been denied."""
        ret = self.sec.summarise_user_access(
            [
                "LOW",
                "LOW: LY",
                "MEDIUM",
                "HIGH",
                "TOP HIGH",
                "MOD2",
                "MOD1",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
            ],
            denylist=[
                "MEDIUM",
                "HIGH",
                "TOP HIGH",
            ],
        )
        print(ret)
        self.assertEqual(
            ret.labels, ["LOW", "LOW: LY", "MOD1", "MOD2", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:CLEAR", "TLP:GREEN"]
        )

        self.assertEqual(ret.labels_inclusive, [])
        self.assertEqual(ret.labels_exclusive, ["LOW", "LOW: LY", "MOD1", "MOD2"])
        self.assertEqual(ret.labels_markings, ["TLP:AMBER", "TLP:AMBER+STRICT", "TLP:CLEAR", "TLP:GREEN"])

        self.assertEqual(ret.unique, "5a929d2916adbb837329a09214e89074")

        self.assertEqual(ret.max_access, "LOW: LY MOD1 MOD2 TLP:AMBER+STRICT")
        self.assertEqual(
            ret.allowed_presets,
            [
                "LOW TLP:CLEAR",
            ],
        )

    def test_summarise_user_access_drop_all_rels_and_classifications_that_allow_tlps(self):
        """Edge case where you keep all classifications that allow TLPs and drop all RELs."""
        ret = self.sec.summarise_user_access(
            [
                "LOW",
                "LOW: LY",
                "MEDIUM",
                "HIGH",
                "TOP HIGH",
                "MOD2",
                "MOD1",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
            ],
            denylist=[
                "LOW",
                "LOW: LY",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
            ],
        )
        print(ret)
        self.assertEqual(
            ret.labels,
            ["HIGH", "MEDIUM", "MOD1", "MOD2", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:CLEAR", "TLP:GREEN", "TOP HIGH"],
        )

        self.assertEqual(ret.labels_inclusive, [])
        self.assertEqual(ret.labels_exclusive, ["HIGH", "MEDIUM", "MOD1", "MOD2", "TOP HIGH"])
        self.assertEqual(ret.labels_markings, ["TLP:AMBER", "TLP:AMBER+STRICT", "TLP:CLEAR", "TLP:GREEN"])

        self.assertEqual(ret.unique, "a876d65ff5384928d2ff2b9bcd5875ed")
        self.assertEqual(ret.max_access, "TOP HIGH MOD1 MOD2")
        self.assertEqual(
            ret.allowed_presets,
            [
                "HIGH",
            ],
        )

    def test_summarise_user_access_small(self):
        """Verify a user with low access can summarise and have access to the system."""
        ret = self.sec.summarise_user_access(["LOW", "TLP:CLEAR"])
        print(ret)
        self.assertEqual(ret.labels, ["LOW", "TLP:CLEAR"])

        self.assertEqual(ret.labels_inclusive, [])
        self.assertEqual(ret.labels_exclusive, ["LOW"])
        self.assertEqual(ret.labels_markings, ["TLP:CLEAR"])

        self.assertEqual(ret.unique, "93a7969076f12224c1f7cc0ad078ed67")
        self.assertEqual(ret.max_access, "LOW TLP:CLEAR")
        self.assertEqual(ret.allowed_presets, ["LOW TLP:CLEAR"])

    def test_summarise_user_access_with_rels(self):
        """Verify a user with high access with RELs can summarise and have access to the system."""
        ret = self.sec.summarise_user_access(["TOP HIGH", "REL:APPLE"])
        print(ret)
        self.assertEqual(ret.labels, ["REL:APPLE", "REL:BEE", "REL:CAR", "TOP HIGH"])

        self.assertEqual(ret.labels_inclusive, ["REL:APPLE", "REL:BEE", "REL:CAR"])
        self.assertEqual(ret.labels_exclusive, ["TOP HIGH"])
        self.assertEqual(ret.labels_markings, [])

        self.assertEqual(ret.unique, "cee092cac12cfa12c25f9ec8dc04bea0")
        self.assertEqual(ret.max_access, "TOP HIGH REL:APPLE,BEE,CAR")
        self.assertEqual(ret.allowed_presets, ["TOP HIGH REL:APPLE,BEE,CAR"])

    def test_summarise_user_access_with_rels_no_origin(self):
        """Verify a user with high access with RELs that aren't he origin can summarise and have access to the system."""
        ret = self.sec.summarise_user_access(["HIGH", "REL:CAR"])
        print(ret)
        self.assertEqual(ret.labels, ["HIGH", "REL:APPLE", "REL:CAR"])

        self.assertEqual(ret.labels_inclusive, ["REL:APPLE", "REL:CAR"])
        self.assertEqual(ret.labels_exclusive, ["HIGH"])
        self.assertEqual(ret.labels_markings, [])

        self.assertEqual(ret.unique, "633f554c1fbe9c7b816b56888a820e8e")
        self.assertEqual(ret.max_access, "HIGH REL:APPLE,CAR")
        self.assertEqual(ret.allowed_presets, ["HIGH"])

    def test_get_enforceable_tlps(self):
        """Verify getting enforceable marking works with safe and unsafe markings mixed with other classification strings."""

        def tlp_test(test_input, test_output):
            result = self.sec.get_enforceable_markings(test_input)
            self.assertEqual(result, test_output)

            test_input_safe = self.sec.unsafe_to_safe(test_input)
            self.assertEqual(len(test_input_safe), len(test_input), "The unsafe to safe conversion has dropped values")
            test_input_safe.sort()
            test_input.sort()
            if len(test_input) > 0:
                self.assertNotEqual(
                    test_input_safe, test_input, "The unsafe to safe conversion had no affect on the input value."
                )
            result = self.sec.get_enforceable_markings(test_input_safe)
            safe_output = self.sec.unsafe_to_safe(test_output)
            self.assertEqual(result, safe_output)

        # Sets that match
        tlp_test(["TLP:CLEAR", "TLP:AMBER", "TLP:AMBER+STRICT"], ["TLP:AMBER+STRICT"])
        # double up to ensure cache doesn't somehow mutate the result
        tlp_test(["TLP:CLEAR", "TLP:AMBER", "TLP:AMBER+STRICT"], ["TLP:AMBER+STRICT"])
        tlp_test(["TLP:AMBER+STRICT"], ["TLP:AMBER+STRICT"])
        tlp_test(["TLP:GREEN", "TLP:AMBER+STRICT"], ["TLP:AMBER+STRICT"])
        tlp_test(["TOP HIGH", "MOD1", "TLP:CLEAR", "TLP:AMBER", "TLP:AMBER+STRICT"], ["TLP:AMBER+STRICT"])
        tlp_test(["MEDIUM", "REL:CAR", "MOD1", "TLP:CLEAR", "TLP:AMBER+STRICT"], ["TLP:AMBER+STRICT"])

        # Sets that don't match
        tlp_test(["TLP:CLEAR", "TLP:AMBER"], [])
        tlp_test([], [])
        tlp_test(["TLP:GREEN"], [])
        tlp_test(["TOP HIGH", "MOD1", "TLP:CLEAR", "TLP:AMBER"], [])
        tlp_test(["MEDIUM", "REL:CAR", "MOD1", "TLP:CLEAR"], [])

    def test_get_labels(self):
        self.assertEqual(
            self.sec.get_labels_allowed(),
            frozenset(
                {
                    "TOP HIGH",
                    "TLP:CLEAR",
                    "LOW: LY",
                    "REL:BEE",
                    "TLP:GREEN",
                    "TLP:AMBER",
                    "MEDIUM",
                    "REL:APPLE",
                    "TLP:AMBER+STRICT",
                    "MOD2",
                    "REL:CAR",
                    "HIGH",
                    "MOD1",
                    "LOW",
                    "MOD3",
                    "HANOVERLAP",
                    "OVER",
                }
            ),
        )
        self.assertEqual(self.sec.get_labels_inclusive(), frozenset({"REL:APPLE", "REL:BEE", "REL:CAR"}))
        self.assertEqual(
            self.sec.get_labels_exclusive(),
            frozenset({"LOW: LY", "MOD2", "MOD1", "LOW", "HIGH", "MEDIUM", "TOP HIGH", "OVER", "MOD3", "HANOVERLAP"}),
        )
        self.assertEqual(
            self.sec.get_labels_markings(), frozenset({"TLP:AMBER+STRICT", "TLP:AMBER", "TLP:CLEAR", "TLP:GREEN"})
        )
        self.assertEqual(self.sec.get_default_security(), "LOW")

    def test_bad_security_rels_tlps(self):
        """Check good and bad TLP/REL with their corresponding inclusive/exclusive partners."""
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "LOW REL:APPLE")
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "LOW REL:CAR TLP:CLEAR")
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "TLP:CLEAR")
        self.assertEqual("LOW TLP:CLEAR", self.sec.string_normalise("LOW TLP:CLEAR"))
        self.assertEqual("LOW TLP:GREEN", self.sec.string_normalise("LOW TLP:CLEAR TLP:GREEN"))
        self.assertEqual("MEDIUM REL:APPLE,CAR", self.sec.string_normalise("MEDIUM REL:APPLE REL:CAR"))
        self.assertEqual("MEDIUM REL:APPLE,CAR", self.sec.string_normalise("MEDIUM REL:APPLE REL:CAR"))
        self.assertEqual("TOP HIGH REL:APPLE", self.sec.string_normalise("TOP HIGH REL:APPLE"))
        self.assertEqual("TOP HIGH REL:APPLE,CAR", self.sec.string_normalise("TOP HIGH REL:APPLE REL:CAR"))
        self.assertEqual("TOP HIGH", self.sec.string_normalise("TOP HIGH TLP:GREEN"))
        self.assertEqual("TOP HIGH REL:APPLE", self.sec.string_normalise("TOP HIGH REL:APPLE TLP:CLEAR TLP:GREEN"))

    def test_rel_origin_abb_name(self):
        """Check whether origin rel nickname is shown when only REL present is origin"""
        ret = self.sec.summarise_user_access(
            [
                "LOW",
                "LOW: LY",
                "MEDIUM",
                "HIGH",
                "TOP HIGH",
                "REL:APPLE",
                "REL:BEE",
                "REL:CAR",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
            ],
            denylist=[
                "REL:BEE",
                "REL:CAR",
                "TLP:AMBER",
                "TLP:AMBER+STRICT",
                "TLP:CLEAR",
                "TLP:GREEN",
            ],
        )
        self.assertEqual(ret.max_access, "TOP HIGH REL:APPLEO")
