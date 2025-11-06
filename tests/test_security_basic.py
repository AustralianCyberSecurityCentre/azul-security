import json
import os
import unittest

from azul_security import exceptions
from azul_security import security as se
from azul_security.friendly import to_securityt

from . import support


class TestBasic(unittest.TestCase):
    def setUp(self) -> None:
        support.resetEnv()
        self.sec = se.Security()

    def test_combine(self):
        items = [
            "LOW",
        ]
        self.assertEqual("LOW", self.sec.string_combine(items))
        items = ["LOW", "MEDIUM"]
        self.assertEqual("MEDIUM", self.sec.string_combine(items))
        items = ["LOW", "MEDIUM", "HIGH"]
        self.assertEqual("HIGH", self.sec.string_combine(items))
        items = ["MEDIUM", "HIGH"]
        self.assertEqual("HIGH", self.sec.string_combine(items))

        items = ["MEDIUM REL:APPLE", "MEDIUM"]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))

        items = ["MEDIUM REL:APPLE", "MEDIUM REL:APPLE,BEE,CAR"]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))

        items = ["MEDIUM REL:APPLE,BEE REL:CAR"]
        self.assertEqual("MEDIUM REL:APPLE,BEE,CAR", self.sec.string_combine(items))

        items = ["MEDIUM REL:APPLE,CAR", "MEDIUM REL:APPLE,BEE"]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))

        items = ["MEDIUM REL:APPLE", "MEDIUM REL:APPLE,BEE,CAR REL:APPLE REL:BEE"]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))

        items = ["MEDIUM REL:APPLE", "MEDIUM REL:CAR"]
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_combine, items)

        items = [
            "LOW TLP:GREEN",
            "MEDIUM REL:APPLE",
        ]
        self.assertEqual("MEDIUM REL:APPLE", self.sec.string_combine(items))

        items = [
            "LOW TLP:AMBER",
            "MEDIUM REL:APPLE REL:BEE",
        ]
        self.assertEqual(
            "MEDIUM REL:APPLE,BEE",
            self.sec.string_combine(items),
        )

    def test_private_rank(self):
        ret = self.sec._rank(to_securityt(["LOW"], [], ["TLP:CLEAR"]))
        self.assertEqual([1, 0, 0, 1], list(ret))

        ret = self.sec._rank(to_securityt(["MEDIUM"], [], ["TLP:CLEAR"]))
        self.assertEqual([4, 0, 0, 1], list(ret))

        ret = self.sec._rank(to_securityt(["HIGH"], [], ["TLP:CLEAR"]))
        self.assertEqual([8, 0, 0, 1], list(ret))
        ret = self.sec._rank(to_securityt(["HIGH"], [], ["TLP:GREEN"]))
        self.assertEqual([8, 0, 0, 2], list(ret))

        ret = self.sec._rank(to_securityt(["LOW"], ["REL:APPLE"], ["TLP:GREEN"]))
        self.assertEqual([1, 0, 1, 2], list(ret))
        ret = self.sec._rank(to_securityt(["HIGH"], ["REL:APPLE"], ["TLP:GREEN"]))
        self.assertEqual([8, 0, 1, 2], list(ret))
        ret = self.sec._rank(to_securityt(["HIGH"], ["REL:BEE"], ["TLP:GREEN"]))
        self.assertEqual([8, 0, 2, 2], list(ret))
        ret = self.sec._rank(to_securityt(["HIGH"], ["REL:CAR"], ["TLP:GREEN"]))
        self.assertEqual([8, 0, 4, 2], list(ret))
        ret = self.sec._rank(to_securityt(["HIGH"], ["REL:CAR"], ["TLP:AMBER"]))
        self.assertEqual([8, 0, 4, 4], list(ret))

        # check that multiple of same type are ranked correctly
        ret = self.sec._rank(to_securityt([], ["REL:APPLE"], []))
        self.assertEqual([0, 0, 1, 0], list(ret))
        ret = self.sec._rank(to_securityt([], ["REL:CAR", "REL:APPLE"], []))
        self.assertEqual([0, 0, 5, 0], list(ret))
        ret = self.sec._rank(to_securityt([], ["REL:CAR", "REL:BEE", "REL:APPLE"], []))
        self.assertEqual([0, 0, 7, 0], list(ret))

    def test_rank(self):
        data = [
            "HIGH",
            "HIGH TLP:GREEN",
            "LOW",
            "LOW TLP:AMBER+STRICT",
        ]
        self.assertEqual(
            [
                "LOW",
                "LOW TLP:AMBER+STRICT",
                "HIGH",
            ],
            self.sec.string_rank(data),
        )

        self.assertEqual(
            [
                "MEDIUM REL:APPLE",
                "MEDIUM MOD1 REL:APPLE",
                "HIGH REL:APPLE",
            ],
            self.sec.string_rank(
                [
                    "HIGH REL:APPLE",
                    "MEDIUM REL:APPLE",
                    "MEDIUM MOD1 REL:APPLE",
                    "MEDIUM MOD1 REL:APPLE",
                    "MEDIUM MOD1 REL:APPLE",
                    "MEDIUM MOD1 REL:APPLE",
                    "MEDIUM MOD1 REL:APPLE",
                    "MEDIUM MOD1 REL:APPLE",
                ]
            ),
        )

        self.assertEqual(
            [
                "MEDIUM REL:APPLE",
                "MEDIUM REL:APPLE,BEE",
                "MEDIUM MOD1 REL:APPLE",
                "MEDIUM MOD1 REL:APPLE,BEE",
                "HIGH REL:APPLE",
                "HIGH REL:APPLE,BEE",
            ],
            self.sec.string_rank(
                [
                    "MEDIUM REL:APPLE",
                    "MEDIUM MOD1 REL:APPLE",
                    "HIGH REL:APPLE",
                    "MEDIUM REL:APPLE REL:BEE",
                    "MEDIUM MOD1 REL:APPLE,BEE",
                    "HIGH REL:APPLE REL:BEE",
                ]
            ),
        )

    def test_normalise(self):
        self.assertEqual("HIGH REL:APPLE", self.sec.string_normalise("HIGH REL:APPLE"))
        self.assertEqual("HIGH", self.sec.string_normalise("HIGH"))
        self.assertEqual(
            "HIGH REL:APPLE,BEE,CAR",
            self.sec.string_normalise("HIGH REL:APPLE REL:BEE REL:CAR"),
        )
        self.assertEqual(
            "HIGH MOD2 MOD3 REL:APPLE,BEE,CAR",
            self.sec.string_normalise("high REL:APPLE MOD2 MOD3 REL:BEE REL:CAR"),
        )

        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "MODERATOR")
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "HIGHREL:APPLE")
        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "HIGHTLP:GREEN")

        self.assertEqual("HIGH REL:APPLE", self.sec.string_normalise("high///REL:APPLE"))
        self.assertEqual(
            "HIGH REL:APPLE,BEE",
            self.sec.string_normalise("HIGH///REL:APPLE\\REL:BEE"),
        )
        self.assertEqual(
            "HIGH REL:APPLE,BEE,CAR",
            self.sec.string_normalise("HIGH///REL:APPLE REL:BEE\\REL:CAR"),
        )

        self.assertRaises(exceptions.SecurityParseException, self.sec.string_normalise, "INVALIDognregtro")

        # test rel
        self.assertEqual(
            "HIGH REL:APPLE,BEE,CAR",
            self.sec.string_normalise("high REL:APPLE,BEE,CAR"),
        )

    def test_security_consistency(self):
        def c(x):
            return self.sec.string_normalise(self.sec.string_normalise(x))

        self.assertEqual("HIGH REL:APPLE,BEE,CAR", c("high REL:APPLE,BEE,CAR"))
        self.assertEqual(
            "HIGH MOD1 MOD2 MOD3 REL:APPLE,BEE,CAR",
            c("high MEDIUM MOD3 MOD1 MOD2 REL:APPLE,BEE REL:CAR"),
        )

    def test_unique(self):
        self.assertEqual(self.sec.string_unique("LOW"), "41bc94cbd8eebea13ce0491b2ac11b88")
        self.assertEqual(self.sec.string_unique("MEDIUM"), "c87f3be66ffc3c0d4249f1c2cc5f3cce")
        self.assertEqual(self.sec.string_unique("HIGH"), "b89de3b4b81c4facfac906edf29aec8c")
        self.assertEqual(self.sec.string_unique("LOW TLP:CLEAR"), "b15bf68723013e78cbc15b8eb85b8fd8")
        self.assertEqual(self.sec.string_unique("MEDIUM REL:APPLE,BEE,CAR"), "741445afa8e5a5777f7675fc5bf0ae25")
        self.assertEqual(self.sec.string_unique("HIGH REL:APPLE,BEE,CAR"), "5c878e955bf9b8b462ecdd4d9311be42")

    def test_presets(self):
        self.assertEqual("LOW TLP:CLEAR", self.sec._s.presets[0])
        self.assertEqual("HIGH", self.sec._s.presets[1])
        self.assertEqual("MEDIUM REL:APPLE,BEE", self.sec._s.presets[2])
        self.assertEqual("MEDIUM REL:APPLE,BEE,CAR", self.sec._s.presets[3])

    def test_can_view(self):
        user_perm = ["REL:APPLE", "REL:BEE", "LOW", "MEDIUM"]
        obj_perm = "REL:APPLE REL:BEE MEDIUM"

        # User and object same permissions
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        # Vary inclusive groups
        obj_perm = "REL:APPLE,BEE,CAR MEDIUM"
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        obj_perm = "REL:APPLE MEDIUM"
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        obj_perm = "REL:CAR MEDIUM"

        self.assertRaises(exceptions.SecurityParseException, self.sec.check_access, *(user_perm, obj_perm))

        # Vary the exclusive groups
        obj_perm = "REL:APPLE REL:BEE REL:CAR HIGH"
        self.assertFalse(self.sec.check_access(user_perm, obj_perm))

        obj_perm = "REL:APPLE REL:BEE REL:CAR MEDIUM"
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        # Vary inclusive with exclusive group
        obj_perm = "REL:APPLE MEDIUM"
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        obj_perm = "REL:CAR MEDIUM"
        self.assertRaises(exceptions.SecurityParseException, self.sec.check_access, *(user_perm, obj_perm))

        # Check Enforceable marking
        obj_perm = "LOW TLP:CLEAR"
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        obj_perm = "LOW TLP:GREEN"
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        obj_perm = "LOW TLP:AMBER+STRICT"
        self.assertFalse(self.sec.check_access(user_perm, obj_perm))

        # Change user permissions to ensure the appropriate user can still access the marking.
        user_perm = ["LOW", "TLP:AMBER+STRICT"]
        self.assertTrue(self.sec.check_access(user_perm, obj_perm))

        user_perm = ["REL:APPLE", "REL:BEE", "LOW"]
        obj_perm = "REL:APPLE REL:BEE MEDIUM"

        # check does raise
        self.assertRaises(exceptions.SecurityAccessException, self.sec.check_access, *(user_perm, obj_perm, True))

    def test_get_allowed_presets(self):
        self.assertEqual(
            self.sec._get_allowed_presets(["REL:APPLE", "REL:BEE", "LOW", "MEDIUM", "HIGH"]),
            ["LOW TLP:CLEAR", "HIGH", "MEDIUM REL:APPLE,BEE", "MEDIUM REL:APPLE,BEE,CAR"],
        )

        self.assertEqual(
            self.sec._get_allowed_presets(["REL:APPLE", "REL:BEE", "LOW", "MEDIUM"]),
            ["LOW TLP:CLEAR", "MEDIUM REL:APPLE,BEE", "MEDIUM REL:APPLE,BEE,CAR"],
        )

        self.assertEqual(self.sec._get_allowed_presets(["REL:APPLE", "REL:BEE", "LOW"]), ["LOW TLP:CLEAR"])

        self.assertEqual(
            self.sec._get_allowed_presets(["REL:APPLE", "LOW", "MEDIUM"]),
            ["LOW TLP:CLEAR", "MEDIUM REL:APPLE,BEE", "MEDIUM REL:APPLE,BEE,CAR"],
        )
        self.assertEqual(
            self.sec._get_allowed_presets([]),
            [],
        )

    def test_classification_gte_lte_configured(self):
        """Verify that the classification gte and lte created the appropriate frozen sets."""
        self.assertEqual(self.sec._s.classifications_that_allow_tlps, frozenset(["LOW", "LOW: LY"]))
        self.assertEqual(
            self.sec._s.classifications_that_allow_releasability, frozenset(["TOP HIGH", "HIGH", "MEDIUM"])
        )
