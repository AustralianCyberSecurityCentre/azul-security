import unittest

from azul_security import friendly, settings
from azul_bedrock import exceptions_security
from azul_security.friendly import SecurityT, to_securityt

from . import support


class TestInvalids(unittest.TestCase):
    def setUp(self) -> None:
        support.resetEnv()
        st = settings.Settings()
        self.fr = friendly.SecurityFriendly(st)
        return super().setUp()

    def test_minimize(self):
        items = self.fr._minimise(frozenset({"HIGH", "MEDIUM", "MOD1"}), ["LOW", "MEDIUM", "HIGH"])
        self.assertEqual(frozenset({"HIGH", "MOD1"}), items)
        items = self.fr._minimise(frozenset({"TLP:CLEAR", "TLP:AMBER"}), ["LOW", "MEDIUM", "HIGH"])
        self.assertEqual(frozenset({"TLP:CLEAR", "TLP:AMBER"}), items)

        items = self.fr._minimise(frozenset({"TLP:CLEAR", "TLP:AMBER"}), ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"])
        self.assertEqual(frozenset({"TLP:AMBER"}), items)

    def test_normalise(self):
        item = to_securityt({"HIGH", "MEDIUM", "LOW"}, {"REL:APPLE", "REL:BEE", "REL:CAR"}, {"TLP:CLEAR", "TLP:AMBER"})
        self.assertEqual(self.fr.normalise(item), to_securityt({"HIGH"}, {"REL:APPLE", "REL:BEE", "REL:CAR"}, {}))

        item = to_securityt({"LOW"}, {"REL:APPLE", "REL:BEE", "REL:CAR"}, {"TLP:CLEAR", "TLP:AMBER"})
        self.assertRaises(exceptions_security.SecurityParseException, self.fr.normalise, item)

        item = to_securityt({"LOW"}, {}, {"TLP:CLEAR", "TLP:AMBER"})
        self.assertEqual(self.fr.normalise(item), to_securityt({"LOW"}, {}, {"TLP:AMBER"}))

    def test_split_releasability(self):
        self.assertEqual(("      ", set()), self.fr._split_releasability("      "))
        self.assertEqual(("", {"REL:APPLE", "REL:BEE", "REL:CAR"}), self.fr._split_releasability("REL:APPLE,BEE,CAR"))
        self.assertEqual(
            (" ", {"REL:APPLE", "REL:BEE", "REL:CAR"}), self.fr._split_releasability("REL:APPLE,BEE REL:CAR")
        )
        self.assertEqual(
            ("  ", {"REL:APPLE", "REL:BEE", "REL:CAR"}), self.fr._split_releasability("REL:APPLE REL:BEE REL:CAR")
        )
        self.assertEqual(
            ("  ", {"REL:APPLE", "REL:BEE", "REL:CAR"}), self.fr._split_releasability("REL:CAR REL:BEE REL:APPLE")
        )
        self.assertEqual(
            (" ", {"REL:APPLE", "REL:BEE", "REL:CAR"}), self.fr._split_releasability("REL:CAR,BEE REL:APPLE")
        )
        self.assertEqual(("", {"REL:APPLE", "REL:BEE", "REL:CAR"}), self.fr._split_releasability("REL:CAR,BEE,APPLE"))
        self.assertEqual(("", {"REL:SEED"}), self.fr._split_releasability("REL:SEED"))
        self.assertEqual(("APPLE  CORE", {"REL:SEED"}), self.fr._split_releasability("APPLE REL:SEED CORE"))
        self.assertEqual(
            ("APPLE   CORE", {"REL:SEED", "REL:RED"}), self.fr._split_releasability("APPLE REL:SEED REL:RED CORE")
        )
        self.assertEqual(("APPLE ", {"REL:SEED"}), self.fr._split_releasability("APPLE REL:SEED"))
        self.assertEqual((" CORE", {"REL:SEED"}), self.fr._split_releasability("REL:SEED CORE"))

    def test_to_labels(self):
        self.assertEqual(({"HIGH"}, set(), set()), self.fr.to_labels("HIGH"))
        self.assertEqual(({"HIGH", "MOD1", "MOD2"}, set(), set()), self.fr.to_labels("HIGH MOD1 MOD2"))
        self.assertEqual(({"HIGH", "MOD1", "MOD2", "MOD3"}, set(), set()), self.fr.to_labels("HIGH MOD1 MOD2 MOD3"))
        self.assertEqual(
            ({"LOW: LY", "MOD1", "MOD2", "MOD3"}, set(), set()), self.fr.to_labels("LOW: LY MOD1 MOD2 MOD3")
        )

        self.assertEqual(({"LOW", "HANOVERLAP"}, set(), set()), self.fr.to_labels("LOW HANOVERLAP"))
        self.assertEqual(({"LOW", "OVER"}, set(), set()), self.fr.to_labels("LOW OVER"))

        self.assertEqual(
            ({"MEDIUM"}, {"REL:APPLE", "REL:BEE", "REL:CAR"}, set()),
            self.fr.to_labels("MEDIUM REL:APPLE REL:BEE REL:CAR"),
        )
        self.assertEqual(
            ({"MEDIUM"}, {"REL:APPLE", "REL:BEE", "REL:CAR"}, set()), self.fr.to_labels("MEDIUM REL:APPLE,BEE,CAR")
        )
        self.assertEqual(({"MEDIUM"}, {"REL:APPLE", "REL:BEE"}, set()), self.fr.to_labels("MEDIUM REL:APPLE,BEE"))
        self.assertEqual(({"MEDIUM"}, {"REL:APPLE"}, set()), self.fr.to_labels("MEDIUM REL:APPLE"))

        self.assertEqual(
            ({"HIGH", "MOD2"}, {"REL:APPLE", "REL:BEE"}, set()), self.fr.to_labels("HIGH MOD2 REL:APPLE,BEE")
        )

        self.assertEqual(
            ({"HIGH", "MOD2"}, {"REL:APPLE", "REL:BEE"}, set()), self.fr.to_labels("HIGH\\\\\\MOD2\\REL:APPLE,BEE")
        )
        self.assertEqual(
            ({"HIGH", "MOD2"}, {"REL:APPLE", "REL:BEE"}, set()), self.fr.to_labels("HIGH\\\\\\MOD2 REL:APPLE,BEE")
        )
        self.assertEqual(
            ({"HIGH", "MOD2"}, {"REL:APPLE", "REL:BEE"}, set()), self.fr.to_labels("HIGH/MOD2////REL:APPLE,BEE")
        )
        self.assertEqual(
            ({"HIGH", "MOD2"}, {"REL:APPLE", "REL:BEE"}, set()), self.fr.to_labels("HIGH/MOD2 REL:APPLE,BEE")
        )
        self.assertEqual(
            ({"TOP HIGH", "MOD2"}, {"REL:APPLE", "REL:BEE"}, set()), self.fr.to_labels("TOP HIGH/MOD2 REL:APPLE,BEE")
        )

        self.assertRaises(
            exceptions_security.SecurityParseException, self.fr.to_labels, "HIGH/MOD2 REL:APPLE,BEE turbo"
        )
        self.assertRaises(exceptions_security.SecurityParseException, self.fr.to_labels, "PENGUIN")
        self.assertRaises(exceptions_security.SecurityParseException, self.fr.to_labels, "REL:CARL")

    def test_from_labels(self):
        self.assertEqual("HIGH", self.fr.from_labels(to_securityt({"HIGH"}, {}, {})))
        self.assertEqual("HIGH MOD1 MOD2", self.fr.from_labels(to_securityt({"HIGH", "MOD1", "MOD2"}, {}, {})))
        self.assertEqual(
            "HIGH MOD1 MOD2 MOD3",
            self.fr.from_labels(to_securityt({"HIGH", "MOD1", "MOD2", "MOD3"}, {}, {})),
        )

        self.assertEqual("HANOVERLAP", self.fr.from_labels(to_securityt({"HANOVERLAP"}, {}, {})))
        self.assertEqual("OVER", self.fr.from_labels(to_securityt({"OVER"}, {}, {})))

        self.assertEqual(
            "REL:APPLE,BEE,CAR",
            self.fr.from_labels(to_securityt({}, {"REL:APPLE", "REL:BEE", "REL:CAR"}, {})),
        )
        self.assertEqual("REL:APPLE,BEE", self.fr.from_labels(to_securityt({}, {"REL:APPLE", "REL:BEE"}, {})))
        self.assertEqual("REL:APPLE", self.fr.from_labels(to_securityt({}, {"REL:APPLE"}, {})))

        self.assertEqual(
            "HIGH MOD2 REL:APPLE,BEE",
            self.fr.from_labels(to_securityt({"HIGH", "MOD2"}, {"REL:APPLE", "REL:BEE"}, {})),
        )
        self.assertEqual(
            "HIGH MOD2 REL:APPLE,BEE",
            self.fr.from_labels(to_securityt({"MOD2", "HIGH"}, {"REL:BEE", "REL:APPLE"}, {})),
        )
        self.assertEqual(
            "TOP HIGH MOD2 REL:APPLE,BEE",
            self.fr.from_labels(to_securityt({"MOD2", "TOP HIGH"}, {"REL:BEE", "REL:APPLE"}, {})),
        )

        self.assertRaises(
            exceptions_security.SecurityParseException, self.fr.from_labels, to_securityt({"PENGUIN"}, {}, {})
        )
        self.assertRaises(
            exceptions_security.SecurityParseException, self.fr.from_labels, to_securityt({}, {"REL:CARL"}, {})
        )
