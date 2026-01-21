import json
import os


def resetEnv():
    os.environ["security_minimum_required_access"] = json.dumps([])
    os.environ["security_default"] = "LOW"
    os.environ["security_presets"] = json.dumps(
        [
            "low TLP:CLEAR",
            "high",
            "REL:APPLE REL:BEE medium",
            "REL:APPLE REL:BEE REL:CAR medium",
            "TOP HIGH REL:APPLE REL:BEE REL:CAR",
        ]
    )
    os.environ["security_allow_releasability_priority_gte"] = "30"
    os.environ["security_labels"] = json.dumps(
        {
            "classification": {
                "title": "Classifications",
                "options": [
                    {"name": "LOW", "priority": "10"},
                    {"name": "LOW: LY", "priority": "20"},
                    {"name": "MEDIUM", "priority": "30"},
                    {"name": "HIGH", "priority": "40"},
                    {"name": "TOP HIGH", "priority": "50"},
                ],
            },
            "caveat": {
                "title": "Required",
                "options": [
                    {"name": "MOD1", "priority": "5"},
                    {"name": "MOD2", "priority": "10"},
                    {"name": "MOD3", "priority": "15"},
                    {"name": "HANOVERLAP", "priority": "20"},
                    {"name": "OVER", "priority": "25"},
                ],
            },
            "releasability": {
                "title": "Groups",
                "origin": "REL:APPLE",
                "origin_alt_name": "APPLEO",
                "prefix": "REL:",
                "options": [
                    {"name": "REL:APPLE", "priority": "0"},
                    {"name": "REL:BEE", "priority": "10"},
                    {"name": "REL:CAR", "priority": "20"},
                ],
            },
            "tlp": {
                "title": "TLP",
                "options": [
                    {"name": "TLP:CLEAR", "priority": "10"},
                    {"name": "TLP:GREEN", "priority": "20"},
                    {"name": "TLP:AMBER", "priority": "30"},
                    {"name": "TLP:AMBER+STRICT", "priority": "40", "enforce_security": "true"},
                ],
            },
        }
    )
