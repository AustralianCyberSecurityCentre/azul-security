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
                    {"name": "MOD1"},
                    {"name": "MOD2"},
                    {"name": "MOD3"},
                    {"name": "HANOVERLAP"},
                    {"name": "OVER"},
                    {"name": "RESTRICTED1", "min_priority": "10", "max_priority": "10"},
                    {"name": "RESTRICTED2", "min_priority": "30", "max_priority": "50"},
                ],
            },
            "releasability": {
                "title": "Groups",
                "origin": "REL:APPLE",
                "origin_alt_name": "APPLEO",
                "prefix": "REL:",
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
                    {"name": "TLP:AMBER+STRICT", "enforce_security": "true"},
                ],
            },
        }
    )
