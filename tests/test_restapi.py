import json
import os
import unittest

from azul_bedrock.models_auth import UserInfo
from fastapi import Depends, FastAPI, Request
from starlette.testclient import TestClient

from . import support


def set_token_with_roles(token_roles: list[str] = ["validated"]):
    def set_token(request: Request) -> UserInfo:
        """Ignore input and return static token."""
        request.state.user_info = UserInfo(
            username="llama",
            org="test",
            email="",
            roles=token_roles,
            unique_id="llama-subject-id",
        )
        return request.state.user_info

    return set_token


def get_app(token_roles: list[str] = ["validated"]):
    """Get a client for testing metastore routes."""
    from azul_security import restapi

    app = FastAPI(
        title="Azul",
        version="test",
        openapi_url=f"/api/openapi.json",
        docs_url=None,
        redoc_url=None,
        dependencies=[Depends(set_token_with_roles(token_roles))],
    )
    app.include_router(restapi.router)
    client = TestClient(app)
    return client


class TestRestapi(unittest.TestCase):
    def assertEqualP(self, actual, expected):
        """Same as assertEqual, but print complete actual output when it fails.

        We deal with a lot of json dictionaries, so this makes it easier to get the
        boilerplate for test cases.
        """
        try:
            self.assertEqual(actual, expected)
        except AssertionError:
            print("Comparison failed, you can use the below output as basis of a test case:")
            print(actual)
            print("")
            raise

    @classmethod
    def alter_environment(cls):
        support.resetEnv()
        os.environ["security_minimum_required_access"] = json.dumps(["LOW", "MEDIUM", "MOD1", "REL:APPLE"])

    def setUp(self):
        self.alter_environment()

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.client = get_app()
        # print the whole difference between datastructures in a failed test
        cls.maxDiff = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()

    def test_post_security_build(self):
        response = self.client.post("/v1/security/normalise", json={"security": "loW MoD1"})
        print(response.content)
        self.assertEqual(200, response.status_code)

        parsed = response.json()
        self.assertEqualP(parsed, "LOW MOD1")

        response = self.client.post("/v1/security/normalise", json={"security": "LOW TLP:CLEAR"})
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "LOW TLP:CLEAR")

        response = self.client.post("/v1/security/normalise", json={"security": "LOW TLP:AMBER+STRICT"})
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "LOW TLP:AMBER+STRICT")

        response = self.client.post("/v1/security/normalise", json={"security": "LOW MOD1"})
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "LOW MOD1")

        response = self.client.post("/v1/security/normalise", json={"security": "LOW MEDIUM MOD1"})
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "MEDIUM MOD1")

        response = self.client.post("/v1/security/normalise", json={"security": "MEDIUM MOD2 REL:APPLE REL:BEE MOD1"})
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "MEDIUM MOD1 MOD2 REL:APPLE,BEE")

        response = self.client.post("/v1/security/normalise", json={"security": " medium\\HIGH//low  "})
        print(response.content)
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "HIGH")

        response = self.client.post("/v1/security/normalise", json={"security": "LOW MOD1 MEDIUM"})
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "MEDIUM MOD1")

        # various invalid input
        response = self.client.post("/v1/security/normalise", json={"security": "LOW REL:APPLE"})
        self.assertEqual(400, response.status_code)
        response = self.client.post("/v1/security/normalise", json={"security": ""})
        self.assertEqual(400, response.status_code)
        response = self.client.post("/v1/security/normalise", json={"security": "ORANGE SODA"})
        self.assertEqual(400, response.status_code)

    def test_post_security_max(self):
        response = self.client.post("/v1/security/max", json=["low MOD1", "MEdiuM"])
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "MEDIUM MOD1")

        response = self.client.post("/v1/security/max", json=["LOW MOD1", "MEDIUM"])
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        self.assertEqualP(parsed, "MEDIUM MOD1")

        response = self.client.post("/v1/security/max", json=["HIGH"])
        self.assertEqual(200, response.status_code)

        # invalid security string
        response = self.client.post("/v1/security/max", json=["ORANGE", "SODA"])
        self.assertEqual(400, response.status_code)
        # invalid security combination
        response = self.client.post("/v1/security/max", json=["LOW REL:APPLE", "LOW REL:BEE"])
        self.assertEqual(400, response.status_code)
        # empty input
        response = self.client.post("/v1/security/max", json=[])
        self.assertEqual(400, response.status_code)
        response = self.client.post("/v1/security/max", json=[""])
        self.assertEqual(400, response.status_code)
        response = self.client.post("/v1/security/max", json=["", ""])
        self.assertEqual(400, response.status_code)

    def test_get_security(self):
        response = self.client.get("/v0/security")
        self.assertEqual(200, response.status_code)
        parsed = response.json()
        print(f"actual:\n{parsed}\nend actual")
        self.assertEqualP(
            parsed,
            {
                "labels": {
                    "classification": {
                        "options": [
                            {"name": "LOW", "priority": 10},
                            {"name": "LOW: LY", "priority": 20},
                            {"name": "MEDIUM", "priority": 30},
                            {"name": "HIGH", "priority": 40},
                            {"name": "TOP HIGH", "priority": 50},
                        ],
                        "title": "Classifications",
                    },
                    "caveat": {
                        "options": [
                            {"name": "MOD1", "priority": 5},
                            {"name": "MOD2", "priority": 10},
                            {"name": "MOD3", "priority": 15},
                            {"name": "HANOVERLAP", "priority": 20},
                            {"name": "OVER", "priority": 25},
                        ],
                        "title": "Required",
                    },
                    "releasability": {
                        "options": [
                            {"name": "REL:APPLE", "priority": 0},
                            {"name": "REL:BEE", "priority": 10},
                            {"name": "REL:CAR", "priority": 20},
                        ],
                        "title": "Groups",
                        "origin": "REL:APPLE",
                        "origin_alt_name": "APPLEO",
                        "prefix": "REL:",
                    },
                    "tlp": {
                        "options": [
                            {"name": "TLP:CLEAR", "priority": 10, "enforce_security": False},
                            {"name": "TLP:GREEN", "priority": 20, "enforce_security": False},
                            {"name": "TLP:AMBER", "priority": 30, "enforce_security": False},
                            {"name": "TLP:AMBER+STRICT", "priority": 40, "enforce_security": True},
                        ],
                        "title": "TLP",
                    },
                },
                "admin_roles": ["admin"],
                "default": "LOW",
                "presets": [
                    "LOW TLP:CLEAR",
                    "HIGH",
                    "MEDIUM REL:APPLE,BEE",
                    "MEDIUM REL:APPLE,BEE,CAR",
                    "TOP HIGH REL:APPLE,BEE,CAR",
                ],
                "allow_releasability_priority_gte": 30,
                "minimum_required_access": ["LOW", "MEDIUM", "MOD1", "REL:APPLE"],
            },
        )

    def test_is_user_admin(self):
        # Token with no admin roles
        resp = self.client.get("v0/security/is_admin")
        self.assertFalse(resp.json())

        # Token with no roles
        no_role_user_client = get_app([])
        resp = no_role_user_client.get("v0/security/is_admin")
        self.assertFalse(resp.json())

        # Token with admin role
        admin_role_user_client = get_app(["validated", "admin"])
        resp = admin_role_user_client.get("v0/security/is_admin")
        self.assertTrue(resp.json())
