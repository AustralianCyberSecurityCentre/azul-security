"""Implementation of basic security procedures for Azul.

Language confusion:
Security Label - an atomic security item that represents a single access/permission.
Security Labels - a list of security labels, order does not matter.
Security Group - a collection of related security labels that have common properties for UI, etc.
Security String - the rendered string of security labels that is human readable.
Security Dict - security labels organised to split into 3 categories of 'inclusive', 'exclusive' and 'markings'.
"""

import hashlib
import re
from typing import Iterable

import cachetools
from azul_bedrock.models_restapi.basic import UserSecurity

from . import friendly, settings
from .exceptions import (
    SecurityAccessException,
    SecurityConfigException,
    SecurityParseException,
)
from .friendly import SecurityT, to_securityt

EXCLUSIVE = "exclusive"
INCLUSIVE = "inclusive"
MARKINGS = "markings"


def md5(text: str):
    """Return string md5 representing incoming text."""
    return hashlib.md5(text.encode()).hexdigest()  # noqa: S303 # nosec B303, B324


class Security:
    """Process and transform security labels."""

    def __init__(self):
        """Initialise."""
        self._s = s = settings.Settings()
        self._cache_enforceable_markings = cachetools.LRUCache(maxsize=1000)

        # create friendly string processor by combining all group friendlies together
        self._friendly = friendly.SecurityFriendly(self._s)

        # normalise presets
        for i, x in enumerate(s.presets):
            s.presets[i] = self.string_normalise(x)

        # verify minimum required access makes sense
        self.minimum_required_access = frozenset(s.minimum_required_access)
        for x in self.minimum_required_access:
            if x not in s.exclusive and x not in s.inclusive:
                raise SecurityConfigException(
                    f"minimum required access level ({x}) not found in inclusive or exclusive sets"
                )

        # normalise default security
        if not s.default:
            raise SecurityConfigException("must set security_default to valid security option")
        s.default = self.string_normalise(s.default)

    def get_labels_allowed(self) -> frozenset[str]:
        """Return all security labels."""
        return self._s.allowed

    def get_labels_inclusive(self) -> frozenset[str]:
        """Return all inclusive security labels."""
        return self._s.inclusive

    def get_labels_exclusive(self) -> frozenset[str]:
        """Return all exclusive security labels."""
        return self._s.exclusive

    def get_labels_markings(self) -> frozenset[str]:
        """Return all markings security labels."""
        return self._s.markings

    def get_default_security(self) -> str:
        """Return the default security string."""
        return self._s.default

    def _rank(self, sec: SecurityT) -> Iterable[int]:
        """Figure out a ranking for this security list.

        Prioritises classifications, required, groups and then info.

        items at the top of a config list are considered higher ranked.
        """

        def do_rank(check: frozenset[str], expected: list[str]):
            sum = 0
            for i, item in enumerate(expected):
                if item in check:
                    # use each bit to flag presence yes/no for all expected items
                    # this allows for multiple items to be present
                    sum += 1 << i
            return sum

        yield do_rank(sec.exclusive, self._s.labels.classification.get_all_names())
        yield do_rank(sec.exclusive, self._s.labels.caveat.get_all_names())
        yield do_rank(sec.inclusive, self._s.labels.releasability.get_all_names())
        yield do_rank(sec.markings, self._s.labels.tlp.get_all_names())

    def string_rank(self, secs: list[str]) -> list[str]:
        """Sort securities according to a ranking system, to bring better ones to the top."""
        # parse and deduplicate
        parsed = set(self._friendly.to_labels(x) for x in secs)
        # sort as list
        ranked = sorted(parsed, key=lambda x: list(self._rank(x)))
        # render
        return [self._friendly.from_labels(x) for x in ranked]

    def string_combine(self, secs: list[str]) -> str:
        """Combine a list of security objects into a single object."""
        parsed = set(self._friendly.to_labels(x) for x in secs)
        # get all unique exclusives from security rows
        exc = set(y for x in parsed for y in x.exclusive)
        # get all unique markings from security rows
        oth = set(y for x in parsed for y in x.markings)

        # keep inclusives based on set overlap
        # i.e. [(),()] => ()
        # i.e. [(A1,A2,A3), (A1), ()] => (A1)
        # i.e. [(A1,A2,A3)] => (A1,A2,A3)
        # i.e. [(A1,A2,A3), (A1,A2)] => (A1,A2)
        # i.e. [(A1), (A2)] => PANIC (no access possible)
        # get inclusives from each security row
        # remove empty sets since they don't impact access
        inc_groups = [set(y for y in x.inclusive) for x in parsed if x.inclusive]
        # do the groups of inclusives have a common set of labels within them?
        inc = set.intersection(*inc_groups) if inc_groups else set()
        if inc_groups and not inc:
            # Occurs when two sets for the group have no common items - i.e. nobody can view the document
            raise SecurityParseException(f"no common inclusive set: {inc}")

        normalised = self._friendly.normalise(to_securityt(exc, inc, oth))
        return self._friendly.from_labels(normalised)

    def string_normalise(self, sec: str) -> str:
        """Normalise a security string."""
        return self._friendly.from_labels(self._friendly.to_labels(sec))

    def string_parse(self, sec: str) -> SecurityT:
        """Return a parsed security string for analysis."""
        return self._friendly.to_labels(sec)

    def string_unparse(self, sec: SecurityT) -> str:
        """Unparses a previously parsed security string."""
        return self._friendly.from_labels(sec)

    def string_unique(self, sec: str) -> str:
        """Calculate a unique hash for security."""
        parsed = self._friendly.to_labels(sec)
        # used for uniqueness of the returned list of accesses
        # using md5 here is fine, since the allowed tags are from a set list, rather than user input
        return md5(" ".join(sorted(parsed.exclusive) + sorted(parsed.inclusive) + sorted(parsed.markings)))

    def check_access(
        self, permitted_labels: Iterable[str], protected_object_permission: str, raise_error: bool = False
    ) -> bool:
        """Verify if the viewer is allowed to view an object with the provided permissions.

        NOTE: True security is enforced by the opensearch database DLS, not this function.

        Args:
            permitted_labels: Security labels for the of the user or entity wanting to view an object.
            protected_object_permission: Security string of the object the user wants to view.

        Returns:
            bool indicating if user can view object
        """
        sec = self._friendly.to_labels(protected_object_permission)
        permitted = set(permitted_labels)
        # check if user has all exclusive labels
        if not sec.exclusive.issubset(permitted):
            if raise_error:
                raise SecurityAccessException(
                    f"User cannot access all {','.join(sec.exclusive.difference(permitted))}"
                )
            return False
        # check if user has at least one inclusive labels
        if sec.inclusive and not sec.inclusive.intersection(permitted):
            if raise_error:
                raise SecurityAccessException(f"User cannot access any {','.join(sec.inclusive)}")
            return False
        # Check if user has at least one TLP marking
        objects_enforceable_markings = set(self.get_enforceable_markings(sec.markings))
        if objects_enforceable_markings and not objects_enforceable_markings.intersection(permitted):
            if raise_error:
                raise SecurityAccessException(f"User cannot access any {','.join(sec.inclusive)}")
            return False
        return True

    def _get_allowed_presets(self, permitted_labels: Iterable[str]) -> list[str]:
        """Return presets that a user is able to access."""
        ret = []
        for preset in self._s.presets:
            if self.check_access(permitted_labels, preset):
                ret.append(preset)
        return ret

    def _access_calc_unique(self, labels: Iterable[str]) -> str:
        """Calculate a unique 'access' hash for a given list of valid labels for a user."""
        return md5(".".join(sorted(labels)))

    def safe_to_unsafe(self, labels: list[str], drop_mismatch: bool = False) -> list[str]:
        """Convert 'safe' labels into 'unsafe' labels, drop unmatched.

        e.g.
        s-official -> OFFICIAL
        s-tlp-amber -> TLP:AMBER
        """
        ret = [self._s.safe_to_unsafe.get(x) for x in labels]
        if not drop_mismatch and None in ret:
            raise SecurityParseException(f"unmatched safe->unsafe in {labels}")
        return [x for x in ret if x is not None]

    def unsafe_to_safe(self, labels: list[str], drop_mismatch: bool = False) -> list[str]:
        """Convert 'unsafe' labels into 'safe' labels.

        e.g.
        OFFICIAL -> s-official
        TLP:AMBER -> s-tlp-amber
        """
        ret = [self._s.unsafe_to_safe.get(x) for x in labels]
        if not drop_mismatch and None in ret:
            raise SecurityParseException(f"unmatched unsafe->safe in {labels}")
        return [x for x in ret if x is not None]

    def summarise_user_access(
        self, labels: list[str], denylist: list[str] = None, includelist: list[str] = None
    ) -> UserSecurity:
        """Summarise the users access into a simple data structure."""
        if not denylist:
            denylist = []
        if not includelist:
            includelist = []
        ret = UserSecurity()
        if self._s.labels.releasability.origin not in labels:
            labels.append(self._s.labels.releasability.origin)
        else:
            labels += [item for item in self._s.labels.releasability.get_all_names() if item not in labels]
        # check access meets minimum requirements
        # must verify BEFORE applying the denylist as this is only intended to detect misconfiguration
        missing = self.minimum_required_access.difference(labels)
        if missing:
            raise SecurityAccessException(
                f"user does not meet minimum_required_access, missing security labels {list(missing)}"
            )
        # remove security labels in the denylist
        labels = set(labels).difference(set(x.upper() for x in denylist))
        exclusive_labels = sorted(self._s.exclusive.intersection(labels))
        # Deny all rel's if the deny list has removed all high classification items.
        if not self._friendly.is_classification_allowed_rels(set(exclusive_labels)):
            labels = set(labels).difference(set(rel.upper() for rel in self._s.labels.releasability.get_all_names()))

        ret.labels = sorted(labels)

        # bucket the security labels
        ret.labels_exclusive = exclusive_labels
        ret.labels_inclusive = sorted(self._s.inclusive.intersection(labels))
        ret.labels_markings = sorted(self._s.markings.intersection(labels))
        ret.unique = self._access_calc_unique(labels)
        ret.max_access = self._friendly.from_labels(
            self._friendly.normalise(
                to_securityt(ret.labels_exclusive, ret.labels_inclusive, ret.labels_markings), ignore_origin=True
            )
        )

        ret.allowed_presets = self._get_allowed_presets(labels)
       
        if (
            len(ret.labels_inclusive) == 1
            and ret.labels_inclusive[0] == self._s.labels.releasability.origin
            and self._s.labels.releasability.origin_alt_name
        ):
            updated_max_access = re.sub(
                r"REL:[^ ]*", f"REL:{self._s.labels.releasability.origin_alt_name}", ret.max_access
            )
            # Update ret.max_access
            ret.max_access = updated_max_access
        return ret

    @cachetools.cachedmethod(lambda self: self._cache_enforceable_markings, key=lambda _self, m: "-".join(sorted(m)))
    def get_enforceable_markings(self, markings: list[str]) -> list[str]:
        """Return the markings provided if they are an enforceable marking.

        If unsafe markings are provided they are returned in an unsafe format.
        If safe markings are provided they are returned in a safe format.
        """
        # Assume unsafe markings were provided.
        default_result = self._s.enforceable_markings.intersection(markings)
        if len(default_result) > 0:
            return list(default_result)

        # If safe markings were provided convert them to unsafe markings and check if they are enforceable.
        unsafe_markings = self.safe_to_unsafe(markings, drop_mismatch=True)
        if len(unsafe_markings) == 0:
            return []
        unsafe_result = self._s.enforceable_markings.intersection(unsafe_markings)
        if len(unsafe_result) == 0:
            return []
        return self.unsafe_to_safe(list(unsafe_result), drop_mismatch=True)
