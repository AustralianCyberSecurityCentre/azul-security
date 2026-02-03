"""Handle complexities around human readable and human created security strings."""

import re
from typing import NamedTuple

import cachetools

from .exceptions import SecurityParseException
from .settings import Settings


class SecurityT(NamedTuple):
    """Deconstructed security that can be hashed and cached."""

    exclusive: frozenset[str]
    inclusive: frozenset[str]
    markings: frozenset[str]


def to_securityt(exc, inc, oth):
    """Make a SecurityT with auto conversion to frozenset."""
    return SecurityT(frozenset(exc), frozenset(inc), frozenset(oth))


class SecurityFriendly:
    """Handle conversion to/from human readable security string."""

    def __init__(self, settings: Settings) -> dict:
        # cache conversion functions for speed
        self._cache_to_labels = cachetools.LRUCache(maxsize=1000)
        self._cache_from_labels = cachetools.LRUCache(maxsize=1000)
        self._cache_normalise = cachetools.LRUCache(maxsize=1000)

        self._settings = settings

        self._prefix = self._settings.labels.releasability.prefix
        self._prefix_re = re.compile(f"({self._prefix}[^\\s]*)")

        self._tk_classification = [f" {x} " for x in settings.labels.classification.get_all_names()]
        # must sort from longest to smallest to prevent substring matches
        # otherwise 'TOP HIGH' matches against 'HIGH', leaving invalid label 'TOP'
        self._tk_classification.sort(key=lambda x: len(x), reverse=True)
        self._tk_caveat = [f" {x} " for x in settings.labels.caveat.get_all_names()]
        self._tk_releasability = [f" {self._prefix}{x} " for x in settings.labels.releasability.get_all_names()]
        self._tk_tlp = [f" {x} " for x in settings.labels.tlp.get_all_names()]

        self._all_classification = settings.labels.classification.get_all_names()
        self._all_caveat = settings.labels.caveat.get_all_names()
        self._all_releasability = settings.labels.releasability.get_all_names()
        self._all_tlp = settings.labels.tlp.get_all_names()

    def _split_releasability(self, sec: str) -> tuple[str, set[str]]:
        """Extract all security group labels in the string and return remainder of string along with them.

        i.e. ' REL:APPLE REL:BEE,CAR TEST' -> ('   TEST', ['REL:APPLE','REL:BEE','REL:CAR'])
        """
        combined_groups = self._prefix_re.findall(sec)
        for x in combined_groups:
            sec = sec.replace(x, "", 1)
        ret = set()
        for group in combined_groups:
            ret.update(f"{self._prefix}{x}" for x in group.replace(self._prefix, "", 1).split(",") if x)
        return sec, ret

    def _merge_releasability(self, split: list[str]) -> str:
        """Turn a list of inclusives into a merged group.

        i.e. ['REL:APPLE','REL:BEE','REL:CAR'] -> 'REL:APPLE,BEE,CAR'
        """
        if not split:
            return ""
        return self._prefix + ",".join(sorted(x.replace(self._prefix, "") for x in split))

    def is_classification_allowed_rels(self, exclusive: set[str]) -> bool:
        """Check if the provided exclusive labels are allowed to have Releasability."""
        if len(exclusive) == 0:
            return True
        clsfs = exclusive.intersection(set(self._all_classification))

        return len(clsfs.intersection(self._settings.classifications_that_allow_releasability)) > 0

    def _minimise(self, items: frozenset[str], targets: list[str]) -> frozenset[str]:
        """If there are multiple items in the intersection of 'items' and 'targets', keep last mentioned in 'targets'.

        Items not in targets are returned as-is.

        i.e.
        items={a,b,c,d,e,apple} targets=[a,b,c,d,e] -> {e,apple}
        items={a,b,c,d,e,apple} targets=[e,d,c,b,a] -> {a,apple}
        """
        highlander = set(targets) & items
        highest = None
        if highlander:
            for mark in reversed(targets):
                if mark in highlander:
                    highest = mark
                    break
            highlander.remove(highest)
        items = items - highlander
        return frozenset(items)

    @cachetools.cachedmethod(lambda self: self._cache_normalise)
    def normalise(self, sec: SecurityT, ignore_origin: bool = False) -> SecurityT:
        """Normalise a parsed set of security groups."""
        exc, inc, oth = sec
        classification_allowed_rels = self.is_classification_allowed_rels(exc)

        # Drop all TLPs as at least one of the classification is only allows rels.
        if classification_allowed_rels:
            oth = set()

        has_releasability = len(inc) > 0
        origin = self._settings.labels.releasability.origin
        # Ignore origin when summarising a users access.
        if not ignore_origin:
            if inc and origin and origin not in inc:
                raise SecurityParseException(f"has releasability but does not have {origin=}")

        if not classification_allowed_rels and has_releasability:
            raise SecurityParseException(
                f"Classifications '{','.join(exc)}' have a releasability(s) {','.join(inc)}"
                + " but none of the classifications support releasability."
            )

        # check found groups are valid
        if not inc.issubset(self._all_releasability):
            bad = inc.difference(self._all_releasability)
            raise SecurityParseException(f"has invalid group in {bad=}")

        # check for bad entries
        if exc.difference(self._settings.exclusive):
            raise SecurityParseException(
                f"Unregistered security items 'exclusive': {exc.difference(self._settings.exclusive)}"
            )
        if inc.difference(self._settings.inclusive):
            raise SecurityParseException(
                f"Unregistered security items 'inclusive': {inc.difference(self._settings.inclusive)}"
            )
        if oth.difference(self._settings.markings):
            raise SecurityParseException(
                f"Unregistered security items 'markings': {oth.difference(self._settings.markings)}"
            )

        # there can only be one classification (but keep 'required')
        exc = self._minimise(exc, self._settings.labels.classification.get_all_names())

        # there can be only one info (tlp)
        oth = self._minimise(oth, self._settings.labels.tlp.get_all_names())

        return to_securityt(exc, inc, oth)

    @cachetools.cachedmethod(lambda self: self._cache_to_labels)
    def to_labels(self, raw: str) -> SecurityT:
        """Turn a security string into a list of security markings.

        NOTE - Also enforces security strings are valid.
        BIGLY SECRET//REL:APPLE,BEE AVOCADO -> ['BIGLY SECRET', 'REL:APPLE', 'REL:BEE', 'AVOCADO']
        """
        # uppercase to remove casing differences
        # replace slashes with spaces as they are sometimes used
        # cover start and end with spaces so we can detect tokens and avoid substring problem
        normalised = " " + raw.upper().replace("/", " ").replace("\\", " ") + " "
        exc = set()
        inc = set()
        oth = set()

        # identify classification
        for token in self._tk_classification:
            if token in normalised:
                normalised = normalised.replace(token, " ")
                exc.add(token.strip())
                continue

        if len(exc) <= 0:
            raise SecurityParseException(f"no classification in {raw}")

        # identify caveat's
        for token in self._tk_caveat:
            if token in normalised:
                normalised = normalised.replace(token, " ")
                exc.add(token.strip())

        # identify tlp
        for token in self._tk_tlp:
            if token in normalised:
                normalised = normalised.replace(token, " ")
                oth.add(token.strip())

        # identify releasability's
        normalised = normalised.strip()
        if normalised:
            normalised, inc = self._split_releasability(normalised)

        minimal = normalised.replace(" ", "")
        if minimal:
            raise SecurityParseException(f"invalid groups: {normalised.strip()}")

        try:
            ret = self.normalise(to_securityt(exc, inc, oth))
        except SecurityParseException as e:
            raise SecurityParseException(f"{str(e)}: {raw=}") from None

        return ret

    @cachetools.cachedmethod(lambda self: self._cache_from_labels)
    def from_labels(self, sec: SecurityT) -> str:
        """Turn a set of security markings into a security string.

        NOTE - Also enforces security strings are valid.
        ['BIGLY SECRET', 'REL:APPLE', 'REL:BEE', 'AVOCADO'] -> BIGLY SECRET REL:APPLE,BEE AVOCADO
        """
        exc, inc, oth = sec
        ret = []
        # classification from exclusives
        for item in self._all_classification:
            if item in exc:
                ret.append(item)

        # caveat from exclusives
        for item in self._all_caveat:
            if item in exc:
                ret.append(item)

        # releasability from inclusives
        diff = inc.difference(self._all_releasability)
        if diff:
            raise SecurityParseException(f"security has invalid groups: {diff}")
        groups = self._merge_releasability(list(inc))
        has_releasability = False
        if groups:
            ret.append(groups)
            has_releasability = True

        is_allowed_rels = self.is_classification_allowed_rels(exc)
        if has_releasability and not is_allowed_rels:
            raise SecurityParseException(
                f"Classifications '{','.join(exc)}' have a releasability(s) {','.join(inc)}"
                + " but none of the classifications support releasability."
            )

        # tlp from markings
        if not is_allowed_rels:
            for item in self._all_tlp:
                if item in oth:
                    ret.append(item)
        else:
            oth = set()

        # check that exclusive and markings were fully consumed
        for item in exc.union(oth):
            if item not in ret:
                raise SecurityParseException(f"security has invalid label {item}")

        return " ".join(ret)
