"""Settings for security module."""

import re
from functools import cached_property

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import SecurityConfigException


def security_to_role(label: str) -> str:
    """Replace special characters and simplify security labels.

    Intended for use with systems that are picky about valid characters.
    """
    # lowercase as that appears to be convention in opensearch role names
    label = label.lower()
    # prefix allows for keeping security label roles separate from system roles
    # also ensures at least two characters in role name
    label = "s-" + label
    # valid characters
    return re.sub(r"[^a-zA-Z0-9\-\_]", "-", label)


class LabelOption(BaseModel):
    """A Security Label."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = self.name.upper()
        if self.name.startswith(" ") or self.name.endswith(" "):
            raise SecurityConfigException(f"security labels must not start or end with a space: '{self.name}'")

    name: str
    # Priority of this security label (higher is more important)
    # Priority is used to limit when TLP's and Releasability can be applied to a classification.
    priority: int = 0


class LabelOptionTlp(LabelOption):
    """A TLP Security Label."""

    # cause a TLP label option to enforce security in opensearch, this is only useful for TLPs although could be
    # set for classifications and cavets and releasability.
    enforce_security: bool = False


class LabelOptions(BaseModel):
    """Information about a particular security group definition."""

    # all security labels in this group
    options: list[LabelOption] = []
    title: str = ""

    def get_all_names(self):
        """Return the list of security labels as strings in priority order (first is highest priority)."""
        return [x.name for x in self.options]


class LabelOptionsReleasability(LabelOptions):
    """Information about a particular security group definition specific to releasability."""

    # if any choices are set, origin must be present
    # (default releasability added to all events where releasibility is allowed.)
    origin: str = ""
    # alternate name for default releasability
    origin_alt_name = ""
    # prefix that is present in all entries for 'releasability'
    prefix: str = "REL:"


class LabelOptionsTlp(LabelOptions):
    """Label options for Tlps."""

    options: list[LabelOptionTlp] = []


class SecurityLabels(BaseModel):
    """Collection of all security labels in the system."""

    # Events must have one of these markings and user must have it to access.
    # Order is from least restrictive to most restrictive.
    # If multiple are preset only the most restrictive is kept.
    # These items are rendered first.
    classification: LabelOptions = LabelOptions()
    # If events have multiple of these markings, user must have all of them to access.
    # These items are rendered second.
    caveat: LabelOptions = LabelOptions()
    # If events have multiple of these markings, user must have at least one of them to access.
    # REL:APPLE and REL:BANANA automatically combine into a 'REL:APPLE,BANANA' label.
    # These items are rendered third.
    releasability: LabelOptionsReleasability = LabelOptionsReleasability()
    # These markings are descriptive only and do not control access.
    # i.e. TLP
    # Order is from least restrictive to most restrictive.
    # If multiple are preset only the most restrictive is kept.
    # These items are rendered last.
    tlp: LabelOptionsTlp = LabelOptionsTlp()


class Settings(BaseSettings):
    """Security config parser using pydantic."""

    labels: SecurityLabels
    # A list of roles from the JWT, if a user has ANY of these they are considered an administrator.
    admin_roles: list[str] = ["admin"]

    # default security string for when insufficient security information has been supplied
    default: str = ""
    # security strings that are commonly used
    presets: list[str] = []

    # Releasability is allowed for all classifications greater than or equal to this priority.
    # TLPs are allowed when less than this priority.
    # A classification cannot have both TLP and Releasability.
    # Note - this value does not have a default because if it's set to it's default the
    # behavior doesn't lead to this not being set as an obvious conclusion.
    allow_releasability_priority_gte: int

    # List of security labels that represent minimum required access to the system.
    # External systems must ensure every user has this level of access.
    # Labels should not be removed from this list once set, as systems
    # may optimised data storage around the list of minimum accesses.
    # e.g. Azul Metastore stores events without DLS if security of event is subset of this list.
    # Must list all classifications, not only the highest ranking. i.e. ['LOW', 'LOW: LY']
    minimum_required_access: list[str] = []

    model_config = SettingsConfigDict(env_prefix="security_")

    def __init__(self):
        super().__init__()
        # possible labels for the exclusive security field
        self._exclusive = frozenset(self.labels.classification.get_all_names() + self.labels.caveat.get_all_names())
        # possible labels for the inclusive security field
        self._inclusive = frozenset(self.labels.releasability.get_all_names())
        for x in self.labels.releasability.get_all_names():
            if not x.startswith(self.labels.releasability.prefix):
                raise SecurityConfigException(
                    f"All security group labels must be prefixed with '{self.labels.releasability.prefix}'"
                )

        # extra allowed security settings
        self._markings = frozenset(self.labels.tlp.get_all_names())
        self._enforceable_markings = frozenset(
            [tlp_label.name for tlp_label in self.labels.tlp.options if tlp_label.enforce_security]
        )
        self._allowed = frozenset(self._markings.union(self._inclusive.union(self._exclusive)))

        # check allowed list is same length as other groups combined
        summed = (
            self.labels.classification.get_all_names()
            + self.labels.caveat.get_all_names()
            + self.labels.releasability.get_all_names()
            + self.labels.tlp.get_all_names()
        )
        if len(self._allowed) < len(summed):
            for x in self._allowed:
                summed.remove(x)
            raise SecurityConfigException(f"a security label has been defined twice: {summed}")

        for label in self.labels.releasability.get_all_names():
            if " " in label:
                raise SecurityConfigException(f"group labels must not have spaces: '{label}'")

        # generate 'safe' security labels that are compatible with opensearch role names
        self._unsafe_to_safe = {}
        self._safe_to_unsafe = {}
        for label in self._allowed:
            safe_label = security_to_role(label)
            self._unsafe_to_safe[label] = safe_label
            if safe_label in self._safe_to_unsafe:
                raise SecurityConfigException(f"two labels were made safe to the same value: {safe_label}")
            self._safe_to_unsafe[safe_label] = label

        # normalise minimum required access
        self.minimum_required_access = [x.upper() for x in self.minimum_required_access]

        # Classifications that allow TLPs and others that allow Rels
        _classifications_that_allow_tlps: set[str] = set()
        _classifications_that_allow_rels: set[str] = set()

        for clsf in self.labels.classification.options:
            # Exception to catch if something has changed that will affect this functionality of this code.
            if clsf.name not in self._exclusive:
                raise Exception(
                    "All classification names must be in the exclusive setting the exclusive setting "
                    + f"'{clsf.name}' is not."
                )

            if clsf.priority >= self.allow_releasability_priority_gte:
                _classifications_that_allow_rels.add(clsf.name)
            else:
                _classifications_that_allow_tlps.add(clsf.name)

        # Convert to frozen sets.
        self._classifications_that_allow_rels = frozenset(_classifications_that_allow_rels)
        self._classifications_that_allow_tlps = frozenset(_classifications_that_allow_tlps)

        self._origin_alt_name = self.labels.releasability.origin_alt_name

    @property
    def inclusive(self) -> frozenset[str]:
        """Set of valid inclusive labels."""
        return self._inclusive

    @property
    def exclusive(self) -> frozenset[str]:
        """Set of valid exclusive labels."""
        return self._exclusive

    @property
    def markings(self) -> frozenset[str]:
        """Set of valid markings labels."""
        return self._markings

    @property
    def enforceable_markings(self) -> frozenset[str]:
        """Set of valid enforceable markings labels."""
        return self._enforceable_markings

    @property
    def allowed(self) -> frozenset[str]:
        """Set of all valid labels (except for friendlies)."""
        return self._allowed

    @property
    def safe_to_unsafe(self) -> dict:
        """Map safe labels to unsafe labels."""
        return self._safe_to_unsafe

    @property
    def unsafe_to_safe(self) -> dict:
        """Map unsafe labels to safe labels."""
        return self._unsafe_to_safe

    @property
    def classifications_that_allow_tlps(self) -> frozenset[str]:
        """List of classifications that are allowed to have TLPs."""
        return self._classifications_that_allow_tlps

    @property
    def classifications_that_allow_releasability(self) -> frozenset[str]:
        """List of classifications that are allowed to have releasibility."""
        return self._classifications_that_allow_rels

    @cached_property
    def required_opensearch_roles(self) -> list:
        """Map unsafe to safe and add builtin opensearch specific mappings."""
        copy_unsafe_to_safe = self._unsafe_to_safe.copy()
        result = list(copy_unsafe_to_safe.values())
        result.append("s-any")
        result.append("azul_read")
        result.append("azul_write")
        # fillers to prevent Opensearch prevent SG 900D errors
        result.append("azul-fill1")
        result.append("azul-fill2")
        result.append("azul-fill3")
        result.append("azul-fill4")
        result.append("azul-fill5")

        return result
