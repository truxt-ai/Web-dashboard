"""Security regression tests for SHLD-13 — the Maven boundary of SHLD-8.

Source of truth: the shield audit on parent SHLD-8, finding 4.2.

    CVE-2021-44228 — log4j-core 2.14.1 (Maven), resolved from `pom.xml`.
    CRITICAL, CVSS 10.0, CISA KEV, EPSS 97%. Fixed in 2.17.1.

These assert the dependency boundary the scanner named — the same artifact it read —
against the fixed version the advisory names. They are expected to FAIL on `main` and
to pass once the remediation on `hod/shld-8-g2-impl` lands a `pom.xml` whose log4j
coordinates sit at or above 2.17.1.

`pom.xml` is not in the tree at a225f66, so today every case below fails on the
manifest itself rather than on a version. That is deliberate, not a gap: the finding
was resolved from that path, and a suite that skipped when the file was absent would
report a CISA KEV entry closed with nothing having been fixed. See
TEST-IMPACT-SHLD-8-g2.md for what that discrepancy means for the impl step.

Written on unittest.TestCase with a stdlib XML parser so they run without adding a
test dependency, and without a JDK or Maven, to a repo that has none of the three.
Any of these works from the repo root:

    python3 -m pytest tests/test_maven_dependency_boundary.py
    python3 -m unittest discover -s tests -t tests
    python3 tests/test_maven_dependency_boundary.py
"""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
POM = REPO_ROOT / "pom.xml"

LOG4J_GROUP = "org.apache.logging.log4j"
FIXED_IN = "2.17.1"

# Log4Shell and the two follow-ons that decide the floor. 2.15.0 closes CVE-2021-44228
# on its own; the advisory names 2.17.1 because 45046 and 45105 land after it, which is
# why a bump to 2.15.0 or 2.16.0 has to read as a failure here rather than a pass.
LOG4SHELL_FAMILY = (
    "CVE-2021-44228",  # JNDI lookup substitution -> RCE
    "CVE-2021-45046",  # incomplete 2.15.0 fix, Thread Context Map lookup -> RCE
    "CVE-2021-45105",  # self-referential lookups -> uncontrolled recursion
)
VULNERABLE_FLOOR = "2.0-beta9"  # first affected release

_NS = re.compile(r"^\{[^}]*\}")
_PROP_REF = re.compile(r"^\$\{([^}]+)\}$")


def _tag(elem):
    """Local tag name. POMs may or may not carry the 4.0.0 namespace; both parse."""
    return _NS.sub("", elem.tag)


def _child_text(elem, name):
    for sub in elem:
        if _tag(sub) == name:
            return (sub.text or "").strip()
    return None


def _properties(root):
    """Every <properties> entry, flattened. Maven pins log4j through one of these as
    often as it does inline, so ignoring them would read a managed pin as absent."""
    props = {}
    for elem in root.iter():
        if _tag(elem) == "properties":
            for prop in elem:
                props[_tag(prop)] = (prop.text or "").strip()
    return props


def _resolve(value, props):
    """Follow ${...} indirection. Returns (resolved, unresolved_key); exactly one is set."""
    seen = set()
    while value:
        match = _PROP_REF.match(value)
        if not match:
            return value, None
        key = match.group(1)
        if key in seen or key not in props:
            return None, key
        seen.add(key)
        value = props[key]
    return value, None


def _version_key(version):
    """Ordering key for a Maven version, or None if it has no numeric head.

    A qualifier sorts below its bare release, so 2.0-beta9 < 2.0 < 2.17.1.
    """
    core = re.match(r"\d+(?:\.\d+)*", version)
    if core is None:
        return None
    nums = [int(part) for part in core.group(0).split(".")]
    nums += [0] * (4 - len(nums))
    qualifier = version[core.end():].lstrip(".-_")
    return tuple(nums[:4]) + (0 if qualifier else 1,)


def at_least(version, floor):
    key = _version_key(version)
    return key is not None and key >= _version_key(floor)


def log4j_coordinates():
    """Every declared org.apache.logging.log4j artifact in the pom.

    Reads <dependencies> and <dependencyManagement> alike — the scanner resolves from
    both — and returns one record per declaration:
    (artifactId, resolved_version, unresolved_property, raw_version).
    """
    root = ET.parse(POM).getroot()
    props = _properties(root)
    found = []
    for elem in root.iter():
        if _tag(elem) != "dependency":
            continue
        group, _ = _resolve(_child_text(elem, "groupId") or "", props)
        if group != LOG4J_GROUP:
            continue
        artifact = _child_text(elem, "artifactId") or "<unnamed>"
        raw = _child_text(elem, "version")
        if raw is None:
            found.append((artifact, None, None, None))
            continue
        version, unresolved = _resolve(raw, props)
        found.append((artifact, version, unresolved, raw))
    return found


class MavenBoundaryTestCase(unittest.TestCase):
    """Shared load step, which fails rather than skips when the manifest is absent."""

    def coordinates(self):
        if not POM.is_file():
            self.fail(
                "pom.xml does not exist at this revision. The SHLD-8 audit resolved "
                f"{LOG4SHELL_FAMILY[0]} (log4j-core 2.14.1) from that path, so either the "
                "manifest is missing from the tree the scanner read, or the finding does "
                "not belong to this repository. Skipping here would report a CISA KEV "
                "entry closed with nothing fixed; see TEST-IMPACT-SHLD-8-g2.md."
            )
        return log4j_coordinates()

    def concrete(self):
        """Declarations carrying a version this pom can resolve on its own."""
        return [(name, version) for name, version, _, _ in self.coordinates() if version]


class TestScannedManifest(MavenBoundaryTestCase):
    """The boundary itself. Everything below is unverifiable without it."""

    def test_the_scanned_manifest_is_in_the_tree(self):
        self.coordinates()

    def test_no_version_is_left_to_an_unresolvable_property(self):
        """A ${...} the pom cannot resolve reads as 'no version found', which would let
        the floor cases below pass on a pin they never actually inspected."""
        dangling = [
            f"{name} version {raw} -> ${{{key}}} is not defined in <properties>"
            for name, _, key, raw in self.coordinates()
            if key
        ]
        self.assertEqual([], dangling, "; ".join(dangling))

    def test_no_declaration_defers_its_version_out_of_this_pom(self):
        """A <dependency> with no <version> is pinned by a parent POM or an imported BOM
        this test cannot see. The scanner resolved a concrete 2.14.1, so a version that
        is invisible here is an unasserted boundary, not a clean one."""
        managed = {name for name, _ in self.concrete()}
        deferred = [name for name, version, key, raw in self.coordinates()
                    if version is None and key is None and raw is None and name not in managed]
        self.assertEqual(
            [], deferred,
            "declared with no resolvable version in pom.xml: "
            f"{', '.join(deferred)}; the audit resolved log4j-core 2.14.1, so this pin "
            "has to be visible here to be asserted",
        )


class TestLog4jCoreFloor(MavenBoundaryTestCase):
    """CVE-2021-44228 — the one finding in this ticket's scope.

    CVSS 10.0, on CISA's Known Exploited Vulnerabilities catalog, EPSS 97%: the highest
    exploit signal in the SHLD-8 report and the reason this group is ranked third of
    five in the parent's triage table despite being a single finding.
    """

    def test_log4j_core_clears_the_log4shell_family(self):
        cores = [version for name, version in self.concrete() if name == "log4j-core"]
        if not cores:
            # Removing log4j-core resolves the advisory as surely as upgrading it, so an
            # absent artifact in a present pom is a pass. The pom itself is asserted above.
            return
        for version in cores:
            self.assertTrue(
                at_least(version, FIXED_IN),
                f"pom.xml declares log4j-core {version}; "
                f"{', '.join(LOG4SHELL_FAMILY)} need >= {FIXED_IN}",
            )

    def test_no_log4j_artifact_sits_in_the_affected_range(self):
        """Catches the partial bump the floor case alone would not explain: 2.15.0 and
        2.16.0 close CVE-2021-44228 and still carry 45046 or 45105."""
        affected = [
            f"{name} {version}"
            for name, version in self.concrete()
            if at_least(version, VULNERABLE_FLOOR) and not at_least(version, FIXED_IN)
        ]
        self.assertEqual(
            [], affected,
            f"in the affected range [{VULNERABLE_FLOOR}, {FIXED_IN}): {', '.join(affected)}",
        )

    def test_every_log4j_artifact_moves_with_core(self):
        """log4j-api and the binding jars ship as a set with log4j-core. A bump that moves
        core alone leaves the group skewed, which is the signature of a partial fix."""
        behind = [f"{name} {version}" for name, version in self.concrete()
                  if not at_least(version, FIXED_IN)]
        self.assertEqual(
            [], behind,
            f"{LOG4J_GROUP} artifacts below {FIXED_IN}: {', '.join(behind)}",
        )


if __name__ == "__main__":
    unittest.main()
