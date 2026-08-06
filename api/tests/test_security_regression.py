"""Security regression tests for SHLD-1.

Source of truth: shield scan of a225f66 on main, run 2026-08-06T00:20:54Z.

These assert the dependency boundary recorded in api/requirements.txt — the same
artifact the scanner reads — against the fixed version each advisory names. They are
expected to FAIL on main and to pass once the remediation bumps the pins.

Written on unittest.TestCase so they run without adding a test dependency to a repo
that has none. Any of these works from the repo root:

    python3 -m pytest api/tests/test_security_regression.py
    python3 -m unittest discover -s api/tests -t api/tests
    python3 api/tests/test_security_regression.py

Between them, Pillow and cryptography account for every high-severity pip finding in
the scan (11 of 19 highs overall), so there is no backstop case on this side.
"""

import re
import unittest
from pathlib import Path

REQUIREMENTS = Path(__file__).resolve().parents[1] / "requirements.txt"

_PIN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)")


def pinned_versions():
    """Map of normalised distribution name -> pinned version for every `==` pin."""
    pins = {}
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        match = _PIN.match(line)
        if match:
            pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pins


def _sort_key(version):
    """Release tuple for `version`; a pre-release suffix sorts below its release."""
    core = re.match(r"\d+(?:\.\d+)*", version).group(0)
    nums = [int(part) for part in core.split(".")]
    nums += [0] * (4 - len(nums))
    return tuple(nums) + (1 if core == version else 0,)


def at_least(version, floor):
    return _sort_key(version) >= _sort_key(floor)


class AdvisoryFloorTestCase(unittest.TestCase):
    """Shared assertion: the pin for `name` sits at or above an advisory's fixed version."""

    def assert_floor(self, name, floor, advisory):
        pins = pinned_versions()
        self.assertIn(
            name,
            pins,
            f"{name} is no longer pinned in api/requirements.txt; "
            f"{advisory} was assessed against a pinned version",
        )
        pinned = pins[name]
        self.assertTrue(
            at_least(pinned, floor),
            f"api/requirements.txt pins {name}=={pinned}; {advisory} needs >= {floor}",
        )


class TestPillowAdvisoryFloor(AdvisoryFloorTestCase):
    """Largest high-severity cluster in the scan: 8 highs, all fixed in Pillow 12.3.0.

    Two of them are memory-corruption class rather than DoS — CVE-2026-59197 (native
    heap out-of-bounds write) and CVE-2026-59205 (controlled heap corruption in
    ImageCms.ImageCmsTransform.apply) — which is what ranks this cluster first.
    """

    HIGH_ADVISORIES = (
        "CVE-2026-54058",  # out-of-bounds read via attacker-controlled row stride (mmap)
        "CVE-2026-54059",  # DoS via crafted PCF font data
        "CVE-2026-54060",  # DoS via excessive memory allocation on font files
        "CVE-2026-55379",  # DoS via crafted BDF font file
        "CVE-2026-55380",  # DoS via crafted GD 2.x image file
        "CVE-2026-59197",  # native heap out-of-bounds write
        "CVE-2026-59199",  # DoS via out-of-bounds write in image processing
        "CVE-2026-59200",  # decompression bomb DoS via PdfParser.PdfStream.decode()
        "CVE-2026-59204",  # JPEG2000 tiled decode retains a growing scratch buffer
        "CVE-2026-59205",  # controlled native heap corruption in ImageCms
    )

    def test_pillow_clears_every_high_advisory(self):
        self.assert_floor("pillow", "12.3.0", ", ".join(self.HIGH_ADVISORIES))

    def test_pillow_clears_the_moderate_advisories_sharing_the_floor(self):
        # Same 12.3.0 fix; kept separate so a partial bump reports which class it missed.
        moderates = (
            "CVE-2026-55798",  # arbitrary command injection via shell metacharacters
            "CVE-2026-59198",  # TGA RLE encoder serialises adjacent heap data
            "CVE-2026-59203",  # DoS via crafted EPS file
        )
        self.assert_floor("pillow", "12.3.0", ", ".join(moderates))


class TestCryptographyAdvisoryFloor(AdvisoryFloorTestCase):
    """The only confidentiality break in the scan, and three different fixed versions.

    CVE-2026-69247 is a Bleichenbacher oracle in PKCS#7 EnvelopedData decryption:
    plaintext recovery, not denial of service. It carries the highest floor (50.0.0),
    so a single pin at 50.0.0 subsumes the other two.
    """

    def test_pkcs7_bleichenbacher_oracle(self):
        self.assert_floor("cryptography", "50.0.0", "CVE-2026-69247")

    def test_exponential_path_building_via_duplicate_intermediates(self):
        self.assert_floor("cryptography", "49.0.0", "CVE-2026-69249")

    def test_bundled_openssl(self):
        self.assert_floor("cryptography", "48.0.1", "GHSA-537c-gmf6-5ccf")

    def test_wildcard_dns_escape_from_permitted_subtrees(self):
        # Moderate, same 49.0.0 floor as CVE-2026-69249.
        self.assert_floor("cryptography", "49.0.0", "CVE-2026-69248")


if __name__ == "__main__":
    unittest.main()
