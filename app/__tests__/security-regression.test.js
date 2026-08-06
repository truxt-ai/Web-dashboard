/**
 * Security regression tests for SHLD-1.
 *
 * Source of truth: shield scan of a225f66 on main, run 2026-08-06T00:20:54Z.
 *
 * These assert the dependency boundary recorded in app/package-lock.json — the same
 * artifact the scanner reads — against the fixed version each advisory names. They are
 * expected to FAIL on main and to pass once the remediation bumps the lockfile.
 *
 * There is no behavioural exploit test here on purpose: every npm advisory in this scan
 * is resolved by version, and the scan classifies them all as `rescan_decisive`. A test
 * that reproduced, say, the brace-expansion blowup would assert on timing and would be
 * flaky in CI without proving anything the version floor does not already prove.
 */

const fs = require('fs');
const path = require('path');

const LOCKFILE = path.join(__dirname, '..', 'package-lock.json');
const MANIFEST = path.join(__dirname, '..', 'package.json');

const lock = JSON.parse(fs.readFileSync(LOCKFILE, 'utf8'));
const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));

/** Every installed copy of `name` in the lockfile, as `{ where, version }`. */
function installedCopies(name) {
  const suffix = `node_modules/${name}`;
  return Object.entries(lock.packages)
    .filter(([where]) => where === suffix || where.endsWith(`/${suffix}`))
    .map(([where, meta]) => ({ where, version: meta.version }));
}

/** True when `version` is at or above `floor`. A pre-release sorts below its release. */
function atLeast(version, floor) {
  const parts = (v) => {
    const core = v.match(/^\d+(?:\.\d+)*/)[0];
    const nums = core.split('.').map(Number);
    while (nums.length < 4) nums.push(0);
    nums.push(core === v ? 1 : 0);
    return nums;
  };
  const a = parts(version);
  const b = parts(floor);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return true;
}

/**
 * Assert no installed copy of `name` sits below `floor`.
 *
 * Zero copies passes: dropping the package resolves the advisory just as an upgrade does.
 * Presence is asserted separately, and only where the app actually owns the dependency.
 */
function expectNoCopyBelow(name, floor, advisory, filter = () => true) {
  const offenders = installedCopies(name)
    .filter(filter)
    .filter((copy) => !atLeast(copy.version, floor));

  expect(
    offenders.map((c) => `${c.where} @ ${c.version} (needs >= ${floor} for ${advisory})`)
  ).toEqual([]);
}

describe('SHLD-1 · npm dependency boundary (app/package-lock.json)', () => {
  // Cluster 1 of the three covered here: the only high-severity advisory in this scan
  // that lands on a dependency app/package.json declares directly, so the boundary is
  // one the app owns outright rather than inherits.
  describe('axios — CVE-2026-67320 (high), fixed in 1.18.0', () => {
    test('no installed axios is below 1.18.0', () => {
      expectNoCopyBelow('axios', '1.18.0', 'CVE-2026-67320');
    });

    test('the direct pin in package.json is at or above 1.18.0', () => {
      const pin = manifest.dependencies.axios;
      expect(pin).toBeDefined();
      const version = pin.replace(/^[^\d]*/, '');
      expect(
        atLeast(version, '1.18.0')
          ? null
          : `package.json pins axios ${pin}; CVE-2026-67320 needs >= 1.18.0`
      ).toBeNull();
    });

    // The 1.18.0 bump also closes eight moderate axios advisories from the same scan.
    // Kept as one case: they share a floor, so separate cases would repeat one assertion.
    test('1.18.0 also clears the eight moderate axios advisories', () => {
      const moderates = [
        'CVE-2026-67312', 'CVE-2026-67313', 'CVE-2026-67314', 'CVE-2026-67315',
        'CVE-2026-67316', 'CVE-2026-67317', 'CVE-2026-67318', 'CVE-2026-67319',
        'CVE-2026-67321',
      ];
      expect(moderates.length).toBeGreaterThan(0);
      expectNoCopyBelow('axios', '1.18.0', moderates.join(', '));
    });
  });

  // Backstop for the high-severity npm advisories outside the covered clusters. Without
  // this a remediation could bump axios alone, turn the suite green, and leave five highs
  // standing. One data-driven case per package; each shares a floor across its advisories.
  describe('remaining high-severity npm advisories', () => {
    test.each([
      // brace-expansion 1.x only: all three advisories name a 1.1.x fix, and the lockfile
      // carries a 1.1.15 copy under test-exclude. The separate 2.1.1 copy is NOT covered
      // here — see the open question in TEST-IMPACT-SHLD-1.md.
      {
        name: 'brace-expansion',
        floor: '1.1.18',
        advisory: 'CVE-2026-13149, CVE-2026-14257, CVE-2026-69152',
        onlyOneDotX: true,
      },
      { name: 'form-data', floor: '4.0.6', advisory: 'CVE-2026-12143' },
      { name: 'js-yaml', floor: '3.15.0', advisory: 'CVE-2026-59869' },
    ])('$name is at or above $floor ($advisory)', ({ name, floor, advisory, onlyOneDotX }) => {
      const filter = onlyOneDotX ? (copy) => copy.version.startsWith('1.') : undefined;
      expectNoCopyBelow(name, floor, advisory, filter);
    });
  });
});
