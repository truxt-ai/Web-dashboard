# Test impact memo — SHLD-1 security regression tests

Branch `hod/shld-1-tests`, cut from `main` at `a225f66`.
Source of truth: shield scan run `2026-08-06T00:20:54Z-20e95f` (0 critical, 19 high,
14 moderate, 1 low across 34 findings, all classed `rescan_decisive`).

These tests fail on `main` by design. They are the acceptance check for the
remediation on `hod/shld-1-impl`; that branch is where the pins move, not this one.

## How to run

```
cd app && npm install && npx jest                       # 6 cases, all currently failing
python3 -m pytest api/tests/test_security_regression.py # 6 cases, all currently failing
```

## What each case protects

### `app/__tests__/security-regression.test.js` — boundary: `app/package-lock.json`

| Test case | Advisory | Boundary today | Floor |
| --- | --- | --- | --- |
| `axios … › no installed axios is below 1.18.0` | CVE-2026-67320 (high) — Node HTTP adapter can use an inherited proxy after interceptor config cloning | `node_modules/axios` @ 1.16.1 | 1.18.0 |
| `axios … › the direct pin in package.json is at or above 1.18.0` | CVE-2026-67320 (high) | `app/package.json` pins `"axios": "1.16.1"` | 1.18.0 |
| `axios … › 1.18.0 also clears the eight moderate axios advisories` | CVE-2026-67312 / 67313 / 67314 / 67315 / 67316 / 67317 / 67318 / 67319 / 67321 (moderate) | same boundary | 1.18.0 |
| `remaining … › brace-expansion is at or above 1.1.18` | CVE-2026-13149, CVE-2026-14257, CVE-2026-69152 (high) | `node_modules/test-exclude/node_modules/brace-expansion` @ 1.1.15 | 1.1.18 |
| `remaining … › form-data is at or above 4.0.6` | CVE-2026-12143 (high) — CRLF injection via unescaped multipart field names | `node_modules/form-data` @ 4.0.5 | 4.0.6 |
| `remaining … › js-yaml is at or above 3.15.0` | CVE-2026-59869 (high) — merge-key chains force quadratic CPU | `node_modules/js-yaml` @ 3.14.2 | 3.15.0 |

### `api/tests/test_security_regression.py` — boundary: `api/requirements.txt`

| Test case | Advisory | Boundary today | Floor |
| --- | --- | --- | --- |
| `TestPillowAdvisoryFloor::test_pillow_clears_every_high_advisory` | CVE-2026-54058 / 54059 / 54060 / 55379 / 55380 / 59197 / 59199 / 59200 / 59204 / 59205 (high) | `Pillow==12.2.0` | 12.3.0 |
| `TestPillowAdvisoryFloor::test_pillow_clears_the_moderate_advisories_sharing_the_floor` | CVE-2026-55798 / 59198 / 59203 (moderate) | `Pillow==12.2.0` | 12.3.0 |
| `TestCryptographyAdvisoryFloor::test_pkcs7_bleichenbacher_oracle` | CVE-2026-69247 (high) — PKCS#7 EnvelopedData decryption oracle | `cryptography==48.0.0` | 50.0.0 |
| `TestCryptographyAdvisoryFloor::test_exponential_path_building_via_duplicate_intermediates` | CVE-2026-69249 (high) | `cryptography==48.0.0` | 49.0.0 |
| `TestCryptographyAdvisoryFloor::test_bundled_openssl` | GHSA-537c-gmf6-5ccf (high) — vulnerable OpenSSL in the wheels | `cryptography==48.0.0` | 48.0.1 |
| `TestCryptographyAdvisoryFloor::test_wildcard_dns_escape_from_permitted_subtrees` | CVE-2026-69248 (moderate) | `cryptography==48.0.0` | 49.0.0 |

## Why these three clusters

The ticket asked for the top 2-3 critical/high findings. The scan has 0 critical and 19
high spread over six packages, so the ranking is by severity class first, cluster size
second:

1. **Pillow (8 high).** Largest cluster, and the only one containing memory-corruption
   rather than denial of service: CVE-2026-59197 (native heap out-of-bounds write) and
   CVE-2026-59205 (controlled heap corruption in `ImageCms.ImageCmsTransform.apply`).
2. **cryptography (3 high).** The only confidentiality break in the scan.
   CVE-2026-69247 is a Bleichenbacher oracle: plaintext recovery, not DoS.
3. **axios (1 high + 8 moderate).** The only high-severity finding on a package
   `app/package.json` declares directly, so it is a boundary this repo owns outright
   rather than inherits. Asserted at both the manifest pin and the lockfile.

The remaining npm highs (brace-expansion, form-data, js-yaml) are covered by one
data-driven backstop case rather than being left out. Without it a remediation could bump
axios alone, turn the suite green, and leave five high-severity findings standing.

## Deliberate omissions

- **No behavioural exploit tests.** Every finding in this scan is `rescan_decisive`:
  it resolves against the manifest or it does not. Reproducing, say, the brace-expansion
  blowup would assert on wall-clock timing and be flaky in CI without proving anything
  the version floor does not already prove. The version boundary is the honest test here.
- **CVE-2026-12590 (body-parser, low) is not covered.** Below the high bar the ticket set.
  `node_modules/body-parser` is at 2.2.2 and the advisory names 2.3.0; add a row to the
  backstop `test.each` table if the remediation decides to close it.
- **Zero installed copies passes.** Dropping a package resolves its advisory as well as
  upgrading does, so `expectNoCopyBelow` does not require presence. Presence is asserted
  only for `axios` in `app/package.json`, where the app genuinely owns the dependency.

## Open question for the impl step

`app/package-lock.json` carries **two** brace-expansion copies: 1.1.15 (under
`test-exclude`) and 2.1.1 (top level). All three advisories name 1.1.x fixed versions,
so the test asserts against the 1.x line only. Whether 2.1.1 is also affected cannot be
settled from this ticket: the scan's per-finding detail was stripped to fit the delivery
payload, and the complete machine report was written only to the scanner's ephemeral run
directory. If the rescan after remediation still reports a brace-expansion finding, that
copy is the reason, and the `onlyOneDotX` filter in the backstop table needs to go.
