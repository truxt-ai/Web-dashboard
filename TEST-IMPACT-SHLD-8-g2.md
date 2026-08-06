# Test impact memo — SHLD-13 security regression tests (SHLD-8 group g2)

Branch `hod/shld-8-g2-tests`, cut from `main` at `a225f66`.
Scope: the single finding this ticket owns — `CVE-2021-44228`, `log4j-core` 2.14.1,
manifest `pom.xml` (parent SHLD-8, finding 4.2). Group g1 (`package-lock.json`) is
SHLD-9's; nothing here touches it.

These tests fail on `main` by design. They are the acceptance check for the remediation
on `hod/shld-8-g2-impl`; that branch is where the pin moves, not this one.

## Read this first: the manifest is not in the repository

`pom.xml` does not exist at `a225f66`, and it does not exist on **any** branch of
`truxt-ai/Web-dashboard`. `origin/main` is six files — `README.md`, `api/app.py`,
`api/requirements.txt`, `app/index.js`, `app/package.json`, `app/package-lock.json`.
There is no Java source, no Maven wrapper, and no reference to `log4j` anywhere in the
history.

So the finding this ticket scopes points at a manifest the repository does not have.
That is a fact about the audit, not a fact this step can fix, and it is the impl step's
first decision:

- if the scanner read a tree that legitimately has a `pom.xml`, that manifest belongs in
  the repo and the pin lands at `2.17.1`, at which point this suite goes green; or
- if it does not, `CVE-2021-44228` is a false positive against this repository and the
  finding should be withdrawn on SHLD-8 rather than remediated on SHLD-14.

Either way it is a human call, so the tests encode the boundary the audit named and let
it fail loudly rather than guessing.

## How to run

```
python3 -m pytest tests/test_maven_dependency_boundary.py   # 6 cases, all currently failing
python3 -m unittest discover -s tests -t tests              # same 6, no pytest needed
python3 tests/test_maven_dependency_boundary.py             # same 6, direct
```

Stdlib only — `unittest` plus `xml.etree.ElementTree`. No JDK, no Maven, no new test
dependency, matching the constraint the SHLD-1 suite set on a repo that has none of them.

## What each case protects

`tests/test_maven_dependency_boundary.py` — boundary: `pom.xml`, floor `2.17.1`.

| Test case | Advisory | What it catches |
| --- | --- | --- |
| `TestScannedManifest::test_the_scanned_manifest_is_in_the_tree` | CVE-2021-44228 | The manifest the audit resolved from is absent. Fails today; the discrepancy above. |
| `TestScannedManifest::test_no_version_is_left_to_an_unresolvable_property` | CVE-2021-44228 | `<version>${log4j.version}</version>` with no such property — reads as "no version found" and would let the floor cases pass on a pin they never inspected. |
| `TestScannedManifest::test_no_declaration_defers_its_version_out_of_this_pom` | CVE-2021-44228 | A `<dependency>` with no `<version>`, pinned by an unseen parent POM or imported BOM. The audit resolved a concrete 2.14.1, so an invisible pin is an unasserted boundary. |
| `TestLog4jCoreFloor::test_log4j_core_clears_the_log4shell_family` | CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 | `log4j-core` below 2.17.1. The direct assertion of the ticket's finding. |
| `TestLog4jCoreFloor::test_no_log4j_artifact_sits_in_the_affected_range` | CVE-2021-45046, CVE-2021-45105 | The partial bump: 2.15.0 and 2.16.0 close CVE-2021-44228 and still carry the follow-ons. This is why the advisory's fixed version is 2.17.1 and not 2.15.0. |
| `TestLog4jCoreFloor::test_every_log4j_artifact_moves_with_core` | all three | Version skew inside `org.apache.logging.log4j` — `log4j-core` moved to 2.17.1, `log4j-api` left at 2.14.1. They ship as a set; skew is the signature of a half-applied bump. |

## Verification of the suite itself

A test that is red today is worth nothing if it is also red after the fix. Each case was
run against a synthetic `pom.xml` in a scratch tree outside the repo (no `pom.xml` was
committed here):

| Fixture | Result |
| --- | --- |
| `log4j-core` 2.14.1 inline — the reported state | 3 fail |
| bumped to 2.16.0 — partial fix | 3 fail |
| bumped to 2.17.1 | **all pass** |
| version via `${log4j.version}` = 2.14.1 | 3 fail — property indirection resolves |
| `${log4j.version}` never defined | 1 fail — the anti-vacuity case |
| `log4j-core` 2.17.1 + `log4j-api` 2.14.1, no `xmlns`, inside `<dependencyManagement>` | 2 fail naming `log4j-api` |
| `<dependency>` with no `<version>` | 1 fail |
| `log4j` dropped, `logback-classic` in its place | **all pass** |

The namespace-less and `<dependencyManagement>` fixture is deliberate: POMs are written
both ways, and a parser that only handled the namespaced `<dependencies>` form would pass
vacuously on half of the real inputs.

## Why one finding gets six cases

The ticket asks for the top 2-3 critical/high findings; Scope pins this ticket to exactly
one, and the hard rules give every other manifest in the report to a sibling. So the depth
went into the failure modes of the one boundary rather than across manifests. The finding
earns it: CVSS 10.0, on CISA's Known Exploited Vulnerabilities catalog, EPSS 97% — the
highest exploit signal in the SHLD-8 report, and ranked third of five in the parent's
triage table despite being a single advisory.

## Deliberate decisions

- **Absent manifest fails, it does not skip.** A `unittest.skipUnless` on
  `POM.is_file()` would turn this suite green on `main` right now and report a CISA KEV
  entry closed with nothing fixed. That is the one outcome worth engineering against, so
  all six cases fail on the missing file rather than quietly dropping out of the count.
- **Removing `log4j-core` passes.** Dropping the dependency resolves the advisory as
  surely as upgrading it, so an absent artifact in a *present* pom is a pass. Presence is
  asserted for the manifest, never for the artifact. Same reasoning the SHLD-1 suite
  applied to zero installed copies on the npm side.
- **No behavioural exploit test.** Standing up a JNDI/LDAP listener and proving a
  `${jndi:ldap://…}` payload resolves would need a JDK, a network listener and a
  vulnerable log4j on the classpath — three things this repo does not have — to prove
  what the version boundary already proves. The finding is manifest-resolvable; the
  manifest is the honest test.
- **No test for the other findings in the report.** `colours`, `axios`, `postcss` and
  the `deploy/legacy.env` credential are out of this ticket's scope by its hard rules.

## Open question for the impl step

**The floor is a flat `2.17.1`, which rejects the backport lines.** Upstream also fixed
Log4Shell in `2.12.4` (Java 8) and `2.3.2` (Java 7) without going to 2.x-latest. This suite
fails both — verified: the 2.12.4 fixture reports 3 failures. That is correct for a
remediation targeting current Java and wrong for one pinned to an older runtime. Since the
repo has no Java at all, there is no `maven.compiler.release` to read and no way to settle
it from this ticket. If SHLD-14 lands a pom targeting Java 8 or 7, replace the single
`FIXED_IN` constant with a per-line floor table rather than lowering it globally —
lowering it to 2.12.4 would also admit 2.13.x through 2.16.x, which are all vulnerable.
