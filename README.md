# truxt-dep-demo

Demo repository with intentionally outdated and vulnerable dependencies for testing [truxt-axiom](https://github.com/truxt-ai/truxt-axiom) automated dependency management.

## Structure

```
truxt-dep-demo/
├── app/                    # Node.js Express app
│   ├── package.json        # Outdated npm packages
│   └── index.js
├── api/                    # Python Flask API
│   ├── requirements.txt    # Outdated Python packages
│   └── app.py
└── .github/workflows/
    ├── npm-audit.yml       # Fails: npm vulnerability scan
    ├── pip-audit.yml       # Fails: Python vulnerability scan
    └── deps-report.yml     # Fails: minimum version enforcement
```

## Outdated Dependencies

### Node.js (`app/package.json`)
| Package | Pinned | Latest | CVEs |
|---------|--------|--------|------|
| lodash | 4.17.4 | 4.17.21+ | Prototype pollution |
| minimist | 0.0.8 | 1.2.8+ | Prototype pollution (critical) |
| axios | 0.18.0 | 1.x | SSRF |
| node-fetch | 1.7.3 | 3.x | Various |
| serialize-javascript | 1.9.1 | 6.x | RCE |
| node-forge | 0.9.0 | 1.x | Multiple |

### Python (`api/requirements.txt`)
| Package | Pinned | Latest | CVEs |
|---------|--------|--------|------|
| Flask | 0.12.4 | 3.x | DoS (CVE-2018-1000656) |
| PyYAML | 3.13 | 6.x | RCE (CVE-2017-18342) |
| Pillow | 5.4.1 | 10.x | Multiple |
| cryptography | 2.1.4 | 42.x | Multiple |
| urllib3 | 1.22 | 2.x | Multiple |
| requests | 2.18.4 | 2.31+ | |

## CI Failures

Every push to `main` triggers three workflows that intentionally fail:

1. **NPM Security Audit** — `npm audit` finds high/critical advisories
2. **Python Security Audit** — `pip-audit` finds CVEs in pinned packages
3. **Dependency Health Report** — version enforcement fails for all packages

These failures are the input signal for truxt-axiom to detect, analyze, and raise fix PRs.

<!-- audit-trigger test: nudge the dep-audit scan on this PR branch -->

