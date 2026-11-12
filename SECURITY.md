# Security Policy

warden handles authentication, sessions and audit records, so security reports are taken seriously and handled privately.

## Reporting a vulnerability

Please do **not** open a public issue, discussion or pull request for a suspected vulnerability.

Report it privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- the affected version or commit
- a description of the issue and its impact
- steps to reproduce, or a proof of concept
- any suggested fix

You will receive an acknowledgement within five business days. We will keep you informed while the issue is investigated and fixed, and credit you in the release notes unless you prefer otherwise.

## Scope

This policy covers the `cognisn-warden` package published on PyPI and the source in this repository that builds it. The sample console under `examples/` is for local development, is not part of the package, and is not supported for deployment, though reports about it are still welcome.

## Supported versions

Security fixes are released for the latest minor release series only. Before 1.0 that is the newest `0.x` series; for example, while `0.1.x` is current, fixes are released as the next `0.1` patch version.

| Version | Supported |
|---|---|
| Latest `0.x` minor series | Yes |
| Older series | No |
| Pre-releases (`a`, `b`, `rc`) | Only until the final release of that version |

## Disclosure

A confirmed vulnerability is fixed privately and released as a new version on PyPI. A GitHub security advisory is then published, with a CVE where one applies, describing the issue, the affected and fixed versions, and any workaround. Nothing about the issue is made public before the fixed version is available.
