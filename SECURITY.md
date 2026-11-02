# Security policy

Kennword stores encrypted vaults, so security issues matter more than anything else here. If you
believe you have found one, please tell us privately first. Thank you!

## Status

Kennword is in early development and has not been independently audited; the findings of two
internal reviews are in [docs/security-review.md](docs/security-review.md). Only the latest
[release](https://github.com/Lumundi/kennword/releases) and the latest commit on `main` are
supported; fixes are not backported to older releases.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/Lumundi/kennword/security/advisories/new).
If you cannot use GitHub, write to [security@kennword.org](mailto:security@kennword.org) instead;
[security.txt](https://www.kennword.org/.well-known/security.txt) lists both channels. Please do not open
a public issue.

Helpful to include:

- what an attacker can do, and under which conditions
- the steps or requests to reproduce it
- the commit you tested and the database you used
- whether Vaultwarden behaves the same way (see below)

We will confirm receipt, keep you informed and credit you in the advisory unless you prefer otherwise.
Please give us reasonable time to fix the issue before you disclose it.

## Issues that also affect Vaultwarden

Kennword ports Vaultwarden's behaviour as exactly as it can, so a flaw in that behaviour may exist
in both. If Vaultwarden behaves the same way, please also report it to Vaultwarden as described in
[its security policy](https://github.com/dani-garcia/vaultwarden/blob/main/SECURITY.md). Kennword
is not part of the Vaultwarden project; its maintainers are not responsible for this port.

## Out of scope

- Issues in the Bitwarden clients or the web vault: report them to [Bitwarden](https://github.com/bitwarden)
- Issues in PHP, Laravel or another dependency that are already known upstream
- Attacks that need physical access to a user's device
- Denial of service, spam and social engineering
- Missing hardening that does not lead to a vulnerability; please open a normal issue for those

While researching, only use accounts and data you own or have permission to use.
