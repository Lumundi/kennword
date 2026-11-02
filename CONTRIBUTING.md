# Contributing

Thank you for helping. Kennword has one goal: to behave exactly like the pinned Vaultwarden
version, so that the official Bitwarden clients and existing Vaultwarden data keep working.

## Before you start

- [AGENTS.md](AGENTS.md) describes the environment, the commands, the parity workflow and the
  conventions of the code. It applies to people and AI assistants alike.
- [PARITY.md](PARITY.md) shows what is ported and what is still open. Each item names the place in
  Vaultwarden's Rust source it comes from; read that before you implement it.
- For larger changes, open an issue first so that we can agree on the approach.

## Making a change

- Port the behaviour from Vaultwarden's source at the pinned commit; do not invent behaviour of your own.
  Where Kennword has to differ, say so in the matrix note and in
  [docs/configuration.md](docs/configuration.md).
- Write a test for every item you mark as done, and a differential test for every route (see
  AGENTS.md).
- Changes to what the clients see are best checked with the clients themselves:
  [docs/clients.md](docs/clients.md) runs the web vault and the CLI against a server of your own.
- Run Pint, PHPStan and the tests before you open a pull request:

  ```bash
  vendor/bin/pint
  vendor/bin/phpstan analyse --memory-limit=1G
  php artisan test
  ```

- If you copy a file, start from one or reproduce another library's behaviour, credit it in
  [NOTICE.md](NOTICE.md).
- Security issues do not belong in public issues or pull requests; see [SECURITY.md](SECURITY.md).
- [docs/maintenance.md](docs/maintenance.md) describes how advisories and Vaultwarden's changes are
  watched, which issues the watch opens and how the pin is moved.

## License of contributions

Kennword is licensed under the AGPL-3.0-only. By contributing, you agree that your contribution is
licensed under the same license. There is no contributor license agreement; you keep the copyright of
your work.

If an AI assistant helped you write a change, say so in the commit message (for example with a
`Co-Authored-By` trailer), as the existing commits do.
