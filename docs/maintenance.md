# Maintenance: advisories and upstream changes

How Kennword notices security advisories and changes upstream, what happens on its own and what
waits for a maintainer. Kennword is only as safe as its port of Vaultwarden's fixes and the
packages it runs on, so both are watched, not left to chance.

## What is watched

| Source | How | When | Shows up as |
| --- | --- | --- | --- |
| Composer packages | Dependabot alerts and security updates (GitHub's advisory database) | when an advisory is published | Dependabot alert and pull request |
| Composer packages | `composer audit` (Packagist: GitHub's and FriendsOfPHP's advisories, abandoned packages) | every CI run, and in the watch | failed CI run; issue per advisory |
| Composer packages | `composer outdated`: minor and major updates | in the watch | one issue listing them |
| GitHub Actions | Dependabot | alerts at once, updates monthly | Dependabot pull request |
| npm packages of the client tests (`tests/Clients`, not shipped) | Dependabot alerts and security updates | when an advisory is published | Dependabot alert and pull request |
| Vaultwarden releases | GitHub API | in the watch | issue per release after the pin |
| Vaultwarden advisories | GitHub API | in the watch | issue per advisory |
| Vaultwarden `main` | `git` in the reference checkout | in the watch | one issue while `main` is ahead of the pin |
| Web vault | bw_web_builds releases, Vaultwarden's `docker/DockerSettings.yaml` | in the watch | issue while a newer build exists |
| PHP | php.net's release feed: the oldest branch `composer.json` allows and the newest of its major version | in the watch | issue per security release |
| Rust crates we reproduce | OSV (RustSec and GitHub), for the versions in the pinned `Cargo.lock` | in the watch | issue per advisory |

The watch is `php artisan parity:watch`, run by the [Watch workflow](../.github/workflows/watch.yml).
Its sources are in `app/Parity/Watch/Sources`. Not used: Renovate (a further service where Dependabot
is enough) and CodeQL (no PHP).

### Why releases matter more than advisories

Vaultwarden publishes its advisories weeks after the release that fixes them: 1.37.0 came out on
24 July 2026, its eleven advisories on 3 October; 1.37.4 on 5 October, its seven advisories on
28 October. The fixes land on `main` under plain titles. The early signs are the release notes, whose
"Security Fixes" section names the still private advisories, and the commits themselves. The watch
reports both, and an advisory only asks to confirm what the port should already do.

## How the watch reports

One GitHub issue per finding, labelled `watch` and one of:

- `upstream`: a change in Vaultwarden to port
- `upstream-security`: a Vaultwarden release with security fixes, or a published advisory
- `security`: an advisory for something Kennword depends on
- `dependencies`: dependency updates (Dependabot uses it too)

A hidden comment at the end of each issue holds the finding's key. The issues are the watch's memory:
a new finding opens an issue, a changed one updates it, and nothing is reported twice. Issues of
findings that can resolve themselves (an advisory for a locked package, the list of updates, `main`
ahead of the pin, a release or web vault after the pin) close with a comment once the watch no longer
reports them, and open again if it does. To silence one for good, label it `wontfix` and close it.
All other issues are closed by a maintainer.

GitHub tells the repository's watchers about new issues and Dependabot alerts in the usual way, in
the web and by mail to the address the account has at GitHub. A failed run (a source could not be
read) is a failed workflow run, which GitHub reports to whoever last changed the schedule. Nothing
else is sent anywhere.

### Privacy

The watch only handles public data: package names and versions, published advisories, upstream
commit hashes and titles. It leaves out who wrote a commit or reported an advisory, and it breaks
`@` mentions in upstream text so that nobody is notified. It needs no secret but the workflow's own
`GITHUB_TOKEN`.

Issues in this repository are public. The watch's issues only repeat what is public already and never
say that Kennword is vulnerable. If the check an issue asks for shows that it is, the fix goes the
private way [SECURITY.md](../SECURITY.md) describes, and the issue is closed without details.

## What happens on its own, and what waits

On its own:

- Dependabot opens pull requests for security updates of any size, one grouped pull request a week
  for patch updates of Composer packages, and one a month for GitHub Actions
  ([dependabot.yml](../.github/dependabot.yml)). Their CI runs the tests, `composer audit` and, since
  `composer.lock` changed, the comparison with Vaultwarden (`reference.yml`).
- The watch opens, updates and closes its issues.

Always waits for a maintainer:

- merging any pull request, and pushing to `main`
- minor and major updates (listed in an issue, no pull request)
- moving the pin
- publishing advisories of our own, and releases
- turning a schedule on or off

Nothing is merged automatically, not even patches: Kennword's worth is behaving exactly like
Vaultwarden, and a patch of a library can change an answer. When an update adds or removes a package,
`NoticeTest` fails until NOTICE.md lists it; such a pull request needs that change by hand. A release
built from a `composer.lock` with an advisory needs a new release.

## Response times

| Case | Target |
| --- | --- |
| Vaultwarden release with security fixes, or a High or Critical advisory the pin does not contain | look at it the same or next working day; port, test and move the pin within two working days |
| the same, Medium or Low | one week |
| advisory for a fix the pin already contains | confirm the port within a week, with a regression test |
| advisory for a package we lock | merge the update within two working days |
| other upstream changes | move the pin with each Vaultwarden release, within about two weeks, not with every commit |
| new web vault | comes with the pin; if a security fix cannot wait for Vaultwarden, a maintainer decides |

## Moving the pin

`php artisan parity:upstream [revision]` fetches a branch, tag or commit of Vaultwarden into the
reference checkout and lists what changed since the pin: the commits, the parity items whose source
changed and our counterparts of the other changed functions (found by name, `post_attachment_v2` →
`postAttachmentV2`). `parity:generate` only shows items that were added or removed; a changed item
keeps its status, so this list is how changed behaviour gets noticed. Commits whose titles suggest a
security fix are marked, as a hint for the order of work, not as a filter.

1. `php artisan parity:upstream <release>`, and keep the list.
2. Update `parity/reference.json`: commit, release and, when Vaultwarden ships a new web vault,
   `web_vault`, `web_vault_digest` and the source tags in `web_vault_source` (NoticeTest fails until
   NOTICE.md names the new tags). Then `parity:fetch`, `parity:sync` and `parity:generate` (see
   AGENTS.md). The commit is also named in `README.md`, `NOTICE.md` (modification notice) and
   `docs/configuration.md` (link to `.env.template`).
3. Work through the added and removed items and through the list from step 1, security fixes first.
   Every fix gets a test.
4. Push. The Reference workflow builds the new Vaultwarden and compares: differences show behaviour
   that is not ported yet. Commit its `parity-schema` artifact.

The watch's issues about that release and about `main` close themselves after the next run.

## Running and changing the watch

- `GH_TOKEN=$(gh auth token) php artisan parity:watch -v` shows every finding with its issue text and
  changes nothing. `--source=vaultwarden-main` (and so on) runs only some sources; `--issues` also
  keeps the issues, in `$GITHUB_REPOSITORY` or with `--repository=owner/name`.
- The Watch workflow starts by hand (Actions → Watch → Run workflow). Its schedule, twice a day at
  about 5:17 and 17:17 UTC, is commented out until a maintainer turns it on. GitHub turns schedules
  off in repositories without activity for 60 days; a workflow run turns it back on.
- Vaultwarden advisories published before 29 October 2026 have no issue of their own
  (`VaultwardenAdvisories::SINCE`); see below.
- A new crate in NOTICE.md's list of reproduced crates belongs in `RustCrates::CRATES`; a test fails
  until it is there.

## Later

Agreed as later steps, not set up yet:

- An advisory register: `parity/advisories.json` with every Vaultwarden advisory and its status, and
  tests that carry `#[Advisory('GHSA-…')]`, enforced like `#[Parity]`. It starts with the backlog: the
  37 advisories published up to 28 October 2026, all fixed in or before the pinned 1.37.4, but not
  confirmed for the port one by one.
- A scheduled Claude routine that looks at new `upstream` issues, compares Vaultwarden's change with
  our code, comments its assessment and opens draft pull requests for security fixes. It never merges.
- A workflow that moves the pin on a branch and opens a draft pull request with the list of
  `parity:upstream`.
