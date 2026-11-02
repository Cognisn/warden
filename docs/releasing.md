# Releasing warden

warden is published to PyPI as [`cognisn-warden`](https://pypi.org/project/cognisn-warden/) by the workflow in `.github/workflows/publish.yml`. This document is the procedure for a maintainer. Nothing here is done by a contributor's pull request, and nothing is published without a maintainer's approval.

## How publication works

- **Trusted publishing, no tokens.** The workflow authenticates to PyPI and TestPyPI with GitHub's OpenID Connect token. No API token or password exists in the repository, its secrets or its environments. PyPI accepts an upload only from this repository, this workflow file and the named environment.
- **Two environments.** The `pypi` environment publishes to PyPI and requires a maintainer's approval in GitHub before the job runs. The `testpypi` environment publishes to TestPyPI.
- **What triggers what.**
  - A version tag (`v0.1.0rc1`, `v0.1.0`) builds, checks and verifies the distributions, then waits for approval in the `pypi` environment.
  - A manual run of the workflow (Actions, Release, Run workflow) does the same and publishes to TestPyPI. GitHub offers a manual run only once the workflow file is on the default branch.
  - A push to any branch runs the build, check and verify jobs as a dry run and publishes nothing.
- **What is checked before anything is published.**
  - The tag must name exactly the version in `src/warden/__init__.py`.
  - `twine check --strict` confirms the metadata and README render.
  - `.github/scripts/check_dist.py files` confirms there is one wheel and one sdist at that version, the wheel holds only the `warden` package and its metadata (with `py.typed`, `LICENSE` and `NOTICE`), and the sdist holds no `examples` directory. The sample console is not part of the package.
  - The wheel is installed into a clean environment on Python 3.12 and 3.13, outside the checkout, and every public module is imported from it (`check_dist.py imports`), then `warden --version` runs.
- **Pinned actions.** Every action is pinned to a commit SHA, and the build tools to exact versions. A tripwire test refuses an unpinned action; Dependabot proposes updates.

The same build and checks run in CI on every push (the `build` job), and `tests/packaging` builds both distributions and fails if either holds anything it should not.

## Versions and tags

- Versions follow Semantic Versioning with PEP 440 pre-release suffixes: `0.1.0a1`, `0.1.0b1`, `0.1.0rc1`, then `0.1.0`.
- The version lives only in `src/warden/__init__.py`; hatchling reads it from there.
- A tag is `v` followed by the version: `v0.1.0rc1`, `v0.1.0`.
- Alpha and beta builds are stamped on the release branch but not tagged or published. Release candidates and final releases are tagged and published.
- PyPI never accepts the same version twice, even after a deletion. A mistake is fixed with a new version, never by moving a tag.

## Releasing a version

Work on the release branch, `release/v<version>`, in a clean checkout.

1. **Confirm the branch is ready.** Every workstream for the release is merged, and CI is green on the branch tip:
   ```
   gh run list --branch release/v0.1.0 --limit 1
   ```
   For a release candidate, the release's gate in its plan has passed.
2. **Stamp the version.** The stamp script refuses any other branch or a version of another release:
   ```
   python scripts/bump_version.py 0.1.0rc1
   ```
   Move the `[Unreleased]` entries in `CHANGELOG.md` under a new heading for the version and date. Reinstall (`pip install -e ".[dev]"`), run the full suite and the checks, then commit as a separate step:
   ```
   git commit -m "chore: stamp 0.1.0rc1"
   git push origin release/v0.1.0
   ```
   Wait for CI to pass on the pushed commit.
3. **Optionally rehearse on TestPyPI.** Once the workflow is on the default branch, run it manually against the release branch and check the result at `https://test.pypi.org/project/cognisn-warden/`. TestPyPI also refuses a version it has seen, so rehearse each version once.
4. **Tag the stamp commit and push the tag.** Use an annotated tag:
   ```
   git tag -a v0.1.0rc1 -m "warden 0.1.0rc1"
   git push origin v0.1.0rc1
   ```
5. **Approve the deployment.** The Release run builds and verifies the distributions, then pauses at the `publish-pypi` job. Read the build and verify logs, then approve it in the run's page (Review deployments, `pypi`).
6. **Check the published package.**
   - The project page shows the version, the rendered README, the licence (Apache-2.0) and the links.
   - The files are one wheel (`py3-none-any`) and one sdist, each with a provenance attestation.
   - In a new virtual environment, outside any checkout:
     ```
     python -m pip install "cognisn-warden==0.1.0rc1"
     python -c "import warden; print(warden.__version__)"
     warden --version
     ```
     A pre-release is installed only when asked for by its exact version or with `--pre`.
7. **Merge a final release to `main` by squash.** Only a final version (no suffix) reaches `main`, and only when the maintainer says so:
   ```
   git switch main
   git pull
   git merge --squash release/v0.1.0
   git commit -m "chore: release 0.1.0"
   git diff v0.1.0 main --stat
   git push origin main
   ```
   The `git diff` must print nothing: `main` then holds exactly the tree that was published. Release candidates are never merged to `main`.
8. **Record the release.** Create a GitHub release for the tag, with the version's `CHANGELOG.md` section as its notes, marked as a pre-release for a release candidate.

## If something goes wrong

- **A check fails before approval.** Nothing has been published. Fix the cause on the release branch through the usual workstream process, stamp the next build (for example `0.1.0rc2`) and tag that. Delete the unpublished tag only if it was never published anywhere.
- **The wrong thing was published.** Yank the release on PyPI (it stays installable by exact version but is no longer chosen by default), fix it, and publish the next version. Never delete a release to reuse its number.
- **A security defect.** Follow `SECURITY.md`. Do not describe the defect in a commit message, tag, issue or release note until the fixed version is published.

## One-time set-up

These are done once by a repository administrator, and are not part of any release.

- The repository is public.
- On PyPI and on TestPyPI, a project `cognisn-warden` with a trusted publisher for repository `Cognisn/warden`, workflow `publish.yml`, and environment `pypi` (PyPI) or `testpypi` (TestPyPI). Before the first upload this can be a pending publisher, which creates the project on first use.
- In the repository's settings, the environments `pypi` and `testpypi`. `pypi` has required reviewers (the maintainers) and accepts deployments only from tags matching `v*`. `testpypi` accepts deployments only from the release branches and the default branch.
- Tag protection for `v*`, so only maintainers can create release tags.
- Private vulnerability reporting enabled, as `SECURITY.md` describes.
