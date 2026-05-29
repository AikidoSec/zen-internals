# zen-internals Release Process

## 1. Before the release

Ensure that all tests are passing on the main branch and that the code is ready for release.
Check what changes were made since the last release and prepare a short changelog to be included in the release description.
Also, ensure you are prepared to test all changes in at least one Zen agent after the release.

## 2. Create a version tag

Create a new tag with a leading `v` followed by the version number using `git tag` (e.g. `git tag v1.0.0`) and push the tag to the repository using `git push origin v1.0.0`.
This will trigger the release workflow that will build the binaries and create the GitHub release.

## 3. Monitor release workflow

Monitor [the workflow](https://github.com/AikidoSec/zen-internals/actions/workflows/publish.yml) for any errors and ensure that the release is published successfully.

## 4. After the release

Update the description of the GitHub release with the human readable changelog you prepared in step 1.
Test the new release by updating the used Zen internals version in at least one Zen agent and ensuring that all changes are working as expected.
Because the Zen internals version is pinned in all Zen agents, it will not automatically be picked up by the agents.
