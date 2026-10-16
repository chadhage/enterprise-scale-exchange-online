# Candidate verification and artifact promotion

`verify.yml` checks pull requests, merge-queue candidates and manual requests. Its
aggregate **Verify** job is fail-closed: every prerequisite job and every selected
test container must succeed. A skipped, undiscovered, missing or partially run
test is not a passing result. There are no automatic test retries or waived
failures.

## Where each check belongs

| Stage | Checks |
| --- | --- |
| Candidate plan | Exact Git source-tree identity; conservative change selection |
| Offline verification | Active Pester containers, once each, distributed over four Windows shards; fresh process per container |
| Source and package | PowerShell parsing/analyzer errors, whitespace, explicit site staging, extracted ZIP imports/configuration/required files |
| Browser | Chromium against the already staged site: wizard gates, generated scope, invalidation, refresh, document rendering and packaged resources |
| Aggregate | Exact container inventory, counters, input hashes and tool versions; machine-readable receipt and bundle digests |
| Pages publication | Validate and promote the verified site bytes; small deployed-version/resource smoke |
| Kit publication | Require full verification, validate and upload the verified ZIP/checksum; download and compare published bytes |

PowerShell/Pester/analyzer versions are defined in `tools.psd1`. Node 22 and the
locked Playwright dependency are used in CI. Actions are pinned to immutable
revisions. Normal verification needs no tenant credentials, production certificate,
ExchangeOnlineManagement installation or live Exchange mutation.

Only changes entirely inside `microsite/` may use the site-only Pester selection,
and only when the base tree already has an unexpired successful **full**
verification artifact. Otherwise selection is full. Documentation, shared
fixtures/modules, workflows, CI tooling and unknown changes all select full.
The site lane still checks packaging and the rendered browser behavior.

The existing `unit`/`integration` folder names are not assumed to describe
execution cost: public-command subprocesses, genuine CMS operations and workflow
tests remain real tests. Process isolation prevents global doubles and forced
module imports leaking between containers. Connection-module coverage is collected
in its existing container, not by running that container again. Coverage is
diagnostic, not a claim of repository-wide coverage or a fabricated percentage gate.

## Run locally

From the repository root in PowerShell:

```powershell
./.github/ci/Install-Tools.ps1
node .github/ci/pipeline.mjs plan
if ($LASTEXITCODE -ne 0) { throw 'Planning failed.' }
./.github/ci/Invoke-OfflineTests.ps1
```

Use a focused Pester container while developing a specific change. Do not run that
focused selection again immediately before the complete runner merely to repeat
the same checks. The runner emits per-container NUnit XML, JSON, logs and shard
summaries in `.artifacts/results`. CI retains failure diagnostics for 30 days.
Tool installation prepends a repository-local module directory to `PSModulePath`.

On a clean staging directory, package and browser checks are:

```powershell
./.github/ci/Test-Source.ps1
./.github/ci/Build-Artifacts.ps1
Push-Location .github/ci
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    npm test
    if ($LASTEXITCODE -ne 0) { throw 'Gate contracts failed.' }
    npx playwright install chromium
    if ($LASTEXITCODE -ne 0) { throw 'Browser installation failed.' }
    npm run test:browser
    if ($LASTEXITCODE -ne 0) { throw 'Browser checks failed.' }
}
finally { Pop-Location }
```

The builder refuses to overwrite an existing `.artifacts/bundle`. Use a fresh
worktree/staging directory for another candidate. The local HTTP server serves
only staged bytes; it never copies missing files from the source checkout.

## Promotion and trust

Successful verification uploads `verified-<scope>-<Git-tree>` for 90 days. Pages
and release workflows search for that exact immutable input set. Reuse requires
a successful allowlisted workflow in this repository whose GitHub-reported head
commit resolves to the same Git tree. Artifact labels, arbitrary receipts and
dependency caches alone are not evidence. If the available run metadata cannot
prove the tree binding, or artifacts expired, verification runs again.

The receipt binds the full bundle inventory and SHA256 of every file. Publication
checks those hashes before using any bytes, including `.nojekyll`. It does not
rebuild, rerun the offline suite, or transform the verified site/ZIP. Tree identity
allows reuse after a squash or merge that preserves the tested source tree even
when the commit identifier changes. A changed merge result requires verification.

Release publication accepts only existing version tags reachable from `main`,
requires **full** verification, refuses replacing existing assets and rechecks
the tag before publication. It does not create tags. Pages publication is limited
to `main`. Write/OIDC permissions exist only in the publishing jobs.

## Repository administration and qualification

After the workflow exists and its full baseline is green, configure branch/ruleset
protection to require the aggregate **Verify** check, require the branch to be
current (or use the merge queue), and prevent direct bypass pushes to `main`.
Workflow files alone cannot enforce merge protection. Configure the `github-pages`
environment to allow deployments only from `main`.

Do not enable publication around a red baseline or narrow selection to hide legacy
failures. Fix failing source/fixtures using their retained evidence. Do not repeat
the entire suite on every OS or after publication. Additional supported-runtime
checks and the backlog's bounded three-run order/determinism qualification are
separate maintenance work, not three full runs per commit. This pipeline does not
claim cross-runtime qualification, live service compatibility, or order independence.
