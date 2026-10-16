import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, lstatSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const root = fileURLToPath(new URL('../..', import.meta.url));
const bundle = path.join(root, '.artifacts', 'bundle');
const planPath = path.join(root, '.artifacts', 'ci', 'plan.json');
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const hash = file => createHash('sha256').update(readFileSync(file)).digest('hex');
const json = file => JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
const save = (file, value) => {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
};

export function inventory(directory) {
  return readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))
    .flatMap(entry => {
      const file = path.join(directory, entry.name);
      if (lstatSync(file).isSymbolicLink()) throw new Error(`Symlinks are not allowed: ${file}`);
      return entry.isDirectory() ? inventory(file) : [file];
    });
}

export function selectScope(changed, forceFull = false) {
  return !forceFull && changed.length > 0 && changed.every(file => file.startsWith('microsite/'))
    ? 'site' : 'full';
}

export function assertReports(plan, reports) {
  const expected = new Set(plan.tests);
  if (!expected.size || expected.size !== plan.tests.length || reports.length !== expected.size) {
    throw new Error('Missing, duplicate or additional test containers');
  }
  for (const report of reports) {
    if (!expected.delete(report.file)) throw new Error(`Unexpected or duplicate container: ${report.file}`);
    for (const field of ['total', 'passed', 'failed', 'failedContainers', 'skipped', 'notRun', 'invocationExit']) {
      if (!Number.isInteger(report[field]) || report[field] < 0) throw new Error(`Invalid result field: ${field}`);
    }
    if (report.complete !== true || !report.total || report.total !== report.passed ||
        report.failed || report.failedContainers || report.skipped || report.notRun || report.invocationExit ||
        report.inputHash !== plan.testHashes[report.file] || report.pester !== '5.7.1' ||
        !Array.isArray(report.tests) || report.tests.length !== report.total ||
        report.tests.some(test => !test.name || test.result !== 'Passed')) {
      throw new Error(`Failed or incomplete container: ${report.file}`);
    }
  }
}

export function validateReceipt(directory, tree, requireFull = false) {
  const receipt = json(path.join(directory, 'verification.json'));
  if (receipt.schema !== 1 || receipt.tree !== tree || receipt.dirty !== false ||
      !['site', 'full'].includes(receipt.scope) || (requireFull && receipt.scope !== 'full') ||
      !receipt.checks || ['offline', 'source', 'package', 'browser'].some(key => receipt.checks[key] !== true)) {
    throw new Error('Artifact is not a verified candidate for these inputs');
  }
  const files = inventory(directory).filter(file => file !== path.join(directory, 'verification.json'));
  if (!receipt.files || Object.keys(receipt.files).length !== files.length) throw new Error('Artifact inventory mismatch');
  for (const file of files) {
    const relative = path.relative(directory, file).split(path.sep).join('/');
    if (receipt.files[relative] !== hash(file)) throw new Error(`Artifact digest mismatch: ${relative}`);
  }
  return receipt;
}

function createPlan() {
  const base = process.env.CI_BASE;
  const changed = base ? git('diff', '--name-only', '-z', base, 'HEAD').split('\0').filter(Boolean) : [];
  let scope = selectScope(changed, process.env.CI_FULL === 'true');
  let baseline = null;
  if (scope === 'site') {
    const baseTree = git('rev-parse', `${base}^{tree}`);
    baseline = process.env.GITHUB_REPOSITORY ? findVerifiedArtifact(baseTree, true, githubApi) : null;
    if (!baseline) scope = 'full';
  }
  const sampleTests = path.join(root, 'samples', 'contoso-exchange-online-managed-service', 'tests');
  const tests = inventory(sampleTests).filter(file => file.endsWith('.Tests.ps1'))
    .filter(file => scope === 'full' || path.basename(file) === 'MicrositeContent.Tests.ps1')
    .map(file => path.relative(root, file).split(path.sep).join('/')).sort();
  const plan = {
    schema: 1, commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}'),
    dirty: git('status', '--porcelain', '--untracked-files=no').length > 0,
    scope, baseline, tests, testHashes: Object.fromEntries(tests.map(file => [file, hash(path.join(root, file))])),
  };
  if (process.env.GITHUB_ACTIONS === 'true' && plan.dirty) throw new Error('CI source checkout is dirty');
  save(planPath, plan);
  if (process.env.GITHUB_OUTPUT) {
    for (const [name, value] of Object.entries({ tree: plan.tree, scope, artifact: `verified-${scope}-${plan.tree}` })) {
      writeFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`, { flag: 'a' });
    }
  }
  console.log(`Selected ${tests.length} test containers (${scope}); tree ${plan.tree}`);
}

export function assertShards(plan, summaries) {
  const shards = new Set(summaries.map(summary => summary.shard));
  if (shards.size !== 4 || summaries.length !== 4 ||
      summaries.some(summary => summary.shardCount !== 4 || ![0, 1, 2, 3].includes(summary.shard))) {
    throw new Error('Missing or duplicate verification shards');
  }
  const reports = summaries.flatMap(summary => summary.reports);
  assertReports(plan, reports);
  return reports;
}

function finalize() {
  const plan = json(planPath);
  if (plan.tree !== git('rev-parse', 'HEAD^{tree}') || plan.commit !== git('rev-parse', 'HEAD') ||
      git('status', '--porcelain', '--untracked-files=no')) {
    throw new Error('Source identity changed during verification');
  }
  const summaries = inventory(path.join(root, '.artifacts', 'results'))
    .filter(file => /^summary-\d+\.json$/.test(path.basename(file))).map(json);
  const reports = assertShards(plan, summaries);
  for (const [file, expected] of Object.entries(plan.testHashes)) {
    if (hash(path.join(root, file)) !== expected) throw new Error(`Test changed during verification: ${file}`);
  }
  const receipt = {
    schema: 1, commit: plan.commit, tree: plan.tree, dirty: plan.dirty, scope: plan.scope,
    runId: process.env.GITHUB_RUN_ID ?? 'local',
    checks: { offline: true, source: true, package: true, browser: true },
    tests: { containers: reports.length, passed: reports.reduce((sum, report) => sum + report.passed, 0) },
    files: Object.fromEntries(inventory(bundle).map(file => [
      path.relative(bundle, file).split(path.sep).join('/'), hash(file),
    ])),
  };
  save(path.join(bundle, 'verification.json'), receipt);
  validateReceipt(bundle, plan.tree, plan.scope === 'full' && !plan.dirty);
}

function githubApi(endpoint) {
  return JSON.parse(execFileSync('gh', ['api', endpoint], { encoding: 'utf8' }));
}

export function findVerifiedArtifact(tree, requireFull, api, repository = process.env.GITHUB_REPOSITORY) {
  if (!repository) throw new Error('GITHUB_REPOSITORY is required');
  let found = null;
  for (const scope of requireFull ? ['full'] : ['full', 'site']) {
    const name = `verified-${scope}-${tree}`;
    const artifacts = api(`repos/${repository}/actions/artifacts?name=${name}&per_page=30`).artifacts;
    for (const artifact of artifacts.filter(item => !item.expired)) {
      const run = api(`repos/${repository}/actions/runs/${artifact.workflow_run.id}`);
      if (run.conclusion === 'success' && ['pull_request', 'push', 'merge_group', 'workflow_dispatch'].includes(run.event) && [
        '.github/workflows/verify.yml', '.github/workflows/deploy-pages.yml', '.github/workflows/release-kit.yml',
      ].includes(run.path) && run.repository.full_name === repository &&
          api(`repos/${repository}/git/commits/${run.head_sha}`).tree.sha === tree) {
        found = { run: run.id, artifact: name };
        break;
      }
    }
    if (found) break;
  }
  return found;
}

function findCandidate(requireFull) {
  const tree = git('rev-parse', 'HEAD^{tree}');
  const found = findVerifiedArtifact(tree, requireFull, githubApi);
  if (process.env.GITHUB_OUTPUT) {
    for (const [key, value] of Object.entries({
      commit: git('rev-parse', 'HEAD'), tree, run: found?.run ?? '',
      artifact: found?.artifact ?? `verified-full-${tree}`,
    })) {
      writeFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`, { flag: 'a' });
    }
  }
  console.log(found ? `Reusing verified candidate ${found.run}` : 'No matching verified candidate; verification is required');
}

async function smoke(url, tree) {
  for (const relative of ['version.json', 'index.html', 'script.js', 'styles.css', 'docs/APPROVED-CHANGE.md']) {
    const response = await fetch(new URL(`${relative}?tree=${tree}`, `${url.replace(/\/$/, '')}/`), {
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`Published resource unavailable: ${relative} (${response.status})`);
    if (relative === 'version.json' && (await response.json()).sourceTree !== tree) {
      throw new Error('Published site is not the verified source tree');
    }
  }
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'plan') createPlan();
  else if (command === 'finalize') finalize();
  else if (command === 'find') findCandidate(args[0] === 'full');
  else if (command === 'validate') validateReceipt(path.resolve(args[0]), args[1], args[2] === 'full');
  else if (command === 'smoke') await smoke(args[0], args[1]);
  else throw new Error(`Unknown pipeline command: ${command}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
