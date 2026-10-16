import assert from 'node:assert/strict';
import { test } from 'node:test';
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { root, assertReports, assertShards, selectScope, validateReceipt, findVerifiedArtifact } from './pipeline.mjs';

test('only changes confined to the microsite may narrow selection', () => {
  assert.equal(selectScope([]), 'full');
  assert.equal(selectScope(['microsite/styles.css']), 'site');
  assert.equal(selectScope(['microsite/styles.css'], true), 'full');
  for (const file of ['README.md', '.github/ci/pipeline.mjs', 'samples/example/docs/guide.md', 'unknown']) {
    assert.equal(selectScope(['microsite/styles.css', file]), 'full');
  }
});

const plan = { tests: ['a.Tests.ps1'], testHashes: { 'a.Tests.ps1': 'abc' } };
const good = {
  file: 'a.Tests.ps1', inputHash: 'abc', total: 1, passed: 1, failed: 0, failedContainers: 0,
  skipped: 0, notRun: 0, invocationExit: 0, complete: true, pester: '5.7.1',
  tests: [{ name: 'contract', result: 'Passed' }],
};
for (const [field, value] of Object.entries({
  total: 0, passed: 0, failed: 1, failedContainers: 1, skipped: 1, notRun: 1, invocationExit: 1,
  complete: false, inputHash: 'changed', pester: '6.0.0', tests: [],
})) {
  test(`gate refuses ${field} drift`, () => assert.throws(() => assertReports(plan, [{ ...good, [field]: value }])));
}
test('gate refuses missing, duplicate, additional and malformed containers', () => {
  for (const reports of [[], [good, good], [{ ...good, file: 'other' }], [{ ...good, total: '1' }]]) {
    assert.throws(() => assertReports(plan, reports));
  }
});
test('gate accepts the exact complete selection', () => assert.doesNotThrow(() => assertReports(plan, [good])));

test('promotion requires matching identity, successful checks and unchanged artifact bytes', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'exchange-ci-'));
  try {
    mkdirSync(path.join(directory, 'site'));
    writeFileSync(path.join(directory, 'site', 'version.json'), '{}');
    const receipt = {
      schema: 1, tree: 'tree', scope: 'full', dirty: false,
      checks: { offline: true, source: true, package: true, browser: true },
      files: { 'site/version.json': createHash('sha256').update('{}').digest('hex') },
    };
    const save = value => writeFileSync(path.join(directory, 'verification.json'), JSON.stringify(value));
    for (const changed of [
      { tree: 'other' }, { dirty: true }, { dirty: undefined }, { scope: 'site' }, { checks: { ...receipt.checks, browser: false } },
      { files: {} },
    ]) {
      save({ ...receipt, ...changed });
      assert.throws(() => validateReceipt(directory, 'tree', true));
    }
    save(receipt);
    assert.doesNotThrow(() => validateReceipt(directory, 'tree', true));
    writeFileSync(path.join(directory, 'site', 'verification.json'), '{}');
    assert.throws(() => validateReceipt(directory, 'tree', true));
    rmSync(path.join(directory, 'site', 'verification.json'));
    writeFileSync(path.join(directory, 'site', 'version.json'), 'tampered');
    assert.throws(() => validateReceipt(directory, 'tree', true));
  } finally {
    rmSync(directory, { recursive: true });
  }
});

test('aggregation requires all four distinct shards and the complete planned selection', () => {
  const summaries = [0, 1, 2, 3].map(shard => ({ shard, shardCount: 4, reports: shard === 0 ? [good] : [] }));
  assert.deepEqual(assertShards(plan, summaries), [good]);
  for (const changed of [
    summaries.slice(1),
    [...summaries, summaries[0]],
    summaries.map(summary => ({ ...summary, shard: 0 })),
    summaries.map(summary => ({ ...summary, shardCount: 3 })),
    summaries.map(summary => ({ ...summary, reports: [] })),
  ]) assert.throws(() => assertShards(plan, changed));
  assert.throws(() => assertReports(plan, [{ ...good, complete: 'true' }]));
  assert.throws(() => assertReports({ ...plan, tests: [plan.tests[0], plan.tests[0]] }, [good]));
});

test('reuse requires successful trusted workflow metadata bound to the actual source tree', () => {
  const run = {
    id: 7, conclusion: 'success', event: 'pull_request', path: '.github/workflows/verify.yml',
    repository: { full_name: 'owner/repo' }, head_sha: 'commit',
  };
  function lookup(changes = {}, artifactChanges = {}, actualTree = 'tree') {
    return findVerifiedArtifact('tree', true, endpoint => {
      if (endpoint.includes('/actions/artifacts?')) {
        return { artifacts: [{ expired: false, workflow_run: { id: 7 }, ...artifactChanges }] };
      }
      if (endpoint.includes('/git/commits/')) return { tree: { sha: actualTree } };
      return { ...run, ...changes };
    }, 'owner/repo');
  }
  for (const changes of [
    { conclusion: 'failure' }, { conclusion: null }, { path: '.github/workflows/unrelated.yml' },
    { repository: { full_name: 'another/repo' } }, { event: 'pull_request_target' },
  ]) assert.equal(lookup(changes), null);
  assert.equal(lookup({}, { expired: true }), null);
  assert.equal(lookup({}, {}, 'forged-source'), null);
  assert.deepEqual(lookup(), { run: 7, artifact: 'verified-full-tree' });
});

test('real isolated runner fails closed on failing, empty, skipped and discovery-error containers', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'exchange-runner-'));
  try {
    for (const [name, content, success] of [
      ['failed', "Describe 'gate' { It 'fails' { 1 | Should -Be 2 } }", false],
      ['empty', '# no discovered tests', false],
      ['skipped', "Describe 'gate' { It 'skips' -Skip { 1 | Should -Be 1 } }", false],
      ['discovery', "BeforeAll { throw 'fixture unavailable' }; Describe 'gate' { It 'never passes' {} }", false],
      ['passed', "Describe 'gate' { It 'passes' { 1 | Should -Be 1 } }", true],
    ]) {
      const file = path.join(directory, `${name}.Tests.ps1`);
      const resultPath = path.join(directory, `${name}.json`);
      writeFileSync(file, content);
      const result = spawnSync('pwsh', [
        '-NoProfile', '-NonInteractive', '-File', path.join(root, '.github', 'ci', 'Invoke-OfflineTests.ps1'),
        '-TestFile', file, '-ResultPath', resultPath,
      ], { cwd: root, encoding: 'utf8', timeout: 60_000 });
      assert.ifError(result.error);
      assert.equal(result.status === 0, success, `${name}: ${result.stdout}\n${result.stderr}`);
      if (success) {
        const report = JSON.parse(readFileSync(resultPath, 'utf8').replace(/^\uFEFF/, ''));
        assert.equal(report.total, 1);
        assert.equal(report.complete, true);
      }
    }
  } finally {
    rmSync(directory, { recursive: true });
  }
});

test('parent runner rejects a successful process with no results and refuses stale outputs', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'exchange-parent-'));
  try {
    const file = path.join(directory, 'early-exit.Tests.ps1');
    const planPath = path.join(directory, 'plan.json');
    const output = path.join(directory, 'results');
    writeFileSync(file, 'exit 0');
    writeFileSync(planPath, JSON.stringify({ tests: [file] }));
    const run = () => spawnSync('pwsh', [
      '-NoProfile', '-NonInteractive', '-File', path.join(root, '.github', 'ci', 'Invoke-OfflineTests.ps1'),
      '-PlanPath', planPath, '-OutputRoot', output,
    ], { cwd: root, encoding: 'utf8', timeout: 60_000 });
    const early = run();
    assert.ifError(early.error);
    assert.notEqual(early.status, 0, `${early.stdout}\n${early.stderr}`);
    const summary = JSON.parse(readFileSync(path.join(output, 'summary-0.json'), 'utf8').replace(/^\uFEFF/, ''));
    assert.equal(summary.reports[0].complete, false);
    const stale = run();
    assert.ifError(stale.error);
    assert.notEqual(stale.status, 0);
    assert.match(`${stale.stdout}\n${stale.stderr}`, /Existing container output refused/);
  } finally {
    rmSync(directory, { recursive: true });
  }
});

test('tool bootstrap creates its module destination in a completely fresh checkout layout', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'exchange-bootstrap-'));
  try {
    const scripts = path.join(directory, '.github', 'ci');
    mkdirSync(scripts, { recursive: true });
    for (const name of ['Install-Tools.ps1', 'tools.psd1']) {
      copyFileSync(path.join(root, '.github', 'ci', name), path.join(scripts, name));
    }
    const moduleDirectory = path.join(directory, '.artifacts', 'modules');
    assert.equal(existsSync(moduleDirectory), false);
    const result = spawnSync('pwsh', [
      '-NoProfile', '-NonInteractive', '-File', path.join(scripts, 'Install-Tools.ps1'),
    ], { cwd: root, encoding: 'utf8', timeout: 60_000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(existsSync(moduleDirectory), true);
  } finally {
    rmSync(directory, { recursive: true });
  }
});
