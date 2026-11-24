// Evaluate retained GitHub REST responses. Fetching/authenticating their provenance
// remains the independent reproducer's duty; a hand-written JSON file is not CI proof.
export const REQUIRED_JOBS = Object.freeze([
  'msrv','rust','postgres','postgres-isolation','linux-package','selfhosted-identity',
  'test (3.11)','test (3.12)','test (3.13)','release-required','dependency-audit',
]);
const REQUIRED_STEPS = {
  'dependency-audit':['Audit locked dependency advisories'],
  'release-required':['Require every qualification job'],
  msrv:['Check declared minimum Rust toolchain'],
  rust:['Format and lint','Required real-cluster and SDK integration tests',
    'Package and verify managed Linux core executables',
    'Require native release preflight under separate kernel UIDs',
    'Require disposable installed systemd lifecycle and sandbox smoke',
    'Require protected ledger credential renewal under systemd',
    'Require exact-release live SQL COMMIT and query recovery under systemd'],
  postgres:['Require peer SQL, custody, fresh SDK and combined failure qualification',
    'Require isolated real drain, controller process faults and SQL recovery',
    'Require cold physical SQL backup and stale restore refusal'],
  'postgres-isolation':['Require separate accounts and live authenticated target probes'],
  'linux-package':['Verify staged units, system accounts and kernel file boundaries'],
  'selfhosted-identity':['Require actual provider issuance and native verification',
    'Require fresh shipping SQL and official SDK recovery with actual providers',
    'Require managed providers to separate systemd roles and SDK agent',
    'Require actual issuer rollover and shipping broker withdrawal/restore refusal',
    'Require cold provider storage restore and stale issuer refusal',
    'Require SPIRE JWT and X.509 issuer rollover'],
};
for (const version of ['3.11','3.12','3.13']) REQUIRED_STEPS[`test (${version})`] = [
  'Verify frozen paper and protocol contracts','Run linter (ruff)',
  'Run type checking (mypy)','Validate pilot infrastructure','Run tests (pytest)','Run demo scripts',
];
export function verifyCI(record, source) {
  const gaps = [], gap = reason => gaps.push(reason);
  if (!record || !/^[a-f0-9]{40}$/.test(source ?? '')) return ['required_ci_inputs'];
  const {run, jobs: page} = record;
  if (!run || !page || !Array.isArray(page.jobs)) return ['required_ci_records'];
  if (run.repository?.full_name !== 'openkedge/kedgeflow'
    || run.path !== '.github/workflows/ci.yml' || run.head_sha !== source
    || !Number.isSafeInteger(run.id) || run.id <= 0
    || !Number.isSafeInteger(run.run_attempt) || run.run_attempt <= 0) gap('ci_source_or_run_binding');
  if (run.status !== 'completed' || run.conclusion !== 'success') gap('ci_not_successful');
  const jobs = page.jobs;
  if (page.total_count !== jobs.length || jobs.length > 100) gap('ci_job_page_incomplete');
  if (new Set(jobs.map(j=>j.name)).size !== jobs.length
    || new Set(jobs.map(j=>j.id)).size !== jobs.length) gap('ci_duplicate_job');
  for (const name of REQUIRED_JOBS) {
    const j = jobs.find(j=>j.name === name);
    if (!j) {gap('ci_missing_job:'+name); continue;}
    if (j.run_id !== run.id || j.head_sha !== source || j.run_attempt !== run.run_attempt) {
      gap('ci_job_binding:'+name);
    }
    if (j.status !== 'completed' || j.conclusion !== 'success') gap('ci_job_not_passed:'+name);
    if (!Array.isArray(j.steps)) {gap('ci_missing_steps:'+name); continue;}
    for (const step of REQUIRED_STEPS[name]) {
      const matches = j.steps.filter(s=>s.name === step);
      if (matches.length !== 1 || matches[0].status !== 'completed'
        || matches[0].conclusion !== 'success') gap('ci_required_step_not_passed:'+name+':'+step);
    }
    for (const s of j.steps) {
      // GitHub can skip a cleanup hook when setup created no cache. Test and
      // qualification steps never receive this exception.
      if (s.status !== 'completed' || (s.conclusion !== 'success'
        && !(s.name?.startsWith('Post ') && s.conclusion === 'skipped'))) {
        gap('ci_unexpected_step_result:'+name+':'+s.name);
      }
    }
  }
  return gaps;
}
export {REQUIRED_STEPS};
