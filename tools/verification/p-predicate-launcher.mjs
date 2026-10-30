/** Node owns the actual monitor ChildProcess; Python is its sibling controller.
 * No product/GUI process executes when a spawn double is supplied by pure tests.
 */
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

function requireThat(value, reason) { if (!value) throw new Error(reason); }
function collect(child, maximum) {
  let data = Buffer.alloc(0);
  child.stdout?.on('data', chunk => {
    data = Buffer.concat([data, chunk]);
    if (data.length > maximum) { data = Buffer.alloc(0); child.stdout.destroy(new Error('bounded controller output')); }
  });
  return () => data;
}
function wait(child) {
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
}

export async function runPredicateCase(contract, kind, {spawnProcess = spawn, ownerPid = process.pid} = {}) {
  requireThat(['term','normal143','controller-death'].includes(kind), 'closed predicate case');
  const fixtureMode = spawnProcess !== spawn;
  const fixedCase = kind === 'normal143' ? 'normal143' : 'term';
  const monitor = spawnProcess(contract.argv[0], [...contract.argv.slice(1), fixedCase],
    {stdio: ['ignore','ignore','ignore'], shell: false});
  const monitorWait = wait(monitor); // Node is the sole actual wait-status owner.
  const controller = spawnProcess(contract.python, ['-I','-S',contract.script,'controller'],
    {stdio: ['pipe','pipe','ignore'], shell: false});
  const controllerWait = wait(controller);
  const output = collect(controller, 65536);
  controller.stdin.end(JSON.stringify({...contract,case:kind,nodePid:ownerPid,monitorPid:monitor.pid}));
  let timer;
  try {
    const [controlStatus, monitorStatus] = await Promise.race([
      Promise.all([controllerWait,monitorWait]),
      new Promise((_, reject) => { timer=setTimeout(()=>reject(new Error('outer discovery/transaction deadline')), 52000); })
    ]);
    if (kind === 'controller-death') {
      requireThat(controlStatus.code === 73 && controlStatus.signal === null, 'controller-death negative not observed');
      // Watchdog CONT then SIGKILL of the ORIGINAL held application pidfd lets
      // the still-owned monitor consume SIGCHLD and exit normally 128+9.
      requireThat(monitorStatus.code === 137 && monitorStatus.signal === null, 'watchdog resume/exact-app cleanup not observed');
      const observed=JSON.parse(output().toString('utf8'));
      requireThat(observed.phase==='stopped-before-controller-death' && observed.ownerNodePid===ownerPid &&
        observed.monitor.pid===monitor.pid && observed.controllerPid===controller.pid &&
        observed.siblingParentBound===true && observed.application.ppid===monitor.pid &&
        observed.watchdogArmed?.[0]?.op==='ARMED', 'pre-death graph/STOP/ARM observation missing');
      return {case:kind,fixtureMode,admitting:false,predicateWitness:false,guiQualification:false,
        ownerNodePid:ownerPid,monitorPid:monitor.pid,controllerPid:controller.pid,
        controllerStatus:controlStatus,monitorWaitStatus:monitorStatus,
        nodeOwnerAlive:true,preDeathObservation:observed,
        recovery:'controller-death-only; watchdog resume followed by exact-app failure cleanup'};
    }
    requireThat(controlStatus.code === 0 && controlStatus.signal === null, 'controller refused');
    requireThat(monitorStatus.code === 143 && monitorStatus.signal === null, 'actual Node-owned monitor wait status must be normal143');
    const result=JSON.parse(output().toString('utf8'));
    requireThat(result.ownerNodePid===ownerPid && result.monitor.pid===monitor.pid &&
      result.controllerPid===controller.pid && result.siblingParentBound===true &&
      result.monitorWaitStatusOwner==='Node', 'controller ownership binding');
    requireThat(kind==='term' ? result.witness.exit_code===15 : result.witness.negativeRejected===true,
      'predicate/negative witness mismatch');
    return {...result,fixtureMode,admitting:false,guiQualification:false,monitorWaitStatus:monitorStatus};
  } finally {
    clearTimeout(timer);
    // No numeric/process-group cleanup fallback. On CLI failure Node exits;
    // unchanged --die-with-parent is containment, never a passing recovery.
    monitor.unref?.(); controller.unref?.();
  }
}

export async function runProbe(contract, options) {
  const cases=[];
  for (const kind of ['term','normal143','controller-death']) cases.push(await runPredicateCase(contract,kind,options));
  return {mode:options?.spawnProcess?'fixture-mode':'native-predicate-only',
    fixtureMode:Boolean(options?.spawnProcess),publicationAuthority:false,guiQualification:false,cases};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    requireThat(process.argv.length===3,'expected sealed contract path');
    const bytes=readFileSync(process.argv[2]); requireThat(bytes.length<=65536,'sealed contract bound');
    console.log(JSON.stringify(await runProbe(JSON.parse(bytes))));
  } catch {
    console.error('P predicate route refused; no native or GUI acceptance.');
    process.exit(1); // Node death invokes existing bwrap containment.
  }
}
