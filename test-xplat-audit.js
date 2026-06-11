/* PADDLA cross-platform determinism audit (uvGs §10.5 platform-coverage).
 * Self-contained: integer-LCG input policies (engine-independent by construction),
 * full-state digest every 50 ticks (uvsHeader timestamp + rng internals excluded,
 * per core §3: inert metadata and diagnostics never enter a hash) + a results-only
 * digest (ticks + totalWin per session). Run the SAME file under different
 * runtimes/OSes; matching digests = byte-identical determinism on that axis.
 *
 *   node test-xplat-audit.js      (V8)
 *   bun  test-xplat-audit.js      (JavaScriptCore)
 *
 * Reference values (engine v9, 300 sessions / ~229,536 ticks):
 *   V8 (node 22, Linux):  STATE 60e11a9c32404cae…  RESULTS 926e1d69392d83b5…
 *   JSC (bun 1.3, Linux): STATE 4eb17938b3fe38e2…  RESULTS 926e1d69392d83b5…
 * RESULTS match across engines; full mid-flight STATE matches only within the
 * same engine family (float low-bit drift across engines — uvGs §3.5 class,
 * and exactly why per-step stateHash is an in-play diagnostic, not trail data).
 */
'use strict';
const crypto = require('crypto');
const E = require('./index.js');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

// integer LCG -> identical on every engine (no floats, no Math.sin)
function lcg(seed){ let s = seed>>>0; return ()=>{ s=(Math.imul(s,1664525)+1013904223)>>>0; return s; }; }
// 4 input policies over the field, engine-independent by construction
const policies = {
  still:   ()=>(t)=>({x:4.5,y:2.0}),
  sweep:   ()=>(t)=>({x:1+((t%700)/100), y:1+((t%300)/100)}),
  jitter:  (r)=>(t)=>({x:1+ (r()%701)/100, y:1+ (r()%301)/100}),
  corners: (r)=>(t)=>{ const c=r()%4; return {x: c%2? 7.5:1.5, y: c<2? 0.8:3.2}; }
};
const SESSIONS = 75;              // 75 x 4 policies = 300 sessions
const acc = crypto.createHash('sha256');
const res = crypto.createHash('sha256');   // outcomes only: ticks+totalWin per session
let totalTicks = 0;
for (const [pname, mk] of Object.entries(policies)) {
  for (let s = 0; s < SESSIONS; s++) {
    const seed = sha256('xplat:'+pname+':'+s);
    const pol = mk(lcg(parseInt(seed.slice(0,8),16)));
    const st = E.createInitialState(seed, 5);
    let guard = 0;
    while (!st.finished && guard < 50000) {
      E.tick(st, pol(st.tickCount));
      // core §3: timestamps are inert metadata; rng internals are diagnostics — excluded.
      if (st.tickCount % 50 === 0) acc.update(JSON.stringify(st, (k,v)=> (k==='uvsHeader'||k==='rng') ? undefined : v));
      guard++; totalTicks++;
    }
    acc.update(JSON.stringify({ s: seed, t: st.tickCount, w: st.totalWin, fin: st.finished }));
    res.update(seed+':'+st.tickCount+':'+st.totalWin+';');
  }
}
const rt = typeof Bun !== 'undefined' ? ('bun '+Bun.version+' (JavaScriptCore)') : ('node '+process.version+' (V8)');
console.log('PADDLA xplat audit | engine v'+E.ENGINE_VERSION+' | 300 sessions, '+totalTicks+' ticks');
console.log('runtime: '+rt+' | os: '+process.platform+'/'+process.arch);
console.log('STATE-DIGEST:   '+acc.digest('hex'));
console.log('RESULTS-DIGEST: '+res.digest('hex'));
