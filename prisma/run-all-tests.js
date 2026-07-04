const { fork } = require('child_process');
const path = require('path');

const testScripts = [
  { name: 'User Authentication & TOTP MFA (test-auth.js)', file: 'test-auth.js' },
  { name: 'Asynchronous Scanning & SSE Telemetry (test-async-scan.js)', file: 'test-async-scan.js' },
  { name: 'AI Defensive Shield & Vector Firewall (test-shield.js)', file: 'test-shield.js' },
  { name: 'Auto-Remediation & Git Integration (test-auto-fix.js)', file: 'test-auto-fix.js' },
  { name: 'Honeytoken Deception Fabric (test-deception.js)', file: 'test-deception.js' },
  { name: 'System Status Health Diagnostics (test-health.js)', file: 'test-health.js' },
  { name: 'Diamond Model Forensic Attribution (test-forensics.js)', file: 'test-forensics.js' },
  { name: 'Security Hardening & Concurrency Control (test-hardening.js)', file: 'test-hardening.js' }
];

function runScript(script) {
  return new Promise((resolve) => {
    console.log(`\n=============================================================`);
    console.log(`🚀 RUNNING SUITE: ${script.name}`);
    console.log(`=============================================================`);

    const child = fork(path.join(__dirname, script.file), [], { silent: false });

    child.on('exit', (code) => {
      resolve({
        name: script.name,
        success: code === 0,
        code
      });
    });
  });
}

async function runAll() {
  console.log(`
🛡️  SHIELD INTELLIGENCE PLATFORM — v9.0 UNIFIED VERIFICATION SUITE  🛡️
=====================================================================
`);

  const results = [];
  for (const script of testScripts) {
    const res = await runScript(script);
    results.push(res);
  }

  console.log(`
=====================================================================
📊 FINAL VERIFICATION TEST SUMMARY
=====================================================================`);
  
  let passedCount = 0;
  results.forEach((r) => {
    const icon = r.success ? '✅ PASSED' : '❌ FAILED';
    console.log(`- [${icon}] ${r.name} (Exit Code: ${r.code})`);
    if (r.success) passedCount++;
  });

  console.log(`\nVerification Score: ${passedCount}/${testScripts.length} modules completed.`);

  if (passedCount === testScripts.length) {
    console.log(`\n🎉 CONGRATULATIONS! ALL DEFENSIVE SYSTEMS SUCCESSFULLY ACCREDITED! 🎉\n`);
    process.exit(0);
  } else {
    console.log(`\n⚠️ Security audit completed with failures. Check log outputs.\n`);
    process.exit(1);
  }
}

runAll();
