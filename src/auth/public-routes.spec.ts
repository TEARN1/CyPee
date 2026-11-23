import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';

// Every route needs a sign-in (RequireSignInGuard, global) unless marked
// @Public(). These are the only public routes; adding one is a decision, so
// it means changing this list too.
const EXPECTED_PUBLIC = [
  "auth/auth.controller.ts @Post('register')",
  "auth/auth.controller.ts @Post('login')",
  "compliance/compliance.controller.ts @Post('upload')", // Ed25519-signed
  'compliance/health.controller.ts @Get()',
  "deception/deception.controller.ts @Get('admin/db-backup')", // honeypots return decoys
  "deception/deception.controller.ts @Get('config/aws-credentials')",
  "deception/deception.controller.ts @Get('deception/robots.txt')",
  "deception/deception.controller.ts @Get('internal/k8s-tokens')",
  "deception/deception.controller.ts @Post('deception/honeypot/shell')",
  "deception/deception.controller.ts @Get('deception/canary/template')",
  "deception/deception.controller.ts @Post('graphql')",
  "shield/attacker-recon.controller.ts @Get('beacon/:beaconId')", // canary beacon
  "shield/gateway.controller.ts @All(':appId')", // the protected apps' own traffic
  "shield/gateway.controller.ts @All(':appId/*')",
  "shield/mtd-engine.controller.ts @Post('validate')", // API key
  "shield/vgruvs-host.controller.ts @Post('heartbeat')", // API key
].sort();

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? sources(p) : p.endsWith('.controller.ts') ? [p] : [];
  });
}

describe('public routes', () => {
  it('are exactly the expected list; everything else needs a sign-in', () => {
    const root = join(__dirname, '..');
    const found: string[] = [];
    for (const file of sources(root)) {
      const lines = readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, i) => {
        if (line.trim() !== '@Public()') return;
        for (let j = i - 1; j >= 0 && j > i - 4; j--) {
          const m = lines[j].match(/@(Get|Post|Put|Patch|Delete|All)\([^)]*\)/);
          if (m) {
            found.push(`${file.slice(root.length + 1).replace(/\\/g, '/')} ${m[0]}`);
            break;
          }
        }
      });
    }
    expect(found.sort()).toEqual(EXPECTED_PUBLIC);
  });
});
