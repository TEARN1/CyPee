import * as fs from 'fs';
import * as path from 'path';
import { ScanFindingInput } from './secret-excavator';

export class IaCSecurity {
  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];
    await this.walkDirectory(dirPath, (filePath) => {
      if (filePath.includes('node_modules') || filePath.includes('.git') || filePath.includes('dist')) {
        return;
      }

      const filename = path.basename(filePath).toLowerCase();

      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');

        // 1. Dockerfile checks
        if (filename === 'dockerfile' || filename.startsWith('dockerfile.')) {
          this.auditDockerfile(content, relPath, findings);
        }

        // 2. Docker Compose checks
        if (filename === 'docker-compose.yml' || filename === 'docker-compose.yaml') {
          this.auditDockerCompose(content, relPath, findings);
        }

        // 3. Kubernetes / general YAML config resource checks
        if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
          this.auditKubernetesYaml(content, relPath, findings);
        }
      } catch {
        // Skip unreadable files
      }
    });

    return findings;
  }

  private auditDockerfile(content: string, filePath: string, findings: ScanFindingInput[]) {
    const lines = content.split('\n');
    let hasUser = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith('USER ')) {
        hasUser = true;
      }
    }

    if (!hasUser) {
      findings.push({
        title: 'Dockerfile Running as Root',
        description: 'No explicit USER instruction was defined in the Dockerfile. Containers running as root are susceptible to host takeover if container escapes occur.',
        severity: 'HIGH',
        filePath,
        lineNumber: 1,
        cweId: 'CWE-250',
        mitreId: 'T1611',
        remediation: 'Define a non-root system user inside the Dockerfile (e.g. `RUN useradd -u 8888 app && USER app`) to drop privileges.',
        cvssScore: 8.2,
        pesScore: 82.0,
      });
    }
  }

  private auditDockerCompose(content: string, filePath: string, findings: ScanFindingInput[]) {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for privileged container execution
      if (/privileged:\s*true/.test(line)) {
        findings.push({
          title: 'Docker Compose Privileged Mode Enabled',
          description: 'A container is configured to run in privileged mode, granting it access to all devices on the host system.',
          severity: 'CRITICAL',
          filePath,
          lineNumber: i + 1,
          cweId: 'CWE-266',
          mitreId: 'T1611',
          remediation: 'Remove the `privileged: true` option. Instead, use fine-grained cap_add capabilities if host hardware access is required.',
          cvssScore: 9.3,
          pesScore: 93.0,
        });
      }

      // Check for exposed local ports without network filters
      if (/ports:\s*$/.test(line) || /-\s*"\d+:\d+"/.test(line)) {
        // Just flag as info / low unless we detect insecure database ports exposed publicly
        if (line.includes('5432:5432') || line.includes('6379:6379') || line.includes('3306:3306')) {
          findings.push({
            title: 'Exposed Database Port to Host Network',
            description: `Database port (e.g. PostgreSQL, Redis, MySQL) is binded directly to the host network interface.`,
            severity: 'MEDIUM',
            filePath,
            lineNumber: i + 1,
            cweId: 'CWE-668',
            mitreId: 'T1046',
            remediation: 'Bind db ports to 127.0.0.1 (e.g., "127.0.0.1:5432:5432") or utilize Docker internal network bridging instead of exposing ports.',
            cvssScore: 5.5,
            pesScore: 55.0,
          });
        }
      }
    }
  }

  private auditKubernetesYaml(content: string, filePath: string, findings: ScanFindingInput[]) {
    // Basic check for limits block in K8s configs
    if (content.includes('apiVersion:') && content.includes('kind:')) {
      if (!content.includes('resources:') || !content.includes('limits:')) {
        findings.push({
          title: 'Missing Kubernetes Container Resource Limits',
          description: 'Containers are configured without resource (CPU/Memory) usage limits, making the cluster vulnerable to Denial of Service (DoS) / resource starvation attacks.',
          severity: 'MEDIUM',
          filePath,
          lineNumber: 1,
          cweId: 'CWE-400',
          mitreId: 'T1496',
          remediation: 'Add `resources.limits` and `resources.requests` configurations inside the pod spec container block.',
          cvssScore: 4.8,
          pesScore: 48.0,
        });
      }
    }
  }

  private async walkDirectory(dir: string, callback: (filePath: string) => void): Promise<void> {
    try {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const filepath = path.join(dir, file);
        const stats = fs.statSync(filepath);
        if (stats.isDirectory()) {
          await this.walkDirectory(filepath, callback);
        } else {
          callback(filepath);
        }
      }
    } catch {
      // Directory access issue
    }
  }
}
