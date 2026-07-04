const { PrismaClient } = require('@prisma/client');
const { PrismaBetterSqlite3 } = require('@prisma/adapter-better-sqlite3');

const adapter = new PrismaBetterSqlite3({
  url: 'file:./dev.db',
});
const prisma = new PrismaClient({ adapter });

async function main() {
  const findings = await prisma.finding.findMany({
    orderBy: { createdAt: 'desc' },
  });
  console.log(`\nFound ${findings.length} findings in database:`);
  findings.forEach((f) => {
    console.log(`- [${f.severity}] ${f.title} at ${f.filePath}:${f.lineNumber}`);
  });

  const scans = await prisma.scan.findMany({
    orderBy: { startedAt: 'desc' },
  });
  console.log(`\nFound ${scans.length} scans in database:`);
  scans.forEach((s) => {
    console.log(`- Scan ${s.id} state: ${s.state} (Score: ${s.postureScore})`);
  });
}

main().finally(() => prisma.$disconnect());
