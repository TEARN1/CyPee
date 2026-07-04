const { PrismaClient } = require('@prisma/client');
const { PrismaBetterSqlite3 } = require('@prisma/adapter-better-sqlite3');

const adapter = new PrismaBetterSqlite3({
  url: 'file:./dev.db',
});
const prisma = new PrismaClient({ adapter });

async function main() {
  const certs = await prisma.zKCertificate.findMany({
    orderBy: { issuedAt: 'desc' },
    take: 5,
  });

  console.log(`\nFound ${certs.length} heuristic compliance mappings in database:`);
  certs.forEach((c) => {
    const proof = JSON.parse(c.proof);
    const pub = JSON.parse(c.publicInput);
    console.log(`\n--- Heuristic mapping for standard: ${c.standard} ---`);
    console.log(`- Status: ${proof.status}`);
    console.log(`- Details: ${proof.details}`);
    console.log(`- Disclaimer: ${proof.disclaimer}`);
    console.log(`- Public inputs:`, pub);
  });
}

main().finally(() => prisma.$disconnect());
