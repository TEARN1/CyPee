import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const tenantId = 'default-dev-tenant-uuid';
  const userId = 'default-dev-user-uuid';
  const email = 'dev@shield.io';
  const password = 'ShieldPassword2025!';

  // Check if tenant exists
  let tenant = await prisma.tenant.findUnique({
    where: { id: tenantId },
  });

  if (!tenant) {
    tenant = await prisma.tenant.create({
      data: {
        id: tenantId,
        name: 'Default Dev Org',
        plan: 'ENTERPRISE',
      },
    });
    console.log(`Created default tenant: ${tenant.name} (${tenant.id})`);
  }

  // Check if user exists
  const user = await prisma.user.findFirst({
    where: { email },
  });

  if (!user) {
    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.user.create({
      data: {
        id: userId,
        tenantId: tenant.id,
        email,
        passwordHash,
        role: 'ADMIN',
      },
    });
    console.log(`Created default user: ${email} with password: ${password}`);
  }

  console.log('Seeding completed successfully!');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
