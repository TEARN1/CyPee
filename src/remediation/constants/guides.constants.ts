export interface IRemediationGuide {
  title: string;
  riskDescription: string;
  insecurePattern: string;
  securePattern: string;
}

export const REMEDIATION_GUIDES: Record<string, IRemediationGuide> = {
  SQL_INJECTION: {
    title: 'Unparameterized Database Queries (SQL Injection)',
    riskDescription: `
Concatenating untrusted user input directly into database query strings allows attackers to manipulate the structure of the query. 
This can lead to unauthorized data retrieval, modifications, data deletion (like SQL drop tables), or even remote code execution depending on database configurations.
    `.trim(),
    insecurePattern: `
// INSECURE: Direct concatenation of user input into raw query
async getUserProfile(userId: string) {
  const query = \`SELECT * FROM users WHERE id = '\${userId}'\`;
  return this.db.query(query);
}
    `.trim(),
    securePattern: `
// SECURE: Use parameterized queries/bind variables
async getUserProfile(userId: string) {
  const query = 'SELECT * FROM users WHERE id = $1';
  return this.db.query(query, [userId]);
}
    `.trim(),
  },
  HARDCODED_SECRETS: {
    title: 'Hardcoded Cryptographic Keys or Secrets',
    riskDescription: `
Storing plaintext credentials, API keys, JWT secrets, or encryption keys in version-controlled source files exposes sensitive assets to unauthorized users. 
If the repository is compromised, leaked, or cloned, these keys can be extracted and abused to bypass authentication or gain access to connected services.
    `.trim(),
    insecurePattern: `
// INSECURE: Credential defined as a constant inside code
const JWT_SECRET = 'super-secret-key-12345-never-share-this';

@Module({
  imports: [
    JwtModule.register({ secret: JWT_SECRET }),
  ],
})
export class AuthModule {}
    `.trim(),
    securePattern: `
// SECURE: Load secret keys from environment variables or a secure secret store
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
      }),
    }),
  ],
})
export class AuthModule {}
    `.trim(),
  },
  MISSING_SECURITY_HEADERS: {
    title: 'Missing HTTP Security Headers',
    riskDescription: `
Absence of fundamental HTTP security headers (like Content-Security-Policy, X-Frame-Options, X-Content-Type-Options) exposes clients to clickjacking, cross-site scripting (XSS), and MIME-type sniffing attacks.
    `.trim(),
    insecurePattern: `
// INSECURE: NestJS bootstrapped without registering security headers
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();
    `.trim(),
    securePattern: `
// SECURE: Register Helmet middleware to automatically apply security headers
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Register Helmet middleware
  app.use(helmet());
  
  await app.listen(3000);
}
bootstrap();
    `.trim(),
  },
  XSS_VULNERABILITY: {
    title: 'Cross-Site Scripting (XSS)',
    riskDescription: `
Rendering raw user inputs directly into web templates or browser pages allows malicious scripts to execute within the context of the user's browser. 
Attackers can capture session tokens, hijack cookies, redirect users, or alter website contents dynamically.
    `.trim(),
    insecurePattern: `
// INSECURE: Injecting unsanitized input directly into response HTML
@Get('greet')
greetUser(@Query('name') name: string) {
  return \`<h1>Welcome, \${name}</h1>\`;
}
    `.trim(),
    securePattern: `
// SECURE: Sanitize input or escape dynamic content properly
import * as dompurify from 'dompurify'; // Or use native framework escaping mechanisms

@Get('greet')
greetUser(@Query('name') name: string) {
  // Use framework automatic templating engines which escape by default,
  // or explicitly sanitize/encode input before outputting:
  const sanitized = dompurify.sanitize(name);
  return \`<h1>Welcome, \${sanitized}</h1>\`;
}
    `.trim(),
  },
};

export const FALLBACK_GUIDE: IRemediationGuide = {
  title: 'General Code Quality & Security Practice Violation',
  riskDescription: `
The code scanner flagged a potential security vulnerability or quality concern. While this specific rule doesn't map to a standard template, general best practices suggest:
1. Validating inputs strictly at system boundaries.
2. Sanitizing dynamic data before execution or output generation.
3. Keeping credentials outside the codebase.
  `.trim(),
  insecurePattern: `
// Pattern identified by rule scanner:
// Look for where input is directly trusted, or parameters are unvalidated.
  `.trim(),
  securePattern: `
// Corrective strategy:
// 1. Wrap block with validation guards.
// 2. Perform validation (e.g., length, character sets, schemas).
// 3. Keep logs clean and avoid printing raw exceptions to user.
  `.trim(),
};
