export interface IFinding {
  id: string;
  filePath: string;
  lineNumber: number;
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  platform: 'Web' | 'Mobile' | 'Source Code' | 'Desktop';
  title: string;
  risk: string;
  insecureCode: string;
  secureCode: string;
}

export const sampleFindings: IFinding[] = [
  {
    id: "f1",
    filePath: "src/users/users.service.ts",
    lineNumber: 42,
    ruleId: "SQL_INJECTION",
    severity: "CRITICAL",
    platform: "Web",
    title: "Unparameterized Database Queries (SQL Injection)",
    risk: "Concatenating untrusted user input directly into database query strings allows attackers to manipulate the structure of the query. This can lead to unauthorized data retrieval, modifications, data deletion, or remote code execution.",
    insecureCode: `// INSECURE: Direct concatenation of user input into raw query
async getUserProfile(userId: string) {
  const query = \`SELECT * FROM users WHERE id = '\${userId}'\`;
  return this.db.query(query);
}`,
    secureCode: `// SECURE: Use parameterized queries/bind variables
async getUserProfile(userId: string) {
  const query = 'SELECT * FROM users WHERE id = $1';
  return this.db.query(query, [userId]);
}`
  },
  {
    id: "f2",
    filePath: "src/auth/auth.module.ts",
    lineNumber: 15,
    ruleId: "HARDCODED_SECRETS",
    severity: "HIGH",
    platform: "Source Code",
    title: "Hardcoded Cryptographic Keys or Secrets",
    risk: "Storing plaintext credentials, API keys, JWT secrets, or encryption keys in version-controlled source files exposes sensitive assets to unauthorized users. If the repository is compromised, these keys can be extracted and abused.",
    insecureCode: `// INSECURE: Credential defined as a constant inside code
const JWT_SECRET = 'super-secret-key-12345-never-share-this';

@Module({
  imports: [
    JwtModule.register({ secret: JWT_SECRET }),
  ],
})
export class AuthModule {}`,
    secureCode: `// SECURE: Load secret keys from environment variables or a secure secret store
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
export class AuthModule {}`
  },
  {
    id: "f3",
    filePath: "android/app/src/main/AndroidManifest.xml",
    lineNumber: 8,
    ruleId: "ANDROID_DEBUGGABLE",
    severity: "HIGH",
    platform: "Mobile",
    title: "Application is Configured as Debuggable",
    risk: "Enabling debuggable flags in release binaries exposes internal instrumentation hooks. Attackers can attach debugger tools (like JDWP), inspect running memory heaps, inject dynamic class files, or bypass cryptographic enclaves.",
    insecureCode: `<!-- INSECURE: android:debuggable is set to true in production -->
<application
    android:allowBackup="true"
    android:icon="@mipmap/ic_launcher"
    android:label="@string/app_name"
    android:debuggable="true">
    <activity android:name=".MainActivity" />
</application>`,
    secureCode: `<!-- SECURE: Keep debuggable turned off in manifest configuration files -->
<application
    android:allowBackup="true"
    android:icon="@mipmap/ic_launcher"
    android:label="@string/app_name"
    android:debuggable="false">
    <activity android:name=".MainActivity" />
</application>`
  },
  {
    id: "f4",
    filePath: "src/main.ts",
    lineNumber: 12,
    ruleId: "MISSING_SECURITY_HEADERS",
    severity: "MEDIUM",
    platform: "Web",
    title: "Missing HTTP Security Headers",
    risk: "Absence of fundamental HTTP security headers (like Content-Security-Policy, X-Frame-Options, X-Content-Type-Options) exposes clients to clickjacking, cross-site scripting (XSS), and MIME-type sniffing attacks.",
    insecureCode: `// INSECURE: NestJS bootstrapped without registering security headers
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();`,
    secureCode: `// SECURE: Register Helmet middleware to automatically apply security headers
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Register Helmet middleware
  app.use(helmet());
  
  await app.listen(3000);
}
bootstrap();`
  },
  {
    id: "f5",
    filePath: "controllers/DesktopAudit.cs",
    lineNumber: 87,
    ruleId: "CSHARP_DESERIALIZATION",
    severity: "CRITICAL",
    platform: "Desktop",
    title: "Insecure Deserialization in BinaryFormatter",
    risk: "Deserializing untrusted streams using binary formatters allows attackers to trigger arbitrary object graph construction, resulting in remote code execution (RCE) on the local host.",
    insecureCode: `// INSECURE: Deserializing payloads directly via BinaryFormatter
BinaryFormatter formatter = new BinaryFormatter();
using (MemoryStream stream = new MemoryStream(payloadBytes))
{
    var obj = formatter.Deserialize(stream);
    return obj;
}`,
    secureCode: `// SECURE: Use safe serializers like System.Text.Json with schema validations
using System.Text.Json;

// Deserializing using strongly-typed secure JSON schemas
var obj = JsonSerializer.Deserialize<SafeUserConfig>(payloadBytes);
return obj;`
  }
];
