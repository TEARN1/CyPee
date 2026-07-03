import { Test, TestingModule } from '@nestjs/testing';
import { RemediationService } from './remediation.service';
import { SeverityLevel } from '../compliance/interfaces/finding.interface';

describe('RemediationService', () => {
  let service: RemediationService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RemediationService],
    }).compile();

    service = module.get<RemediationService>(RemediationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateRemediationMarkdown', () => {
    it('should return the SQL injection remediation guide when a SQL rule is parsed', () => {
      const markdown = service.generateRemediationMarkdown('RULE_SQL_INJECTION_DETECTED', SeverityLevel.CRITICAL);
      
      expect(markdown).toContain('### [CRITICAL] Remediation Guide for Rule `RULE_SQL_INJECTION_DETECTED`');
      expect(markdown).toContain('Unparameterized Database Queries (SQL Injection)');
      expect(markdown).toContain('// SECURE: Use parameterized queries/bind variables');
    });

    it('should return the Hardcoded Secrets guide when key/password rules are parsed', () => {
      const markdown = service.generateRemediationMarkdown('AWS_SECRET_ACCESS_KEY_LEAK', SeverityLevel.HIGH);
      
      expect(markdown).toContain('### [HIGH] Remediation Guide for Rule `AWS_SECRET_ACCESS_KEY_LEAK`');
      expect(markdown).toContain('Hardcoded Cryptographic Keys or Secrets');
      expect(markdown).toContain('config.get<string>(\'JWT_SECRET\')');
    });

    it('should return the HTTP Security Headers guide when header rules are parsed', () => {
      const markdown = service.generateRemediationMarkdown('MISSING_HELMET_HEADERS', SeverityLevel.MEDIUM);
      
      expect(markdown).toContain('### [MEDIUM] Remediation Guide for Rule `MISSING_HELMET_HEADERS`');
      expect(markdown).toContain('Missing HTTP Security Headers');
      expect(markdown).toContain('app.use(helmet());');
    });

    it('should return the fallback guide for unrecognized rule IDs', () => {
      const markdown = service.generateRemediationMarkdown('SOME_RANDOM_UNKNOWN_SCANNER_RULE', SeverityLevel.LOW);
      
      expect(markdown).toContain('### [LOW] Remediation Guide for Rule `SOME_RANDOM_UNKNOWN_SCANNER_RULE`');
      expect(markdown).toContain('General Code Quality & Security Practice Violation');
      expect(markdown).toContain('Validating inputs strictly at system boundaries');
    });
  });
});
