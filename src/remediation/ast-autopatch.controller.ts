import { Controller, Post, Body, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { AstAutoPatchService } from './ast-autopatch.service';

@Controller('api/v1/remediation/ast')
export class AstAutoPatchController {
  constructor(private readonly autoPatchService: AstAutoPatchService) {}

  /**
   * Generates a deterministic AST security patch for a vulnerability finding.
   */
  @Post('generate-patch')
  @HttpCode(HttpStatus.OK)
  generatePatch(
    @Body()
    body: {
      ruleId: string;
      targetFile: string;
      codeSnippet?: string;
    },
  ) {
    return this.autoPatchService.generateAutoPatch(body);
  }

  /**
   * Catalog of supported deterministic AST transformation rules.
   */
  @Get('rules')
  getRules() {
    return {
      engine: 'Deterministic Abstract Syntax Tree Security Transformer (v12)',
      totalSupportedCwes: 8,
      rules: [
        { ruleId: 'SQL_INJECTION', cweId: 'CWE-89', transform: 'Parameterization & Prepared Statement Binding ($1, $2)' },
        { ruleId: 'COMMAND_INJECTION_RCE', cweId: 'CWE-78', transform: 'exec() to execFile() argument vector isolation' },
        { ruleId: 'HARDCODED_SECRETS', cweId: 'CWE-798', transform: 'Environment variable extraction with fail-closed guard' },
        { ruleId: 'DDE_FORMULA_INJECTION', cweId: 'CWE-1236', transform: 'Single-quote prepend sanitization for spreadsheets (Excellency)' },
        { ruleId: 'MISSING_SECURITY_HEADERS', cweId: 'CWE-693', transform: 'Automated Helmet & Strict CSP/HSTS middleware injection' },
        { ruleId: 'IMPROPER_INPUT_VALIDATION', cweId: 'CWE-20', transform: 'Type-strict boundary and character whitelist enforcement' },
      ],
    };
  }
}
