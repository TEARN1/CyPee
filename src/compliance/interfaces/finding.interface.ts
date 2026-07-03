export enum SeverityLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export interface ISastFinding {
  filePath: string;
  lineNumber: number;
  ruleId: string;
  severity: SeverityLevel;
  message?: string;
}

export interface IEnrichedSastFinding extends ISastFinding {
  id?: string;
  remediationGuide?: string; // Markdown remediation guide
  processedAt?: Date;
}
