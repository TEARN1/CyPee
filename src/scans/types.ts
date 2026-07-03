export type Provider = 'GITHUB' | 'GITLAB' | 'BITBUCKET' | 'OTHER';

export type ScanState =
  | 'AUTHORIZED'
  | 'PROVISIONING'
  | 'SCANNING'
  | 'CORRELATING'
  | 'REPORTING'
  | 'COMPLETE'
  | 'FAILED'
  | 'ARCHIVED';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const SCAN_QUEUE = 'SCAN_EXECUTION';
