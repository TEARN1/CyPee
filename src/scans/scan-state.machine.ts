import { BadRequestException } from '@nestjs/common';
import { ScanState } from './types';

/**
 * Valid scan state transitions — ensures no state is ever skipped.
 * Prevents race conditions where a worker jumps from SCANNING → COMPLETE
 * without going through CORRELATING and REPORTING first.
 */
const VALID_TRANSITIONS: Record<ScanState, ScanState[]> = {
  AUTHORIZED:    ['PROVISIONING', 'FAILED'],
  PROVISIONING:  ['SCANNING', 'FAILED'],
  SCANNING:      ['CORRELATING', 'FAILED'],
  CORRELATING:   ['REPORTING', 'FAILED'],
  REPORTING:     ['COMPLETE', 'FAILED'],
  COMPLETE:      ['ARCHIVED'],
  FAILED:        [],
  ARCHIVED:      [],
};

export function assertValidTransition(from: ScanState, to: ScanState): void {
  const allowed = VALID_TRANSITIONS[from];
  if (!allowed.includes(to)) {
    throw new BadRequestException(
      `Invalid scan state transition: ${from} → ${to}. Allowed: [${allowed.join(', ')}]`,
    );
  }
}

export function getNextState(current: ScanState): ScanState | null {
  const transitions = VALID_TRANSITIONS[current];
  // Return the first non-FAILED next state (the "happy path")
  return transitions.find((s) => s !== 'FAILED') ?? null;
}
