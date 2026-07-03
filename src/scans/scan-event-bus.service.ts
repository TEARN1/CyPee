import { Injectable, Logger } from '@nestjs/common';
import { Subject, Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface ScanTelemetryEvent {
  type: 'module_start' | 'finding' | 'module_complete' | 'complete' | 'failed' | 'heartbeat';
  module?: string;
  progress?: number;
  message?: string;
  finding?: {
    id: string;
    severity: string;
    title: string;
    filePath?: string;
    lineNumber?: number;
  };
  postureScore?: number;
  totalFindings?: number;
  timestamp: string;
}

@Injectable()
export class ScanEventBus {
  private readonly logger = new Logger(ScanEventBus.name);
  private readonly subjects = new Map<string, Subject<ScanTelemetryEvent>>();

  getOrCreate(scanId: string): Subject<ScanTelemetryEvent> {
    let subject = this.subjects.get(scanId);
    if (!subject) {
      this.logger.log(`Creating SSE Event Stream Subject for scan: ${scanId}`);
      subject = new Subject<ScanTelemetryEvent>();
      this.subjects.set(scanId, subject);
    }
    return subject;
  }

  emit(scanId: string, event: Omit<ScanTelemetryEvent, 'timestamp'>): void {
    const subject = this.subjects.get(scanId);
    if (subject) {
      subject.next({
        ...event,
        timestamp: new Date().toISOString(),
      });
    }
  }

  complete(scanId: string): void {
    const subject = this.subjects.get(scanId);
    if (subject) {
      this.logger.log(`Closing SSE Event Stream Subject for scan: ${scanId}`);
      subject.complete();
      this.subjects.delete(scanId);
    }
  }

  getObservable(scanId: string): Observable<MessageEvent> {
    const subject = this.getOrCreate(scanId);
    return subject.asObservable().pipe(
      map((event) => ({
        data: JSON.stringify(event),
      } as MessageEvent)),
    );
  }
}
