import { Injectable, Logger } from '@nestjs/common';
import { UploadReportDto } from './dto/upload-report.dto';
import { QueueService } from '../queue/queue.service';

@Injectable()
export class ComplianceService {
  private readonly logger = new Logger(ComplianceService.name);

  constructor(private readonly queueService: QueueService) {}

  /**
   * Delegates parsing tasks to the background processing queue.
   * Returns metadata about the background job.
   */
  async handleReportUpload(uploadReportDto: UploadReportDto): Promise<{ status: string; jobId: string; count: number }> {
    const { findings } = uploadReportDto;
    
    this.logger.log(`Received report upload containing ${findings.length} findings.`);

    // Enqueue findings for background async processing
    const jobId = await this.queueService.addFindingsToQueue(findings);

    return {
      status: 'queued',
      jobId,
      count: findings.length,
    };
  }
}
