import { Injectable, NestMiddleware, ForbiddenException, BadRequestException, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ShieldService } from './shield.service';
import { AuditLogService } from '../audit/audit-log.service';

@Injectable()
export class ShieldMiddleware implements NestMiddleware {
  private readonly logger = new Logger(ShieldMiddleware.name);

  constructor(
    private readonly shieldService: ShieldService,
    private readonly auditLog: AuditLogService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const path = req.originalUrl || req.url;
    const now = Date.now();

    // 1. GeoIP Check
    const geo = this.shieldService.auditGeoIp(ip);
    if (!geo.allowed) {
      this.logger.warn(`Access blocked from restricted country: ${geo.country} | IP: ${ip}`);
      await this.auditLog.log('SYSTEM', 'IP_BLOCKED_GEO', `ip:${ip}`, { country: geo.country, path });
      throw new ForbiddenException(`Access denied from location: ${geo.country}`);
    }

    // Check if client solved a PoW challenge for this request
    const powChallenge = req.headers['x-shield-pow-challenge'] as string;
    const powNonce = req.headers['x-shield-pow-nonce'] as string;
    
    let powVerified = false;
    if (powChallenge && powNonce) {
      if (this.shieldService.verifyPoW(powChallenge, powNonce)) {
        powVerified = true;
      } else {
        await this.auditLog.log('SYSTEM', 'POW_VERIFICATION_FAILED', `ip:${ip}`, { path });
        throw new BadRequestException('Proof of Work challenge verification failed.');
      }
    }

    // 2. Behavioral Entropy Check (Bot / Brute force detector)
    const behavior = this.shieldService.detectBotBehavior(ip, now);
    if (behavior.isBot && !powVerified) {
      this.logger.warn(`Predictable bot requests interval detected (Jitter: ${behavior.entropy.toFixed(2)}ms) | IP: ${ip}`);
      res.setHeader('x-shield-challenge', this.shieldService.generateChallenge());
      throw new BadRequestException('Verification required. Complete Proof of Work challenge.');
    }

    // 3. Proof of Work Check for sensitive routes (always require PoW if it is sensitive)
    const isSensitive = path.includes('/auth/login') || path.includes('/compliance/upload') || path.includes('/scans');
    if (isSensitive && !powVerified) {
      // Force sensitive routes to require a PoW challenge if one wasn't solved
      res.setHeader('x-shield-challenge', this.shieldService.generateChallenge());
      throw new BadRequestException('Verification required. Complete Proof of Work challenge.');
    }

    // 4. Session Graph Check
    this.shieldService.auditSessionGraph(ip, path);

    // 5. Vector Firewall Check for payload bodies
    if (req.body && Object.keys(req.body).length > 0) {
      const bodyStr = JSON.stringify(req.body);
      const firewall = this.shieldService.vectorFirewallCheck(bodyStr);

      if (firewall.blocked) {
        this.logger.warn(`Vector Firewall intercepted threat payload matching signature: "${firewall.matchedSignature}" (Similarity: ${(firewall.similarity * 100).toFixed(1)}%) | IP: ${ip}`);
        
        await this.auditLog.log('SYSTEM', 'THREAT_INTERCEPTED', `ip:${ip}`, {
          path,
          matchedSignature: firewall.matchedSignature,
          similarity: firewall.similarity,
        });

        throw new ForbiddenException('Request blocked by Vector Firewall. Malicious payload detected.');
      }
    }

    next();
  }
}
