import { Controller, Get, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { PqcCryptoService } from './pqc-crypto.service';

@Controller('api/v1/shield/pqc')
export class PqcCryptoController {
  constructor(private readonly pqcService: PqcCryptoService) {}

  /**
   * Returns current Post-Quantum Lattice Cryptography posture and active NIST ML-KEM parameters.
   */
  @Get('posture')
  getPosture() {
    return this.pqcService.getQuantumPosture();
  }

  /**
   * Rotates the Post-Quantum Lattice Key Pair.
   */
  @Post('rotate-key')
  @HttpCode(HttpStatus.OK)
  rotateKey() {
    const newKey = this.pqcService.generateLatticeKeyPair();
    return {
      success: true,
      message: 'New NIST FIPS 203 ML-KEM lattice key pair generated',
      newKey,
    };
  }

  /**
   * Tests zero-cost post-quantum lattice encapsulation of an arbitrary payload.
   */
  @Post('test-encapsulate')
  @HttpCode(HttpStatus.OK)
  testEncapsulate(@Body('payload') payload?: string) {
    const enc = this.pqcService.encapsulateSecret(payload || 'sovereign-enclave-quantum-proof');
    return {
      success: true,
      encapsulation: enc,
    };
  }
}
