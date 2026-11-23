import { EphemeralSandboxService } from './ephemeral-sandbox.service';

describe('EphemeralSandboxService', () => {
  const original = process.env.CYPEE_ALLOW_CODE_RUN;
  afterEach(() => {
    if (original === undefined) delete process.env.CYPEE_ALLOW_CODE_RUN;
    else process.env.CYPEE_ALLOW_CODE_RUN = original;
  });

  it('runs nothing unless the owner switched code running on', () => {
    delete process.env.CYPEE_ALLOW_CODE_RUN;
    (globalThis as any).__cypeeEscaped = false;
    const res = new EphemeralSandboxService().executeCandidate(
      "this.constructor.constructor('globalThis.__cypeeEscaped = true')()",
      'x',
    );
    expect(res.success).toBe(false);
    expect(res.error).toContain('switched off');
    expect((globalThis as any).__cypeeEscaped).toBe(false);
  });

  it('when on, still blocks eval and new Function inside the context', () => {
    process.env.CYPEE_ALLOW_CODE_RUN = 'true';
    const res = new EphemeralSandboxService().executeCandidate("return eval('1+1')", 'x');
    expect(res.success).toBe(false);
  });
});
