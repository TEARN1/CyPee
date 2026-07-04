# Guide to Improving Engineering Prompts: SAST Orchestration Backend

When asking an LLM to generate complex backend architectures (like NestJS, BullMQ queues, and Security Remediation services), structural ambiguity is the main source of code generation gaps. 

To improve the original prompt and get **production-ready, zero-revision code**, the prompt should be refined with specific constraints, versions, schema standards, and patterns.

---

## 🛑 The Original Prompt
> *You are an expert Application Security Architect and Principal NestJS Developer. I am building a static application security testing (SAST) orchestration engine designed to help developers fix security flaws in their code before deployment. ... [etc]*

---

## ⚡ The M.A.S.T.E.R. Prompt Template (Improved Version)

Here is a highly optimized, structured version of your prompt that removes all ambiguity and commands the exact production-ready output architecture.

```markdown
# Role Definition
You are a Principal Application Security Architect and Lead NestJS Engineer. You write clean, testable TypeScript code conforming to the SOLID principles and NestJS standard patterns.

# Context
We are building a Static Application Security Testing (SAST) orchestration backend engine. The application ingests static code analysis reports, validates findings, processes them asynchronously via a worker queue, and attaches remediation guidelines.

# Tech Stack & Constraints
1. Framework: NestJS v10+ (using modular structure)
2. Queue System: BullMQ v5+ (configured via @nestjs/bullmq, using NestJS WorkerHost worker patterns)
3. Input Validation: class-validator and class-transformer
4. Language: TypeScript (strict mode enabled)
5. Configuration: Configured asynchronously via @nestjs/config (from environment variables)
6. Database Model: Mock persistence service (or specify TypeORM / Prisma with PostgreSQL if desired)

# Detailed Requirements

## 1. Ingestion Endpoint (POST /api/v1/compliance/upload)
- **Validation**: Accept a JSON payload containing an array of findings. Validate that each finding conforms to the following schema:
  - `filePath`: Non-empty string
  - `lineNumber`: Positive integer (>= 1)
  - `ruleId`: Non-empty string
  - `severity`: String enumeration: LOW, MEDIUM, HIGH, CRITICAL
  - `message`: Optional string
- **Performance**: Immediately offload processing to BullMQ and return a `202 Accepted` status with a `jobId`. Do NOT wait for remediation parsing to complete.

## 2. Worker Queue & Processors (BullMQ)
- Use a dedicated queue named `sast-analysis`.
- Implement a worker processor (`SastProcessor`) that extends `WorkerHost`.
- The processor must map incoming findings to their corresponding remediation guides and write the final enriched finding to the database.
- Configure job retries (3 attempts, exponential backoff starting at 5000ms).

## 3. Remediation Feedback Service
- A service that parses finding metadata and returns a Markdown remediation guide.
- Must support mapped templates for:
  - SQL_INJECTION
  - HARDCODED_SECRETS
  - MISSING_SECURITY_HEADERS
  - XSS_VULNERABILITY
- Each guide MUST return:
  1. Engineering risk description.
  2. Code block demonstrating the insecure pattern.
  3. Code block demonstrating the secure, corrected pattern.

# Expected Output Format
1. Modular project layout (declare the structure).
2. Complete, non-truncated TypeScript files for:
   - DTOs (SastFindingDto, UploadReportDto)
   - Interface definitions (ISastFinding, IEnrichedSastFinding)
   - Ingestion Controller & Service
   - BullMQ Module, Service, and Worker Processor
   - Remediation Service & Guides Configuration
3. A Docker Compose file for setting up local Redis testing.
4. A sample payload input JSON file for API validation testing.
```

---

## 🧠 Why This Improved Prompt Works Better

| Area | In Original Prompt | In Improved Prompt | Benefit |
| :--- | :--- | :--- | :--- |
| **Technology Choices** | "worker queue structure (such as BullMQ)" | "BullMQ v5+ configured via `@nestjs/bullmq` extending `WorkerHost`" | Prevents the model from writing legacy `@nestjs/bull` syntax and enforces NestJS 10 patterns. |
| **Response Behavior** | "accepts standardized static code analysis outputs" | "Immediately offload... return `202 Accepted` with a `jobId`" | Explicitly enforces non-blocking, asynchronous behavior at the HTTP layer. |
| **Vulnerability Selection** | "common structural flaws" | "SQL_INJECTION, HARDCODED_SECRETS, MISSING_SECURITY_HEADERS..." | Guarantees that the code blocks generated cover the exact cases you want to display first. |
| **Output Specifics** | "Provide production-ready TypeScript code" | "Complete, non-truncated TypeScript files for: DTOs, Controllers..." | Stops the LLM from outputting truncated templates or placeholders like `// ... rest of code`. |
