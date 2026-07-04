# SAST Ingestion & Remediation Orchestration Engine

A modular, production-ready NestJS backend service designed to ingest linting and vulnerability scanner outputs, offload report parsing to an asynchronous worker queue (BullMQ), and generate structured markdown remediation guides for identified vulnerabilities.

## 🚀 Key Features

1. **Static Analysis Ingestion**: Accepts JSON uploads containing scanner/linter reports via `POST /api/v1/compliance/upload`.
2. **DTO Request Validation**: Uses `class-validator` to strictly enforce parameters (`filePath`, `lineNumber`, `ruleId`, and `severity`).
3. **Asynchronous Background Processing**: Offloads parsing of heavy files to BullMQ (backed by Redis), returning `202 Accepted` immediately.
4. **Remediation Feedback Service**: Matches code findings with specific vulnerability remediation guides that explain risk and provide code blocks of secure and insecure patterns.
5. **Clean Architecture**: Decoupled modules following domain separation (`Compliance`, `Queue`, `Remediation`).

---

## 📁 Project Structure

```
src/
├── main.ts                       # Application entry point and validation config
├── app.module.ts                 # Main root app module importing config and modules
├── compliance/                   # Ingestion API module
│   ├── compliance.module.ts
│   ├── compliance.controller.ts  # Accepts uploads and handles HTTP routing
│   ├── compliance.service.ts     # Business logic parsing requests
│   ├── dto/
│   │   ├── sast-finding.dto.ts   # Validator for individual finding objects
│   │   └── upload-report.dto.ts  # Validator wrapper for finding arrays
│   └── interfaces/
│       └── finding.interface.ts  # SAST types and structures
├── queue/                        # BullMQ processing module
│   ├── queue.module.ts           # Configures Redis integration
│   ├── queue.constants.ts        # Constant identifiers for queues and jobs
│   ├── queue.service.ts          # Enqueues jobs
│   └── sast-processor.ts         # Worker host processing findings asynchronously
└── remediation/                  # Security Remediation mapping module
    ├── remediation.module.ts
    ├── remediation.service.ts    # Matches ruleIds to remediation templates
    └── constants/
        └── guides.constants.ts   # Core vulnerability database (markdown logs)
```

---

## 🛠️ Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Docker](https://www.docker.com/) (to run Redis container locally)

### Installation

1. Install npm dependencies:
   ```bash
   npm install
   ```

2. Start the local Redis container for the queue worker:
   ```bash
   docker-compose up -d
   ```

3. Configure environment variables in `.env` (a template is provided in `.env`):
   ```ini
   PORT=3000
   REDIS_HOST=localhost
   REDIS_PORT=6379
   ```

### Running the App

- **Development Mode**:
  ```bash
  npm run start:dev
  ```

- **Production Build & Run**:
  ```bash
  npm run build
  npm run start:prod
  ```

---

## 🧪 Testing the Endpoint

1. **Verify server is running** on `http://localhost:3000`.
2. **Submit a test payload** matching the sample schema using `curl` or Postman:

```bash
curl -X POST http://localhost:3000/api/v1/compliance/upload \
  -H "Content-Type: application/json" \
  -d @findings-sample.json
```

### Response
```json
{
  "status": "queued",
  "jobId": "1",
  "count": 4
}
```

### Worker Logging
In the application console, you will observe the background worker receiving the task, processing it asynchronously, formatting remediation templates, and completing:
```text
[Nest] 12345  - 07/03/2026, 10:30:00 AM     LOG [Bootstrap] SAST Ingestion Engine successfully running on: http://localhost:3000
[Nest] 12345  - 07/03/2026, 10:30:15 AM     LOG [ComplianceService] Received report upload containing 4 findings.
[Nest] 12345  - 07/03/2026, 10:30:15 AM     LOG [QueueService] Enqueued job. Job ID: 1
[Nest] 12345  - 07/03/2026, 10:30:15 AM     LOG [SastProcessor] Background processing started for Job ID: 1
[Nest] 12345  - 07/03/2026, 10:30:15 AM     LOG [SastProcessor] Processing 4 findings in background worker.
[Nest] 12345  - 07/03/2026, 10:30:15 AM     LOG [RemediationService] Generating remediation guide for ruleId: "SQL_INJECTION" using template key: "SQL_INJECTION"
...
[Nest] 12345  - 07/03/2026, 10:30:16 AM     LOG [SastProcessor] Background processing completed for Job ID: 1.
```
