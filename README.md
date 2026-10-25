# 🛡️ ActionShield AI

### A Safety Checkpoint for AI Agents

**An AI-agent safety layer that evaluates proposed actions before execution.**

ActionShield AI is a prototype designed to make AI-agent workflows safer by evaluating proposed actions against a policy engine before they can proceed. Instead of allowing an AI agent to perform every requested action directly, ActionShield AI introduces a controlled decision-making checkpoint.

Every proposed action is classified into one of three policy decisions:

* 🟢 **ALLOW** — The action satisfies the configured safety rules.
* 🟡 **REVIEW** — The action requires human review before proceeding.
* 🔴 **BLOCK** — The action violates a safety rule or cannot be safely permitted.

The prototype combines policy-based action evaluation, controlled simulated execution, human approval, workflow security testing, natural-language intent analysis, and persistent audit logging in a web dashboard.

---

## 📌 1. Problem Statement

AI agents are increasingly capable of interacting with files, executing commands, processing information, and carrying out multi-step workflows with limited human intervention.

However, granting an AI agent the ability to perform actions creates important safety challenges.

An agent may propose a destructive operation, attempt to access sensitive information, send data to an untrusted destination, or perform an action whose consequences are unclear.

Simply trusting an agent's decision or relying on a final output check may not be sufficient. Safety controls need to evaluate proposed actions before execution, identify risky operations, and provide a mechanism for human oversight.

### The problem we address

**How can we introduce a safety checkpoint between an AI agent's intentions and its actions, allowing permitted operations while reviewing or blocking potentially dangerous ones?**

ActionShield AI explores this approach through a policy-driven safety layer that evaluates proposed actions before they reach an execution component.

---

## 💡 2. Proposed Solution

ActionShield AI acts as an intermediary between an AI agent and the actions it proposes to perform.

Instead of immediately carrying out an action, the system evaluates its type, parameters, location, and risk indicators against predefined policies.

Based on the evaluation, the system returns `ALLOW`, `REVIEW`, or `BLOCK`.

Actions requiring review can enter a human approval workflow. Decisions and execution attempts are recorded in an audit log, while the Workflow Crash-Test Lab evaluates how the safety policies respond to predefined scenarios.

The AI-Assisted Intent Analysis module also accepts natural-language instructions and converts them into structured action proposals for policy evaluation.

The current prototype uses a deterministic policy engine and a heuristic, rule-based natural-language parser. It does not require a live LLM API.

---

## ✨ 3. Key Features

### 🛡️ Policy Engine

Evaluates proposed actions using deterministic safety rules.

Supported action categories include:

* `READ_FILE`
* `WRITE_FILE`
* `DELETE_FILE`
* `SEND_DATA`
* `RUN_COMMAND`

The engine distinguishes permitted operations from operations that require review or must be blocked.

### ⚙️ Controlled Action Execution

Provides a controlled execution layer that checks policy decisions before processing an action.

The current prototype uses an in-memory simulated workspace. It does not perform arbitrary shell commands, real host-file modifications, or real network requests.

### 👤 Human Approval Workflow

Provides a review mechanism for actions requiring human intervention.

Features include:

* Persistent approval requests
* Pending, approved, and rejected states
* Reviewer comments and timestamps
* Policy revalidation before approval
* Audit logging of relevant decisions
* Protection against duplicate resolution of the same pending request

### 🧪 Workflow Crash-Test Lab

Tests policy behavior using predefined workflow scenarios.

The scenarios cover:

* Permitted file operations
* Sensitive-data exfiltration attempts
* Destructive operations requiring review
* Malformed and suspicious actions
* Multi-stage workflows containing different risk levels
* Command execution restrictions

The lab compares actual policy decisions against expected outcomes without running dangerous operations on the host system.

### 🤖 AI-Assisted Intent Analysis

Accepts natural-language instructions and converts them into structured action proposals.

For example:

> Read the file report.txt and then write a summary to summary.txt.

The analyzer identifies proposed actions, extracts parameters, flags ambiguity, assigns risk indicators, and evaluates each proposal using the policy engine.

**Important:** This prototype uses heuristic, rule-based natural-language processing, not a live LLM. Intent Analysis generates proposals for evaluation; it does not execute them.

### 📋 Audit Logging

Records relevant policy evaluations and execution attempts in an SQLite database.

The dashboard provides access to recent audit entries and their associated decisions and statuses.

### 📊 Interactive Web Dashboard

Provides a unified interface for exploring policy decisions, testing actions, reviewing approval requests, running crash-test scenarios, analyzing natural-language instructions, and inspecting audit records.

---

## 🔄 4. How It Works

The system follows a safety-first workflow:

1. **Receive an action or natural-language instruction.**
2. **Analyze the proposed operation** and extract relevant parameters.
3. **Evaluate the action against the policy engine.**
4. **Assign a decision:** `ALLOW`, `REVIEW`, or `BLOCK`.
5. **Route review-required actions** through the human approval workflow where applicable.
6. **Process permitted actions through the controlled execution layer.**
7. **Record relevant decisions and execution attempts** in the audit log.
8. **Test policy behavior** using the Workflow Crash-Test Lab.

### Example

Suppose an agent proposes to delete a file.

ActionShield AI evaluates the request before execution. Under the prototype's default rules, file deletion requires review rather than being automatically permitted.

The request can then be reviewed through the approval workflow. The system also records the relevant decisions so that the workflow can be inspected later.

This illustrates the central principle behind ActionShield AI:

**Evaluate first. Approve when necessary. Execute only through controlled pathways. Record the outcome.**

---

## 🏗️ 5. System Architecture

The prototype consists of the following components:

| Component          | Responsibility                                  | Technology                       |
| ------------------ | ----------------------------------------------- | -------------------------------- |
| Web dashboard      | User interface and interaction                  | React, Vite, JavaScript, CSS     |
| API layer          | Exposes application endpoints                   | FastAPI                          |
| Policy engine      | Evaluates action safety                         | Python                           |
| Intent analyzer    | Converts natural language into action proposals | Python, heuristic rule-based NLP |
| Execution service  | Processes permitted simulated actions           | Python, in-memory workspace      |
| Approval service   | Manages human review and resolution             | Python, SQLite                   |
| Crash-test service | Runs predefined safety scenarios                | Python                           |
| Audit service      | Records decisions and execution attempts        | Python, SQLite                   |
| Automated tests    | Verifies application behavior                   | Pytest                           |

### High-level workflow

```text
          User / AI Agent
                 |
                 v
       Proposed Action or Intent
                 |
                 v
       ActionShield AI Backend
                 |
                 v
           Policy Engine
                 |
        +--------+--------+
        |        |        |
        v        v        v
      ALLOW    REVIEW    BLOCK
        |        |        |
        v        v        v
    Controlled Human     Reject
    Simulation  Approval  Action
        |        |
        +--------+
             |
             v
         Audit Log

Workflow Crash-Test Lab
tests policy decisions and
safety behavior independently.
```

---

## 🧰 6. Technology Stack

### Backend

* Python
* FastAPI
* Uvicorn
* Pydantic

### Frontend

* React
* Vite
* JavaScript
* HTML and CSS

### Database

* SQLite

### Testing

* Pytest
* Automated unit and API tests
* Frontend production build verification

### Development Environment

* Antigravity IDE
* Git and GitHub

---

## 🚀 7. Getting Started

### Prerequisites

Install the following:

* Python 3.10 or a compatible version supported by the project's dependencies
* Node.js and npm
* Git (optional for cloning the repository)

### Step 1: Clone the repository

Replace `<your-github-username>` with your GitHub username.

```bash
git clone https://github.com/<your-github-username>/ActionShield-AI.git
cd ActionShield-AI
```

### Step 2: Set up the Python environment

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On Linux or macOS:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Start the backend

From the project root:

```bash
uvicorn app.main:app --reload --port 8000
```

The backend will be available at:

* API: `http://127.0.0.1:8000`
* Health check: `http://127.0.0.1:8000/health`
* Interactive API documentation: `http://127.0.0.1:8000/docs`

### Step 4: Install frontend dependencies

Open a second terminal from the project root:

```bash
cd frontend
npm install
```

### Step 5: Start the frontend

```bash
npm run dev
```

Open the dashboard at:

`http://localhost:5173`

Keep both development servers running while using the locally hosted application.

---

## 🔌 8. Main API Endpoints

The prototype exposes endpoints for health checks, policy evaluation, simulated execution, approval management, crash testing, intent analysis, and audit logging.

| Endpoint                               | Method     | Purpose                                                    |
| -------------------------------------- | ---------- | ---------------------------------------------------------- |
| `/health`                              | GET        | Check backend availability                                 |
| `/evaluate`                            | POST       | Evaluate an action against the policy engine               |
| `/execute`                             | POST       | Process an action through the controlled execution service |
| `/audit`                               | GET        | Retrieve recent audit records                              |
| `/approvals`                           | GET / POST | Retrieve or create eligible approval requests              |
| `/approvals/pending`                   | GET        | Retrieve pending approval requests                         |
| `/approvals/{request_id}`              | GET        | Retrieve an approval request                               |
| `/approvals/{request_id}/approve`      | POST       | Approve a pending request                                  |
| `/approvals/{request_id}/reject`       | POST       | Reject a pending request                                   |
| `/crash-tests/scenarios`               | GET        | List predefined test scenarios                             |
| `/crash-tests/scenarios/{scenario_id}` | GET        | Retrieve a specific scenario                               |
| `/crash-tests/run/{scenario_id}`       | POST       | Run a specific scenario                                    |
| `/crash-tests/run-all`                 | POST       | Run the complete scenario suite                            |
| `/intent/analyze`                      | POST       | Analyze a natural-language instruction                     |

For the exact request and response schemas, run the backend and visit `/docs`.

---

## 🧪 9. Running Tests

From the project root, activate the Python virtual environment and run:

```bash
python -m pytest -v
```

To build the frontend:

```bash
cd frontend
npm run build
```

The implementation reports recorded 133 passing backend tests following the Intent Analysis fix. Run the commands above against the current repository to verify its present status.

---

## 🔒 10. Safety Design and Limitations

ActionShield AI is a hackathon prototype demonstrating a policy-driven safety architecture.

Its current implementation includes:

* Deterministic policy evaluation
* Review and block decisions for applicable risky actions
* Policy revalidation during approval
* Controlled, in-memory action simulation
* Isolated crash-test scenarios
* Audit logging
* Input validation and ambiguity detection in Intent Analysis

### Current limitations

* Action execution is simulated in memory rather than performed on real files or external systems.
* Intent Analysis uses heuristic, rule-based NLP rather than a live LLM.
* Natural-language interpretation may not correctly understand every complex instruction.
* The application does not implement production-grade user authentication or role-based approval authorization.
* The prototype has not been established as a production-ready security boundary for arbitrary AI agents.
* Persistent database behavior depends on the deployment environment and its storage configuration.

These limitations are intentional considerations for the current prototype and identify areas for future development.

---

## 🔮 11. Future Scope

Potential future improvements include:

* Integration with real AI agents through standardized action interfaces
* LLM-assisted intent interpretation with deterministic policy enforcement
* Stronger workspace-boundary validation for real filesystem operations
* Authentication and role-based human approvals
* Configurable organizational policies
* More advanced adversarial workflow testing
* Persistent production database infrastructure
* Deployment monitoring and security event alerts
* Integration with additional agent frameworks and automation platforms

---

## 🎯 12. Project Objective

ActionShield AI explores a practical approach to AI-agent safety by placing a policy-driven checkpoint between an agent's intentions and its proposed actions.

The goal is to demonstrate how controlled execution, human oversight, systematic safety testing, and auditability can work together to make automated workflows more transparent and manageable.

**Built as a software prototype for YUKTHI 2026 — AI & Automation.**
