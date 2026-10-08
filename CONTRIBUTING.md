# Contributing to Guardrail API

Thank you for your interest in contributing to **Guardrail API**! We welcome contributions from the community to make API security auditing faster, smarter, and accessible to everyone.

---

## 🛠️ Local Development Setup

### Prerequisites
- [Node.js](https://nodejs.org) >= 20
- [pnpm](https://pnpm.io) >= 9

### Getting Started

1. **Fork and Clone** the repository:
   ```bash
   git clone https://github.com/CodeJairo/guardrail-api.git
   cd guardrail-api
   ```

2. **Install Dependencies**:
   ```bash
   pnpm install
   ```

3. **Build the Project**:
   ```bash
   pnpm run build
   ```

4. **Run the Test Suite**:
   ```bash
   pnpm test
   ```

---

## 📐 Project Architecture

- `src/cli/`: Command-line options, Commander commands, and exit code logic.
- `src/parser/`: OpenAPI v2 & v3 loader, dereferencing, and unified normalizer.
- `src/rules/`:
  - `static/`: Static specification analysis rules (e.g., missing authentication, schema validation).
  - `dynamic/`: Active probes against running API instances (e.g., missing auth enforcement, CORS, security headers, fuzzing).
- `src/engine/`: Scanner coordinator, HTTP client, and finding aggregation.
- `src/reporter/`: Multi-format report generators (console table, JSON, Markdown, HTML, SARIF 2.1.0).
- `src/config/`: Configuration loader (`.guardrailrc.json`).

---

## 🛡️ Adding a New Security Rule

1. Decide whether the rule is **static** (examines the spec) or **dynamic** (probes a live endpoint).
2. Implement your rule in `src/rules/static/my-rule.ts` or `src/rules/dynamic/my-rule.ts`.
3. Adhere to the `StaticRule` or `DynamicRule` interface in `src/rules/types.ts`.
4. Register the new rule in [`src/rules/registry.ts`](file:///home/codejairo/Proyectos/api-security-cli/src/rules/registry.ts).
5. Add unit and integration tests under `test/unit/`.

---

## 📝 Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` A new feature or security rule.
- `fix:` A bug fix in parsing, rule evaluation, or reporting.
- `docs:` Documentation improvements.
- `test:` Adding or refactoring tests.
- `chore:` Dependency updates, configuration, or maintenance.

---

## 🚀 Submitting a Pull Request

1. Create a feature branch: `git checkout -b feat/my-new-rule`.
2. Commit your changes following conventional commits.
3. Verify that all tests pass: `pnpm test` and `pnpm run build`.
4. Open a Pull Request on GitHub against `main` using the PR template.
