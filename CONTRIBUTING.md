# Contributing to Sage

Thank you for your interest in contributing to Sage.

## Development Setup

```bash
git clone https://github.com/avast/sage
cd sage
pnpm install
pnpm build
pnpm test
```

Requires Node.js >= 18 and pnpm >= 9. See [Development](docs/development.md) for the full command reference.

## Making Changes

1. Create a branch from `main`
2. Make your changes
3. Run `pnpm test` and `pnpm check` to verify
4. Run `pnpm lint:fix` to format code
5. Submit a pull request

Keep PRs focused on a single change. Include tests for new functionality.

## Licensing of Contributions

This project uses a dual-license structure. By submitting a pull request, you
agree that your contribution will be licensed under the applicable license:

- **Source code** (everything except `threats/`): your contribution is licensed
  under the [Apache License 2.0](LICENSE).
- **Threat detection rules** (`threats/*.yaml`): your contribution is licensed
  under the [Detection Rule License 1.1](threats/LICENSE). Please include an
  `author` field in your rules for proper attribution.

## Contributing Threat Rules

Threat rules live in `threats/*.yaml`. Each rule must include:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g. `CLT-CMD-001`) |
| `category` | string | `tool`, `network_egress`, `secrets`, or `supply_chain` |
| `severity` | enum | `critical`, `high`, `medium`, or `low` |
| `confidence` | float | 0.0-1.0 |
| `action` | enum | `block`, `require_approval`, or `log` |
| `pattern` | string | Regex pattern |
| `match_on` | string or list | `command`, `url`, `file_path`, `content`, or `domain` |
| `title` | string | Human-readable description |
| `expires_at` | string or null | ISO 8601 date or `null` for permanent |
| `revoked` | boolean | Set `true` to disable without removing |

See [Threat Rules](docs/threat-rules.md) for the full format reference and examples.

## Coding Conventions

- **Naming:** YAML/JSON data uses `snake_case`; TypeScript uses `camelCase`
- **Fail-open:** Every error path must return an `allow` verdict
- **Formatting:** Biome handles linting and formatting (tabs, double quotes, semicolons)
- **Testing:** Add tests for new functionality. Unit tests go in `packages/core/src/__tests__/`

## Reporting Issues

Use GitHub Issues for bugs and feature requests.

**Security vulnerabilities:** Please report privately via [GitHub Security Advisories](https://github.com/avast/sage/security/advisories/new). Do not open public issues for security bugs.
