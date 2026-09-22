# acpplinter

A fast, configurable C++ linter written in Rust that scans source files for code style violations using regex-based rules.

## Features

- **Regex-based rules**: Define custom lint rules using regular expressions
- **File limits**: Enforce maximum file sizes and line counts
- **Configurable via JSON**: Easy-to-edit configuration file for rules and paths

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/acpplinter`.

## Usage

```bash
acpplinter <config.json> [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `-r, --root_path <path>` | Root folder for source files (defaults to config file's directory) |
| `-o, --output <file>` | Output file path (defaults to stdout) |
| `--ignore-safe` | Ignore `/*safe*/` tags and show all warnings |
| `--vs-log` | Use Visual Studio-compatible log format |
| `--json-log <file>` | Output warnings as structured JSON to the specified file |
| `--replace-original-with-preprocessed` | Debug option to see preprocessed files |

### Example

```bash
acpplinter example.json -r ./src
```

## Configuration

The configuration is a JSON file with the following structure:

```json
{
  "roots": ["src", "include"],
  "includes": [".cpp$", ".h$"],
  "excludes": ["third_party"],
  "removeStrings": true,
  "removeComments": true,
  "safeTag": "safe",
  "fileLimits": [...],
  "tests": [...]
}
```

### Top-level Options

| Field | Type | Description |
|-------|------|-------------|
| `roots` | `string[]` | Directories to scan |
| `includes` | `string[]` | Regex patterns for files to include |
| `excludes` | `string[]` | Regex patterns for files to exclude |
| `removeStrings` | `bool` | Strip string literals before linting (default: true) |
| `removeComments` | `bool` | Strip comments before linting (default: true) |
| `safeTag` | `string` | Tag to mark code as safe (default: "safe") |
| `fileLimits` | `object[]` | Optional file size and line-count rules |
| `tests` | `object[]` | Array of lint rules |

### File Limit Rules

Each file limit rule (`fileLimits`) supports:

| Field | Type | Description |
|-------|------|-------------|
| `max_bytes` | `number` | Maximum file size in bytes (inclusive) |
| `max_lines` | `number` | Maximum number of lines (inclusive) |
| `max_bytes_error` | `string` | Error message when `max_bytes` is exceeded |
| `max_lines_error` | `string` | Error message when `max_lines` is exceeded |
| `include_paths` | `string[]` | Only check files matching these patterns |
| `exclude_paths` | `string[]` | Skip files matching these patterns |

At least one limit and its corresponding error message should be provided. If both limits are exceeded, the rule emits both warnings.

```json
{
  "max_bytes": 350000,
  "max_lines": 10000,
  "include_paths": ["\\.cpp$", "\\.h$"],
  "exclude_paths": ["generated"],
  "max_bytes_error": "Source file is too large",
  "max_lines_error": "Source file has too many lines"
}
```

### Test Rules

Each test rule supports:

| Field | Type | Description |
|-------|------|-------------|
| `fail` | `string[]` | Regex patterns that trigger a warning |
| `allow` | `string[]` | Regex patterns that suppress the warning |
| `error` | `string` | Error message to display |
| `classOnly` | `bool` | Only apply inside class definitions |
| `headerOnly` | `bool` | Only apply to header files |
| `include_paths` | `string[]` | Only check files matching these patterns |
| `exclude_paths` | `string[]` | Skip files matching these patterns |
| `expected_fails` | `object` | Expected number of matches (e.g., `{"exactly": 1}`) |

### Example Rule

```json
{
  "fail": ["[^A-Za-z0-9_]+new\\s+"],
  "allow": ["ref new\\s+"],
  "error": "Don't use new, use an owning pointer or container instead"
}
```

## Exit Codes

- `0`: No issues found
- `1`: Issues found or error occurred

## Releases

This project uses [semantic-release](https://semantic-release.gitbook.io/) for automated versioning and GitHub releases.

### How It Works

1. Push commits to the `master` branch
2. semantic-release analyzes commit messages to determine the next version
3. A Windows build is created and packaged as `acpplinter.zip`
4. A GitHub release is published with the zip artifact

### Commit Message Format

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/):

| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `fix:` | Patch (0.0.x) | `fix: handle empty config file` |
| `feat:` | Minor (0.x.0) | `feat: add JSON output format` |
| `feat!:` or `BREAKING CHANGE:` | Major (x.0.0) | `feat!: change config schema` |

Other prefixes like `docs:`, `chore:`, `ci:`, `refactor:`, `test:` do not trigger a release.

### Downloading

Pre-built Windows binaries are available on the [Releases](../../releases) page. Download `acpplinter.zip` and extract `acpplinter.exe`.

## License

MIT
