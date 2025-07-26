# GitHub PR Review MCP Server

An MCP (Model Context Protocol) server for comprehensive GitHub Pull Request review, code analysis, and security issue detection.

## Features

- 🔍 **Comprehensive PR Analysis**: Analyzes pull requests for code quality, security vulnerabilities, and best practices
- 🛡️ **Security Scanning**: Detects common security issues and vulnerabilities across multiple programming languages
- 📊 **Code Quality Assessment**: Evaluates code maintainability, complexity, and adherence to best practices
- 🚨 **Risk Assessment**: Provides overall risk ratings and actionable recommendations
- 🔧 **Multi-language Support**: Supports JavaScript, TypeScript, Python, Java, C#, PHP, and more
- 📋 **Detailed Reporting**: Generates comprehensive review reports with file-level analysis

## Installation

### Prerequisites

- Node.js 18.0.0 or higher
- GitHub Personal Access Token with repository access

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/github-pr-review-mcp.git
cd github-pr-review-mcp
```

2. Install dependencies:
```bash
npm install
```

3. Build the project:
```bash
npm run build
```

4. Set up environment variables:
```bash
export GITHUB_TOKEN=your_github_personal_access_token
```

## Usage

### Running the MCP Server

```bash
npm start
```

The server will start and listen for MCP connections on stdio.

### Configuration in Cursor/Claude

Add the following configuration to your MCP settings:

```json
{
  "github-pr-review": {
    "command": "node",
    "args": ["/path/to/github-pr-review-mcp/dist/index.js"],
    "env": {
      "GITHUB_TOKEN": "your_github_token_here"
    }
  }
}
```

### Available Tools

#### 1. `get_pull_request`
Fetch pull request details including metadata and file changes.

**Parameters:**
- `owner` (string): Repository owner (username or organization)
- `repo` (string): Repository name
- `pull_number` (number): Pull request number

**Example:**
```
Get pull request microsoft/vscode #12345
```

#### 2. `review_pull_request`
Perform a comprehensive review of a pull request including code analysis, issue detection, and security checks.

**Parameters:**
- `owner` (string): Repository owner
- `repo` (string): Repository name
- `pull_number` (number): Pull request number
- `include_security` (boolean, optional): Include security analysis (default: true)
- `include_best_practices` (boolean, optional): Include best practices recommendations (default: true)
- `severity_threshold` (string, optional): Minimum severity level to report - "low", "medium", "high", or "critical" (default: "medium")

**Example:**
```
Review pull request microsoft/vscode #12345 with high severity threshold
```

#### 3. `analyze_code_diff`
Analyze specific code changes for issues and security vulnerabilities.

**Parameters:**
- `diff_content` (string): Git diff content to analyze
- `file_path` (string): Path of the file being analyzed
- `language` (string, optional): Programming language (auto-detected if not provided)
- `include_security` (boolean, optional): Include security analysis (default: true)

**Example:**
```
Analyze this diff for security issues:
```diff
+function validateUser(input) {
+  return eval(input.code);
+}
```

#### 4. `get_repository_prs`
List pull requests for a repository with filtering options.

**Parameters:**
- `owner` (string): Repository owner
- `repo` (string): Repository name
- `state` (string, optional): PR state filter - "open", "closed", or "all" (default: "open")
- `limit` (number, optional): Maximum number of PRs to return (default: 10, max: 100)
- `sort` (string, optional): Sort criteria - "created", "updated", "popularity", or "long-running" (default: "created")

**Example:**
```
List open pull requests for microsoft/vscode
```

## Security Analysis

The server detects various security issues including:

### JavaScript/TypeScript
- Use of `eval()` and similar dangerous functions
- XSS vulnerabilities via `innerHTML`
- Unsafe `setTimeout` usage
- TypeScript `any` type usage
- Hardcoded secrets and API keys

### Python
- Use of `exec()` and `eval()`
- Unsafe `pickle` usage
- Bare `except` clauses
- Input validation issues

### PHP
- SQL injection patterns
- Use of dangerous functions
- Unvalidated superglobal usage

### General
- Hardcoded passwords and API keys
- Commented-out code
- TODO/FIXME markers
- Long lines and code complexity

## Code Quality Assessment

The analyzer evaluates:

- **Complexity**: Cyclomatic complexity based on decision points
- **Maintainability**: Score based on line count, complexity, and readability
- **Duplicate Code**: Detection of repeated code patterns
- **Best Practices**: Language-specific coding standards
- **File Risk**: Assessment based on file types and patterns

## Risk Assessment

Each PR receives an overall risk rating:

- **Low**: Minor issues, safe to merge
- **Medium**: Some issues present, review recommended
- **High**: Security concerns or multiple issues
- **Critical**: Serious issues that block merging

## Development

### Project Structure

```
src/
├── index.ts              # Main MCP server
├── services/
│   ├── GitHubService.ts  # GitHub API interactions
│   ├── CodeAnalyzer.ts   # Code analysis engine
│   └── PRReviewer.ts     # PR review orchestrator
```

### Building

```bash
npm run build
```

### Development Mode

```bash
npm run dev
```

### Linting

```bash
npm run lint
```

### Testing

```bash
npm test
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Run the linter: `npm run lint`
6. Commit your changes: `git commit -am 'Add feature'`
7. Push to the branch: `git push origin feature-name`
8. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

If you discover a security vulnerability, please send an email to security@yourdomain.com. All security vulnerabilities will be promptly addressed.

## Changelog

### Version 1.0.0
- Initial release
- GitHub PR analysis
- Multi-language security scanning
- Code quality assessment
- Risk assessment and recommendations
