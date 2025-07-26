export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type IssueType = 'security' | 'quality' | 'performance' | 'best-practice' | 'bug';

export interface CodeIssue {
    title: string;
    description: string;
    severity: Severity;
    type: IssueType;
    line?: number;
    column?: number;
    rule?: string;
    recommendation?: string;
    codeSnippet?: string;
}

export interface DiffAnalysisRequest {
    diffContent: string;
    filePath: string;
    language?: string;
    includeSecurity?: boolean;
}

export interface FileAnalysis {
    fileName: string;
    language: string;
    lineCount: number;
    issues: CodeIssue[];
    metrics: {
        complexity: number;
        maintainability: number;
        duplicateLines: number;
    };
}

export class CodeAnalyzer {
    private languageDetectors: Map<string, RegExp> = new Map([
        ['javascript', /\.(js|jsx|mjs|cjs)$/i],
        ['typescript', /\.(ts|tsx)$/i],
        ['python', /\.py$/i],
        ['java', /\.java$/i],
        ['csharp', /\.cs$/i],
        ['cpp', /\.(cpp|cxx|cc|c\+\+)$/i],
        ['c', /\.c$/i],
        ['php', /\.php$/i],
        ['ruby', /\.rb$/i],
        ['go', /\.go$/i],
        ['rust', /\.rs$/i],
        ['kotlin', /\.kt$/i],
        ['swift', /\.swift$/i],
        ['sql', /\.sql$/i],
        ['shell', /\.(sh|bash|zsh)$/i],
        ['yaml', /\.(yml|yaml)$/i],
        ['json', /\.json$/i],
        ['xml', /\.xml$/i],
        ['html', /\.(html|htm)$/i],
        ['css', /\.css$/i],
        ['scss', /\.scss$/i],
        ['less', /\.less$/i],
    ]);

    private securityPatterns: Map<string, {
        pattern: RegExp;
        severity: Severity;
        title: string;
        description: string;
        recommendation: string;
    }[]> = new Map([
        ['javascript', [
            {
                pattern: /eval\s*\(/gi,
                severity: 'high',
                title: 'Use of eval()',
                description: 'The eval() function can execute arbitrary code and is a security risk.',
                recommendation: 'Avoid using eval(). Consider JSON.parse() for JSON data or other safer alternatives.'
            },
            {
                pattern: /innerHTML\s*=/gi,
                severity: 'medium',
                title: 'Potential XSS via innerHTML',
                description: 'Setting innerHTML with user input can lead to XSS vulnerabilities.',
                recommendation: 'Use textContent, createTextNode, or sanitize input before setting innerHTML.'
            },
            {
                pattern: /document\.write\s*\(/gi,
                severity: 'medium',
                title: 'Use of document.write()',
                description: 'document.write() can be dangerous and affect page loading.',
                recommendation: 'Use modern DOM manipulation methods instead.'
            },
            {
                pattern: /setTimeout\s*\(\s*["'].*["']\s*,/gi,
                severity: 'medium',
                title: 'setTimeout with string',
                description: 'Using setTimeout with a string argument can lead to code injection.',
                recommendation: 'Use setTimeout with a function instead of a string.'
            },
            {
                pattern: /console\.log\(/gi,
                severity: 'low',
                title: 'Console.log in production',
                description: 'Console statements may leak sensitive information in production.',
                recommendation: 'Remove console statements before deploying to production.'
            },
        ]],
        ['typescript', [
            {
                pattern: /any(?!\w)/gi,
                severity: 'medium',
                title: 'Use of any type',
                description: 'Using "any" type defeats the purpose of TypeScript type checking.',
                recommendation: 'Use specific types or interfaces instead of "any".'
            },
            {
                pattern: /@ts-ignore/gi,
                severity: 'medium',
                title: 'TypeScript ignore directive',
                description: 'Using @ts-ignore suppresses type checking and may hide errors.',
                recommendation: 'Fix the underlying type issue instead of ignoring it.'
            },
        ]],
        ['python', [
            {
                pattern: /exec\s*\(/gi,
                severity: 'critical',
                title: 'Use of exec()',
                description: 'The exec() function can execute arbitrary code and is a major security risk.',
                recommendation: 'Avoid using exec(). Find safer alternatives for dynamic code execution.'
            },
            {
                pattern: /eval\s*\(/gi,
                severity: 'critical',
                title: 'Use of eval()',
                description: 'The eval() function can execute arbitrary code and is a major security risk.',
                recommendation: 'Avoid using eval(). Use ast.literal_eval() for safe evaluation of literals.'
            },
            {
                pattern: /input\s*\(/gi,
                severity: 'medium',
                title: 'Use of input()',
                description: 'The input() function in Python 2 can execute arbitrary code.',
                recommendation: 'Use raw_input() in Python 2 or ensure you\'re using Python 3.'
            },
            {
                pattern: /pickle\.loads?\(/gi,
                severity: 'high',
                title: 'Use of pickle.load/loads',
                description: 'Pickle can execute arbitrary code when deserializing untrusted data.',
                recommendation: 'Use JSON or other safe serialization formats for untrusted data.'
            },
        ]],
        ['sql', [
            {
                pattern: /['"].+\+.+['"]|['"].+\%.+['"]|['"].+f['"].*\{/gi,
                severity: 'critical',
                title: 'Potential SQL Injection',
                description: 'String concatenation in SQL queries can lead to SQL injection.',
                recommendation: 'Use parameterized queries or prepared statements.'
            },
        ]],
        ['php', [
            {
                pattern: /eval\s*\(/gi,
                severity: 'critical',
                title: 'Use of eval()',
                description: 'The eval() function can execute arbitrary PHP code.',
                recommendation: 'Avoid using eval(). Find safer alternatives.'
            },
            {
                pattern: /\$_GET|\$_POST|\$_REQUEST|\$_COOKIE/gi,
                severity: 'medium',
                title: 'Direct use of superglobals',
                description: 'Direct use of superglobals without validation can be dangerous.',
                recommendation: 'Validate and sanitize all user input from superglobals.'
            },
        ]],
    ]);

    private qualityPatterns: Map<string, {
        pattern: RegExp;
        severity: Severity;
        title: string;
        description: string;
        recommendation: string;
    }[]> = new Map([
        ['javascript', [
            {
                pattern: /^.{120,}$/gm,
                severity: 'low',
                title: 'Long line',
                description: 'Lines longer than 120 characters are hard to read.',
                recommendation: 'Break long lines into multiple shorter lines.'
            },
            {
                pattern: /function\s+\w+\s*\([^)]*\)\s*\{[^}]*\{[^}]*\{[^}]*\{/gi,
                severity: 'medium',
                title: 'Deep nesting',
                description: 'Functions with deep nesting are hard to understand and maintain.',
                recommendation: 'Extract nested logic into separate functions.'
            },
            {
                pattern: /var\s+/gi,
                severity: 'low',
                title: 'Use of var',
                description: 'Using "var" can lead to unexpected behavior due to hoisting.',
                recommendation: 'Use "let" or "const" instead of "var".'
            },
        ]],
        ['python', [
            {
                pattern: /^.{79,}$/gm,
                severity: 'low',
                title: 'Long line',
                description: 'Lines longer than 79 characters violate PEP 8.',
                recommendation: 'Break long lines according to PEP 8 guidelines.'
            },
            {
                pattern: /except\s*:/gi,
                severity: 'medium',
                title: 'Bare except clause',
                description: 'Bare except clauses can hide errors and make debugging difficult.',
                recommendation: 'Catch specific exceptions instead of using bare except.'
            },
        ]],
    ]);

    async analyzeDiff(request: DiffAnalysisRequest): Promise<FileAnalysis> {
        const { diffContent, filePath, language, includeSecurity = true } = request;

        const detectedLanguage = language || this.detectLanguage(filePath);
        const issues: CodeIssue[] = [];

        // Parse diff to extract added/modified lines
        const addedLines = this.extractAddedLines(diffContent);

        // Analyze for security issues
        if (includeSecurity) {
            issues.push(...this.analyzeSecurityIssues(addedLines, detectedLanguage));
        }

        // Analyze for code quality issues
        issues.push(...this.analyzeQualityIssues(addedLines, detectedLanguage));

        // Analyze for best practices
        issues.push(...this.analyzeBestPractices(addedLines, detectedLanguage));

        return {
            fileName: filePath,
            language: detectedLanguage,
            lineCount: addedLines.length,
            issues,
            metrics: {
                complexity: this.calculateComplexity(addedLines, detectedLanguage),
                maintainability: this.calculateMaintainability(addedLines, detectedLanguage),
                duplicateLines: this.findDuplicateLines(addedLines),
            },
        };
    }

    private detectLanguage(filePath: string): string {
        for (const [language, pattern] of this.languageDetectors) {
            if (pattern.test(filePath)) {
                return language;
            }
        }
        return 'unknown';
    }

    private extractAddedLines(diffContent: string): { line: string; lineNumber: number }[] {
        const lines = diffContent.split('\n');
        const addedLines: { line: string; lineNumber: number }[] = [];
        let currentLineNumber = 0;

        for (const line of lines) {
            if (line.startsWith('@@')) {
                // Parse line number from diff header
                const match = line.match(/\+(\d+)/);
                if (match) {
                    currentLineNumber = parseInt(match[1], 10);
                }
                continue;
            }

            if (line.startsWith('+') && !line.startsWith('+++')) {
                addedLines.push({
                    line: line.substring(1), // Remove the '+' prefix
                    lineNumber: currentLineNumber,
                });
            }

            if (!line.startsWith('-')) {
                currentLineNumber++;
            }
        }

        return addedLines;
    }

    private analyzeSecurityIssues(lines: { line: string; lineNumber: number }[], language: string): CodeIssue[] {
        const issues: CodeIssue[] = [];
        const patterns = this.securityPatterns.get(language) || [];

        for (const { line, lineNumber } of lines) {
            for (const { pattern, severity, title, description, recommendation } of patterns) {
                if (pattern.test(line)) {
                    issues.push({
                        title,
                        description,
                        severity,
                        type: 'security',
                        line: lineNumber,
                        recommendation,
                        codeSnippet: line.trim(),
                    });
                }
            }
        }

        return issues;
    }

    private analyzeQualityIssues(lines: { line: string; lineNumber: number }[], language: string): CodeIssue[] {
        const issues: CodeIssue[] = [];
        const patterns = this.qualityPatterns.get(language) || [];

        for (const { line, lineNumber } of lines) {
            for (const { pattern, severity, title, description, recommendation } of patterns) {
                if (pattern.test(line)) {
                    issues.push({
                        title,
                        description,
                        severity,
                        type: 'quality',
                        line: lineNumber,
                        recommendation,
                        codeSnippet: line.trim(),
                    });
                }
            }
        }

        return issues;
    }

    private analyzeBestPractices(lines: { line: string; lineNumber: number }[], language: string): CodeIssue[] {
        const issues: CodeIssue[] = [];

        // Common best practice checks across languages
        for (const { line, lineNumber } of lines) {
            // Check for hardcoded secrets
            if (this.containsHardcodedSecret(line)) {
                issues.push({
                    title: 'Potential hardcoded secret',
                    description: 'This line may contain a hardcoded password, API key, or other secret.',
                    severity: 'high',
                    type: 'security',
                    line: lineNumber,
                    recommendation: 'Use environment variables or a secure configuration system for secrets.',
                    codeSnippet: line.trim(),
                });
            }

            // Check for TODO/FIXME comments
            if (/(?:TODO|FIXME|HACK|XXX):/i.test(line)) {
                issues.push({
                    title: 'TODO/FIXME comment',
                    description: 'This code contains a TODO or FIXME comment indicating incomplete work.',
                    severity: 'low',
                    type: 'best-practice',
                    line: lineNumber,
                    recommendation: 'Address the TODO/FIXME comment or create a proper issue to track it.',
                    codeSnippet: line.trim(),
                });
            }

            // Check for commented-out code
            if (this.isCommentedOutCode(line, language)) {
                issues.push({
                    title: 'Commented-out code',
                    description: 'This line appears to contain commented-out code.',
                    severity: 'low',
                    type: 'best-practice',
                    line: lineNumber,
                    recommendation: 'Remove commented-out code and rely on version control for history.',
                    codeSnippet: line.trim(),
                });
            }
        }

        return issues;
    }

    private containsHardcodedSecret(line: string): boolean {
        const secretPatterns = [
            /password\s*[=:]\s*['"][^'"]+['"]/i,
            /api[_-]?key\s*[=:]\s*['"][^'"]+['"]/i,
            /secret\s*[=:]\s*['"][^'"]+['"]/i,
            /token\s*[=:]\s*['"][^'"]+['"]/i,
            /private[_-]?key\s*[=:]\s*['"][^'"]+['"]/i,
            /access[_-]?key\s*[=:]\s*['"][^'"]+['"]/i,
        ];

        return secretPatterns.some(pattern => pattern.test(line));
    }

    private isCommentedOutCode(line: string, language: string): boolean {
        const trimmed = line.trim();

        // Language-specific comment patterns
        const commentPatterns: { [key: string]: RegExp[] } = {
            javascript: [/^\/\/\s*\w+\s*\(/],
            typescript: [/^\/\/\s*\w+\s*\(/],
            python: [/^#\s*\w+\s*\(/],
            java: [/^\/\/\s*\w+\s*\(/],
            csharp: [/^\/\/\s*\w+\s*\(/],
            cpp: [/^\/\/\s*\w+\s*\(/],
            c: [/^\/\/\s*\w+\s*\(/],
        };

        const patterns = commentPatterns[language] || [];
        return patterns.some(pattern => pattern.test(trimmed));
    }

    private calculateComplexity(lines: { line: string; lineNumber: number }[], language: string): number {
        let complexity = 1; // Base complexity

        for (const { line } of lines) {
            // Count decision points (if, else, while, for, etc.)
            const decisionPatterns = [
                /\bif\b/gi,
                /\belse\b/gi,
                /\bwhile\b/gi,
                /\bfor\b/gi,
                /\bswitch\b/gi,
                /\bcatch\b/gi,
                /\?\s*.*\s*:/gi, // ternary operator
            ];

            for (const pattern of decisionPatterns) {
                const matches = line.match(pattern);
                if (matches) {
                    complexity += matches.length;
                }
            }
        }

        return Math.min(complexity, 10); // Cap at 10
    }

    private calculateMaintainability(lines: { line: string; lineNumber: number }[], language: string): number {
        let score = 100; // Start with perfect score

        // Reduce score based on various factors
        const lineCount = lines.length;
        if (lineCount > 50) score -= (lineCount - 50) * 0.5;

        const complexity = this.calculateComplexity(lines, language);
        score -= (complexity - 1) * 5;

        // Check for long lines
        const longLines = lines.filter(({ line }) => line.length > 120).length;
        score -= longLines * 2;

        return Math.max(Math.round(score), 0);
    }

    private findDuplicateLines(lines: { line: string; lineNumber: number }[]): number {
        const lineMap = new Map<string, number>();
        let duplicates = 0;

        for (const { line } of lines) {
            const trimmed = line.trim();
            if (trimmed.length > 5) { // Only consider substantial lines
                const count = lineMap.get(trimmed) || 0;
                lineMap.set(trimmed, count + 1);
                if (count === 1) {
                    duplicates++;
                }
            }
        }

        return duplicates;
    }
} 
