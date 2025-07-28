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

import axios from 'axios';

async function callCopilotForAnalysis(code: string, language: string, analysisType: IssueType): Promise<CodeIssue[]> {
    try {
        const apiKey = process.env.GITHUB_TOKEN;
        if (!apiKey) {
            console.warn('GITHUB_TOKEN not found, skipping Copilot analysis');
            return [];
        }

        const prompts = {
            security: `Analyze the following ${language} code for security vulnerabilities and return a JSON array of issues.

Focus on common security vulnerabilities like:
- SQL injection
- XSS vulnerabilities  
- Authentication/authorization issues
- Input validation problems
- Cryptographic issues
- Insecure data handling
- Path traversal
- Command injection
- Hardcoded credentials/secrets
- Weak cryptography
- Insecure random number generation`,

            quality: `Analyze the following ${language} code for quality issues and return a JSON array of issues.

Focus on code quality issues like:
- Code complexity (cyclomatic complexity, nesting depth)
- Code duplication
- Long methods/functions
- Large classes
- Magic numbers and strings
- Poor naming conventions
- Long parameter lists
- Dead code
- Code smells
- Maintainability issues`,

            performance: `Analyze the following ${language} code for performance issues and return a JSON array of issues.

Focus on performance problems like:
- Inefficient algorithms
- Memory leaks
- Unnecessary object creation
- Inefficient loops
- Database query optimization
- Caching opportunities
- Resource management
- Blocking operations
- CPU-intensive operations
- Network optimization`,

            'best-practice': `Analyze the following ${language} code for best practice violations and return a JSON array of issues.

Focus on best practice violations like:
- Language-specific conventions
- Design patterns misuse
- Error handling practices
- Logging practices
- Code organization
- Documentation standards
- Testing practices
- Accessibility issues
- API design
- Code style consistency
- Framework-specific best practices`,

            bug: `Analyze the following ${language} code for potential bugs and return a JSON array of issues.

Focus on potential bugs like:
- Null pointer exceptions
- Array/buffer overflows
- Race conditions
- Logic errors
- Type mismatches
- Unhandled exceptions
- Resource leaks
- Infinite loops
- Off-by-one errors
- Concurrent access issues`
        };

        const prompt = `${prompts[analysisType]}

Each issue should have this structure:
{
    "title": "Brief issue title",
    "description": "Detailed description of the issue",
    "severity": "low|medium|high|critical",
    "type": "${analysisType}",
    "line": number (line number where issue occurs, if applicable),
    "rule": "rule identifier or pattern name",
    "recommendation": "Specific steps to fix this issue",
    "codeSnippet": "relevant code snippet showing the issue"
}

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

Return only valid JSON array of issues, no additional text.`;

        const model = process.env.COPILOT_MODEL || 'gpt-4o';

        const response = await axios.post(
            'https://api.githubcopilot.com/chat/completions',
            {
                model: model,
                max_tokens: 4000,
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ]
            },
            {
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                timeout: 30000
            }
        );

        const content = response.data.choices[0]?.message?.content;
        if (!content) {
            return [];
        }

        // Extract JSON from response if wrapped in markdown
        let jsonText = content.trim();
        const jsonMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
        if (jsonMatch) {
            jsonText = jsonMatch[1];
        }

        try {
            const issues: CodeIssue[] = JSON.parse(jsonText);
            return Array.isArray(issues) ? issues.filter(issue => issue.type === analysisType) : [];
        } catch (parseError) {
            console.error('Failed to parse Copilot response as JSON:', parseError);
            return [];
        }

    } catch (error) {
        console.error(`Copilot API ${analysisType} analysis failed:`, error);
        return [];
    }
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

    async analyzeDiff(request: DiffAnalysisRequest): Promise<FileAnalysis> {
        const { diffContent, filePath, language, includeSecurity = true } = request;

        const detectedLanguage = language || this.detectLanguage(filePath);
        const issues: CodeIssue[] = [];

        // Parse diff to extract added/modified lines
        const addedLines = this.extractAddedLines(diffContent);
        const codeToAnalyze = addedLines.map(l => l.line).join('\n');

        // Skip analysis if no meaningful code changes
        if (codeToAnalyze.trim().length === 0) {
            return {
                fileName: filePath,
                language: detectedLanguage,
                lineCount: addedLines.length,
                issues: [],
                metrics: {
                    complexity: 1,
                    maintainability: 100,
                    duplicateLines: 0,
                },
            };
        }

        // Analyze for all types of issues using GitHub Copilot
        const analysisTypes: IssueType[] = ['security', 'quality', 'best-practice', 'performance', 'bug'];
        
        for (const analysisType of analysisTypes) {
            // Skip security analysis if not requested
            if (analysisType === 'security' && !includeSecurity) {
                continue;
            }

            try {
                const copilotIssues = await callCopilotForAnalysis(codeToAnalyze, detectedLanguage, analysisType);
                // Map line numbers from analysis to actual diff line numbers
                const mappedIssues = this.mapLineNumbers(copilotIssues, addedLines);
                issues.push(...mappedIssues);
            } catch (error) {
                console.error(`Failed to analyze ${analysisType} issues:`, error);
            }
        }

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
                if (match && match[1] !== undefined) {
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

    private mapLineNumbers(issues: CodeIssue[], addedLines: { line: string; lineNumber: number }[]): CodeIssue[] {
        return issues.map(issue => {
            if (issue.line && issue.line <= addedLines.length) {
                const actualLineInfo = addedLines[issue.line - 1];
                if (actualLineInfo) {
                    return {
                        ...issue,
                        line: actualLineInfo.lineNumber
                    };
                }
            }
            return issue;
        });
    }


    private calculateComplexity(lines: { line: string; lineNumber: number }[], _language: string): number {
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
