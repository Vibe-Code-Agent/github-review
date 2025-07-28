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

async function callCopilotForSecurityAnalysis(code: string, language: string): Promise<CodeIssue[]> {
    try {
        const apiKey = process.env.GITHUB_TOKEN;
        if (!apiKey) {
            console.warn('GITHUB_TOKEN not found, skipping Copilot analysis');
            return [];
        }

        const prompt = `Analyze the following ${language} code for security vulnerabilities and return a JSON array of issues. 

Each issue should have this structure:
{
    "title": "Brief issue title",
    "description": "Detailed description of the security issue",
    "severity": "low|medium|high|critical",
    "type": "security",
    "line": number (if applicable),
    "rule": "security rule identifier",
    "recommendation": "How to fix this issue",
    "codeSnippet": "relevant code snippet"
}

Focus on common security vulnerabilities like:
- SQL injection
- XSS vulnerabilities  
- Authentication/authorization issues
- Input validation problems
- Cryptographic issues
- Insecure data handling
- Path traversal
- Command injection

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
            return Array.isArray(issues) ? issues : [];
        } catch (parseError) {
            console.error('Failed to parse Copilot response as JSON:', parseError);
            return [];
        }

    } catch (error) {
        console.error('Copilot API analysis failed:', error);
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

        // Analyze for security issues using GitHub Copilot
        if (includeSecurity) {
            const codeToAnalyze = addedLines.map(l => l.line).join('\n');
            const copilotIssues = await callCopilotForSecurityAnalysis(codeToAnalyze, detectedLanguage);
            // Optionally, map line numbers if Copilot returns them differently
            issues.push(...copilotIssues);
        }

        // Analyze for code quality issues (local, not via Claude)
        issues.push(...this.analyzeQualityIssues(addedLines, detectedLanguage));

        // Analyze for best practices (local, not via Claude)
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

    // The following methods remain local and do not use Claude

    private analyzeQualityIssues(lines: { line: string; lineNumber: number }[], language: string): CodeIssue[] {
        // You can keep your local quality patterns or call Claude for quality if desired
        // For now, this is a stub that returns an empty array
        return [];
    }

    private analyzeBestPractices(lines: { line: string; lineNumber: number }[], language: string): CodeIssue[] {
        // You can keep your local best practice checks or call Claude for best-practices if desired
        // For now, this is a stub that returns an empty array
        return [];
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
