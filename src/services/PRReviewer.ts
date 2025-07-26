import { GitHubService, PullRequest, PullRequestFile } from './GitHubService';
import { CodeAnalyzer, FileAnalysis, Severity, CodeIssue } from './CodeAnalyzer';

export interface PRReviewRequest {
    owner: string;
    repo: string;
    pullNumber: number;
    includeSecurity?: boolean;
    includeBestPractices?: boolean;
    severityThreshold?: Severity;
}

export interface PRReviewSummary {
    totalIssues: number;
    criticalIssues: number;
    securityIssues: number;
    codeQualityIssues: number;
    bestPracticeIssues: number;
    overallRisk: 'low' | 'medium' | 'high' | 'critical';
    recommendation: string;
}

export interface PRReview {
    pullRequest: PullRequest;
    fileAnalyses: FileAnalysis[];
    summary: PRReviewSummary;
    analysis: {
        filesChanged: number;
        linesAdded: number;
        linesDeleted: number;
        riskFactors: string[];
        recommendations: string[];
    };
}

export class PRReviewer {
    constructor(
        private githubService: GitHubService,
        private codeAnalyzer: CodeAnalyzer
    ) { }

    async reviewPullRequest(request: PRReviewRequest): Promise<PRReview> {
        const {
            owner,
            repo,
            pullNumber,
            includeSecurity = true,
            includeBestPractices = true,
            severityThreshold = 'medium',
        } = request;

        try {
            // Fetch PR data
            const pullRequest = await this.githubService.getPullRequest(owner, repo, pullNumber);
            const files = await this.githubService.getPullRequestFiles(owner, repo, pullNumber);

            // Analyze each changed file
            const fileAnalyses: FileAnalysis[] = [];

            for (const file of files) {
                if (this.shouldAnalyzeFile(file)) {
                    try {
                        const analysis = await this.analyzeFile(file, {
                            includeSecurity,
                            includeBestPractices,
                        });

                        // Filter issues by severity threshold
                        analysis.issues = this.filterIssuesBySeverity(analysis.issues, severityThreshold);

                        if (analysis.issues.length > 0) {
                            fileAnalyses.push(analysis);
                        }
                    } catch (error) {
                        console.error(`Failed to analyze file ${file.filename}:`, error);
                        // Continue with other files
                    }
                }
            }

            // Generate summary and recommendations
            const summary = this.generateSummary(fileAnalyses);
            const analysis = this.generateAnalysis(pullRequest, files, fileAnalyses);

            return {
                pullRequest,
                fileAnalyses,
                summary,
                analysis,
            };
        } catch (error) {
            throw new Error(
                `Failed to review pull request: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    private shouldAnalyzeFile(file: PullRequestFile): boolean {
        // Skip binary files, images, and other non-code files
        const skipExtensions = [
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.pdf', '.doc', '.docx', '.zip', '.tar', '.gz',
            '.exe', '.dll', '.so', '.dylib',
            '.lock', '.log', '.min.js', '.min.css'
        ];

        const skipPatterns = [
            /^package-lock\.json$/,
            /^yarn\.lock$/,
            /^composer\.lock$/,
            /^Gemfile\.lock$/,
            /^Pipfile\.lock$/,
            /\.map$/,
            /node_modules\//,
            /vendor\//,
            /\.git\//,
            /dist\//,
            /build\//,
            /target\//,
            /out\//,
        ];

        const filename = file.filename.toLowerCase();

        // Check extensions
        if (skipExtensions.some(ext => filename.endsWith(ext))) {
            return false;
        }

        // Check patterns
        if (skipPatterns.some(pattern => pattern.test(file.filename))) {
            return false;
        }

        // Only analyze files with patches (actual code changes)
        return !!file.patch && file.status !== 'removed';
    }

    private async analyzeFile(
        file: PullRequestFile,
        options: {
            includeSecurity: boolean;
            includeBestPractices: boolean;
        }
    ): Promise<FileAnalysis> {
        if (!file.patch) {
            throw new Error(`No patch data available for file ${file.filename}`);
        }

        return await this.codeAnalyzer.analyzeDiff({
            diffContent: file.patch,
            filePath: file.filename,
            includeSecurity: options.includeSecurity,
        });
    }

    private filterIssuesBySeverity(issues: CodeIssue[], threshold: Severity): CodeIssue[] {
        const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];
        const thresholdIndex = severityOrder.indexOf(threshold);

        if (thresholdIndex === -1) {
            return issues;
        }

        return issues.filter(issue => {
            const issueIndex = severityOrder.indexOf(issue.severity);
            return issueIndex >= thresholdIndex;
        });
    }

    private generateSummary(fileAnalyses: FileAnalysis[]): PRReviewSummary {
        let totalIssues = 0;
        let criticalIssues = 0;
        let securityIssues = 0;
        let codeQualityIssues = 0;
        let bestPracticeIssues = 0;

        for (const analysis of fileAnalyses) {
            for (const issue of analysis.issues) {
                totalIssues++;

                if (issue.severity === 'critical') {
                    criticalIssues++;
                }

                switch (issue.type) {
                    case 'security':
                        securityIssues++;
                        break;
                    case 'quality':
                    case 'performance':
                    case 'bug':
                        codeQualityIssues++;
                        break;
                    case 'best-practice':
                        bestPracticeIssues++;
                        break;
                }
            }
        }

        const overallRisk = this.calculateOverallRisk(criticalIssues, securityIssues, totalIssues);
        const recommendation = this.generateRecommendation(overallRisk, criticalIssues, securityIssues);

        return {
            totalIssues,
            criticalIssues,
            securityIssues,
            codeQualityIssues,
            bestPracticeIssues,
            overallRisk,
            recommendation,
        };
    }

    private calculateOverallRisk(
        criticalIssues: number,
        securityIssues: number,
        totalIssues: number
    ): 'low' | 'medium' | 'high' | 'critical' {
        if (criticalIssues > 0) {
            return 'critical';
        }

        if (securityIssues > 2) {
            return 'high';
        }

        if (securityIssues > 0 || totalIssues > 10) {
            return 'medium';
        }

        return 'low';
    }

    private generateRecommendation(
        risk: 'low' | 'medium' | 'high' | 'critical',
        criticalIssues: number,
        securityIssues: number
    ): string {
        switch (risk) {
            case 'critical':
                return `🚨 Do not merge! This PR contains ${criticalIssues} critical issue(s) that must be addressed before merging.`;
            case 'high':
                return `⚠️ Review carefully! This PR contains ${securityIssues} security issue(s) that should be addressed.`;
            case 'medium':
                return `📋 Consider addressing the identified issues before merging to improve code quality.`;
            case 'low':
                return `✅ This PR looks good! Only minor issues were identified.`;
            default:
                return `✅ No significant issues found.`;
        }
    }

    private generateAnalysis(
        pullRequest: PullRequest,
        files: PullRequestFile[],
        fileAnalyses: FileAnalysis[]
    ) {
        const riskFactors: string[] = [];
        const recommendations: string[] = [];

        // Large PR analysis
        if (pullRequest.changed_files > 20) {
            riskFactors.push(`Large PR with ${pullRequest.changed_files} files changed`);
            recommendations.push('Consider breaking this PR into smaller, more focused changes');
        }

        if (pullRequest.additions + pullRequest.deletions > 1000) {
            riskFactors.push(`Large changeset with ${pullRequest.additions + pullRequest.deletions} lines modified`);
            recommendations.push('Large changesets are harder to review - consider smaller incremental changes');
        }

        // File type analysis
        const criticalFiles = files.filter(file =>
            this.isCriticalFile(file.filename)
        );

        if (criticalFiles.length > 0) {
            riskFactors.push(`Changes to critical files: ${criticalFiles.map(f => f.filename).join(', ')}`);
            recommendations.push('Extra attention needed for critical file changes');
        }

        // Security-sensitive files
        const securityFiles = files.filter(file =>
            this.isSecuritySensitiveFile(file.filename)
        );

        if (securityFiles.length > 0) {
            riskFactors.push(`Changes to security-sensitive files: ${securityFiles.map(f => f.filename).join(', ')}`);
            recommendations.push('Security review recommended for authentication/authorization changes');
        }

        // Test coverage analysis
        const testFiles = files.filter(file => this.isTestFile(file.filename));
        const codeFiles = files.filter(file =>
            !this.isTestFile(file.filename) &&
            this.shouldAnalyzeFile(file)
        );

        if (codeFiles.length > 0 && testFiles.length === 0) {
            riskFactors.push('No test files modified despite code changes');
            recommendations.push('Consider adding or updating tests for the modified code');
        }

        // Issue severity analysis
        const hasHighSeverityIssues = fileAnalyses.some(analysis =>
            analysis.issues.some(issue => ['high', 'critical'].includes(issue.severity))
        );

        if (hasHighSeverityIssues) {
            recommendations.push('Address high-severity issues before merging');
        }

        return {
            filesChanged: pullRequest.changed_files,
            linesAdded: pullRequest.additions,
            linesDeleted: pullRequest.deletions,
            riskFactors,
            recommendations,
        };
    }

    private isCriticalFile(filename: string): boolean {
        const criticalPatterns = [
            /package\.json$/,
            /requirements\.txt$/,
            /Gemfile$/,
            /composer\.json$/,
            /pom\.xml$/,
            /build\.gradle$/,
            /Dockerfile$/,
            /docker-compose\.ya?ml$/,
            /\.env$/,
            /config\//,
            /settings\//,
            /migrations?\//,
            /schema\//,
            /database\//,
        ];

        return criticalPatterns.some(pattern => pattern.test(filename));
    }

    private isSecuritySensitiveFile(filename: string): boolean {
        const securityPatterns = [
            /auth/i,
            /login/i,
            /password/i,
            /session/i,
            /jwt/i,
            /token/i,
            /security/i,
            /permission/i,
            /role/i,
            /access/i,
            /middleware/i,
            /guard/i,
            /policy/i,
        ];

        return securityPatterns.some(pattern => pattern.test(filename));
    }

    private isTestFile(filename: string): boolean {
        const testPatterns = [
            /\.test\./,
            /\.spec\./,
            /_test\./,
            /_spec\./,
            /test\//,
            /tests\//,
            /spec\//,
            /__tests__\//,
        ];

        return testPatterns.some(pattern => pattern.test(filename));
    }
} 
