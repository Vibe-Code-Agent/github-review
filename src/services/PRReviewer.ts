import { GitHubService, PullRequest, PullRequestFile } from './GitHubService.js';
import { CodeAnalyzer, FileAnalysis, Severity, CodeIssue, IssueType } from './CodeAnalyzer.js';

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

export interface FixRecommendation {
    issueId: string;
    issueTitle: string;
    severity: Severity;
    suggestedFix: string;
    priority: 'immediate' | 'high' | 'medium' | 'low';
    estimatedEffort: 'trivial' | 'minor' | 'moderate' | 'major';
    references?: string[];
    filePath: string;
    line?: number;
    side?: 'LEFT' | 'RIGHT';
}

export interface PRReview {
    pullRequest: PullRequest;
    fileAnalyses: FileAnalysis[];
    summary: PRReviewSummary;
    fixRecommendations: FixRecommendation[];
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
            const fixRecommendations = this.generateFixRecommendations(fileAnalyses);

            return {
                pullRequest,
                fileAnalyses,
                summary,
                fixRecommendations,
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
                return `🚨 Do not merge! This PR contains ${criticalIssues} critical issue(s) that must be addressed before merging. Review the fix recommendations section for detailed guidance.`;
            case 'high':
                return `⚠️ Review carefully! This PR contains ${securityIssues} security issue(s) that should be addressed. Check the fix recommendations for immediate actions.`;
            case 'medium':
                return `📋 Consider addressing the identified issues before merging to improve code quality. See fix recommendations for prioritized solutions.`;
            case 'low':
                return `✅ This PR looks good! Only minor issues were identified. Fix recommendations are available for optional improvements.`;
            default:
                return `✅ No significant issues found.`;
        }
    }

    private generateFixRecommendations(fileAnalyses: FileAnalysis[]): FixRecommendation[] {
        const recommendations: FixRecommendation[] = [];
        let issueCounter = 1;

        for (const analysis of fileAnalyses) {
            for (const issue of analysis.issues) {
                const recommendation = this.createFixRecommendation(
                    issue,
                    analysis.fileName,
                    issueCounter++
                );
                recommendations.push(recommendation);
            }
        }

        // Sort by priority (immediate first) and then by severity
        return recommendations.sort((a, b) => {
            const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3 };
            const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            
            if (a.priority !== b.priority) {
                return priorityOrder[a.priority] - priorityOrder[b.priority];
            }
            return severityOrder[a.severity] - severityOrder[b.severity];
        });
    }

    private createFixRecommendation(
        issue: CodeIssue,
        fileName: string,
        issueId: number
    ): FixRecommendation {
        const priority = this.determinePriority(issue.severity, issue.type);
        const estimatedEffort = this.estimateEffort(issue.type, issue.severity);
        const suggestedFix = this.generateSuggestedFix(issue, fileName);
        const references = this.getReferences(issue.type, issue.rule);

        const fixRecommendation: FixRecommendation = {
            issueId: `${fileName}-${issueId}`,
            issueTitle: issue.title,
            severity: issue.severity,
            suggestedFix,
            priority,
            estimatedEffort,
            references,
            filePath: fileName,
        };

        if (issue.line !== undefined) {
            fixRecommendation.line = issue.line;
            fixRecommendation.side = 'RIGHT';
        }

        return fixRecommendation;
    }

    private determinePriority(
        severity: Severity,
        type: IssueType
    ): 'immediate' | 'high' | 'medium' | 'low' {
        if (severity === 'critical') {
            return 'immediate';
        }
        
        if (severity === 'high' && (type === 'security' || type === 'bug')) {
            return 'immediate';
        }
        
        if (severity === 'high' || (severity === 'medium' && type === 'security')) {
            return 'high';
        }
        
        if (severity === 'medium') {
            return 'medium';
        }
        
        return 'low';
    }

    private estimateEffort(type: IssueType, severity: Severity): 'trivial' | 'minor' | 'moderate' | 'major' {
        if (severity === 'critical') {
            return type === 'security' ? 'major' : 'moderate';
        }
        
        switch (type) {
            case 'security':
                return severity === 'high' ? 'moderate' : 'minor';
            case 'bug':
                return severity === 'high' ? 'moderate' : 'minor';
            case 'performance':
                return severity === 'high' ? 'moderate' : 'minor';
            case 'quality':
                return 'minor';
            case 'best-practice':
                return 'trivial';
            default:
                return 'minor';
        }
    }

    private generateSuggestedFix(issue: CodeIssue, fileName: string): string {
        if (issue.recommendation) {
            return issue.recommendation;
        }

        const baseMessage = `In ${fileName}${issue.line ? ` at line ${issue.line}` : ''}:\n\n`;
        
        switch (issue.type) {
            case 'security':
                return baseMessage + this.getSecurityFix(issue);
            case 'bug':
                return baseMessage + this.getBugFix(issue);
            case 'performance':
                return baseMessage + this.getPerformanceFix(issue);
            case 'quality':
                return baseMessage + this.getQualityFix(issue);
            case 'best-practice':
                return baseMessage + this.getBestPracticeFix(issue);
            default:
                return baseMessage + `Address the ${issue.severity} issue: ${issue.description}`;
        }
    }

    private getSecurityFix(issue: CodeIssue): string {
        const title = issue.title.toLowerCase();
        
        if (title.includes('sql injection')) {
            return '• Use parameterized queries or prepared statements\n• Validate and sanitize all user inputs\n• Consider using an ORM with built-in protection';
        }
        
        if (title.includes('xss') || title.includes('cross-site scripting')) {
            return '• Escape user input before rendering\n• Use Content Security Policy (CSP)\n• Validate input on both client and server side';
        }
        
        if (title.includes('hardcoded') || title.includes('credential')) {
            return '• Move sensitive values to environment variables\n• Use a secure configuration management system\n• Never commit secrets to version control';
        }
        
        if (title.includes('weak') && title.includes('hash')) {
            return '• Use strong hashing algorithms (bcrypt, scrypt, or Argon2)\n• Implement proper salt generation\n• Consider using a security library';
        }
        
        return '• Review security best practices for this type of vulnerability\n• Consider implementing additional security controls\n• Test the fix thoroughly';
    }

    private getBugFix(issue: CodeIssue): string {
        const title = issue.title.toLowerCase();
        
        if (title.includes('null') || title.includes('undefined')) {
            return '• Add null/undefined checks before accessing properties\n• Use optional chaining (?.)\n• Provide default values where appropriate';
        }
        
        if (title.includes('race condition')) {
            return '• Implement proper synchronization mechanisms\n• Use atomic operations where possible\n• Review concurrent access patterns';
        }
        
        if (title.includes('memory leak')) {
            return '• Ensure proper cleanup of event listeners\n• Clear intervals and timeouts\n• Remove references to prevent garbage collection issues';
        }
        
        return '• Analyze the root cause of the issue\n• Implement appropriate error handling\n• Add unit tests to prevent regression';
    }

    private getPerformanceFix(issue: CodeIssue): string {
        const title = issue.title.toLowerCase();
        
        if (title.includes('loop') || title.includes('iteration')) {
            return '• Optimize loop conditions and iterations\n• Consider using more efficient algorithms\n• Cache frequently accessed values';
        }
        
        if (title.includes('query') || title.includes('database')) {
            return '• Add appropriate database indexes\n• Optimize query structure\n• Consider pagination for large datasets';
        }
        
        if (title.includes('memory') || title.includes('allocation')) {
            return '• Reduce object allocations in hot paths\n• Reuse objects where possible\n• Consider memory pooling techniques';
        }
        
        return '• Profile the code to identify bottlenecks\n• Implement caching where appropriate\n• Consider algorithmic optimizations';
    }

    private getQualityFix(issue: CodeIssue): string {
        const title = issue.title.toLowerCase();
        
        if (title.includes('complexity')) {
            return '• Break down complex functions into smaller ones\n• Extract common logic into utilities\n• Simplify conditional statements';
        }
        
        if (title.includes('duplicate')) {
            return '• Extract duplicated code into reusable functions\n• Create shared utilities or constants\n• Follow DRY (Don\'t Repeat Yourself) principle';
        }
        
        if (title.includes('magic number')) {
            return '• Replace magic numbers with named constants\n• Add descriptive comments explaining the values\n• Consider using configuration files for adjustable values';
        }
        
        return '• Improve code readability and structure\n• Add appropriate comments and documentation\n• Follow established coding standards';
    }

    private getBestPracticeFix(issue: CodeIssue): string {
        const title = issue.title.toLowerCase();
        
        if (title.includes('naming')) {
            return '• Use descriptive and meaningful names\n• Follow language-specific naming conventions\n• Avoid abbreviations and unclear terms';
        }
        
        if (title.includes('comment') || title.includes('documentation')) {
            return '• Add clear and concise comments\n• Document complex logic and business rules\n• Keep documentation up to date with code changes';
        }
        
        if (title.includes('error handling')) {
            return '• Implement proper try-catch blocks\n• Provide meaningful error messages\n• Log errors appropriately for debugging';
        }
        
        return '• Follow established coding standards\n• Improve code organization and structure\n• Consider team conventions and guidelines';
    }

    private getReferences(type: IssueType, rule?: string): string[] {
        const references: string[] = [];
        
        switch (type) {
            case 'security':
                references.push(
                    'OWASP Top 10: https://owasp.org/www-project-top-ten/',
                    'Security Best Practices Guide'
                );
                break;
            case 'performance':
                references.push(
                    'Performance Optimization Guide',
                    'Web Vitals: https://web.dev/vitals/'
                );
                break;
            case 'quality':
                references.push(
                    'Clean Code Principles',
                    'Code Quality Standards'
                );
                break;
            case 'best-practice':
                references.push(
                    'Coding Standards Documentation',
                    'Team Guidelines'
                );
                break;
        }
        
        if (rule) {
            references.push(`Rule: ${rule}`);
        }
        
        return references;
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

    async applyRecommendedFix(
        owner: string,
        repo: string,
        pullNumber: number,
        fixRecommendation: FixRecommendation
    ): Promise<void> {
        try {
            const commentBody = this.formatFixComment(fixRecommendation);
            
            if (fixRecommendation.line && fixRecommendation.filePath) {
                await this.githubService.createPullRequestReviewComment(
                    owner,
                    repo,
                    pullNumber,
                    commentBody,
                    fixRecommendation.filePath,
                    fixRecommendation.line,
                    fixRecommendation.side || 'RIGHT'
                );
            } else {
                await this.githubService.createPullRequestComment(owner, repo, pullNumber, commentBody);
            }
        } catch (error) {
            throw new Error(
                `Failed to apply recommended fix: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    private formatFixComment(fix: FixRecommendation): string {
        const priorityEmoji = {
            immediate: '🚨',
            high: '⚠️',
            medium: '📋',
            low: '💡'
        };

        const severityEmoji = {
            critical: '🔴',
            high: '🟠',
            medium: '🟡',
            low: '🟢'
        };

        const effortEmoji = {
            trivial: '⚡',
            minor: '🔧',
            moderate: '⚙️',
            major: '🛠️'
        };

        if (fix.line && fix.filePath) {
            let comment = `${priorityEmoji[fix.priority]} **${fix.issueTitle}** ${severityEmoji[fix.severity]}\n\n`;
            comment += `**Priority:** ${fix.priority} | **Severity:** ${fix.severity} | **Effort:** ${effortEmoji[fix.estimatedEffort]} ${fix.estimatedEffort}\n\n`;
            comment += `${fix.suggestedFix}\n\n`;
            
            if (fix.references && fix.references.length > 0) {
                comment += `**References:** ${fix.references.join(' • ')}\n\n`;
            }
            
            comment += `*Issue ID: \`${fix.issueId}\`*`;
            return comment;
        } else {
            let comment = `## ${priorityEmoji[fix.priority]} Approved Fix Recommendation\n\n`;
            comment += `**Issue:** ${fix.issueTitle}\n`;
            comment += `**Severity:** ${severityEmoji[fix.severity]} ${fix.severity.toUpperCase()}\n`;
            comment += `**Priority:** ${fix.priority.toUpperCase()}\n`;
            comment += `**Estimated Effort:** ${effortEmoji[fix.estimatedEffort]} ${fix.estimatedEffort}\n\n`;
            
            comment += `### 📝 Recommended Fix\n\n`;
            comment += `${fix.suggestedFix}\n\n`;

            if (fix.references && fix.references.length > 0) {
                comment += `### 📚 References\n\n`;
                fix.references.forEach(ref => {
                    comment += `- ${ref}\n`;
                });
                comment += '\n';
            }

            comment += `---\n`;
            comment += `*This fix recommendation has been approved and applied. Issue ID: \`${fix.issueId}\`*`;
            return comment;
        }
    }
} 
