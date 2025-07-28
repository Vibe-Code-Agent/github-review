#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
    CallToolRequestSchema,
    ErrorCode,
    ListToolsRequestSchema,
    McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { GitHubService } from './services/GitHubService';
import { PRReviewer } from './services/PRReviewer';
import { CodeAnalyzer } from './services/CodeAnalyzer';

class GitHubPRReviewServer {
    private server: Server;
    private githubService: GitHubService;
    private prReviewer: PRReviewer;
    private codeAnalyzer: CodeAnalyzer;

    constructor() {
        this.server = new Server(
            {
                name: 'github-pr-review-mcp',
                version: '1.0.0',
            },
            {
                capabilities: {
                    tools: {},
                },
            }
        );

        this.githubService = new GitHubService();
        this.codeAnalyzer = new CodeAnalyzer();
        this.prReviewer = new PRReviewer(this.githubService, this.codeAnalyzer);

        this.setupToolHandlers();
    }

    private setupToolHandlers() {
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            return {
                tools: [
                    {
                        name: 'get_pull_request',
                        description: 'Fetch pull request details including metadata and file changes',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                owner: {
                                    type: 'string',
                                    description: 'Repository owner (username or organization)',
                                },
                                repo: {
                                    type: 'string',
                                    description: 'Repository name',
                                },
                                pull_number: {
                                    type: 'number',
                                    description: 'Pull request number',
                                },
                            },
                            required: ['owner', 'repo', 'pull_number'],
                        },
                    },
                    {
                        name: 'review_pull_request',
                        description: 'Comprehensive review of a pull request including code analysis, issue detection, and security checks',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                owner: {
                                    type: 'string',
                                    description: 'Repository owner (username or organization)',
                                },
                                repo: {
                                    type: 'string',
                                    description: 'Repository name',
                                },
                                pull_number: {
                                    type: 'number',
                                    description: 'Pull request number',
                                },
                                include_security: {
                                    type: 'boolean',
                                    description: 'Include security vulnerability analysis (default: true)',
                                    default: true,
                                },
                                include_best_practices: {
                                    type: 'boolean',
                                    description: 'Include best practices recommendations (default: true)',
                                    default: true,
                                },
                                severity_threshold: {
                                    type: 'string',
                                    enum: ['low', 'medium', 'high', 'critical'],
                                    description: 'Minimum severity level to report (default: medium)',
                                    default: 'medium',
                                },
                            },
                            required: ['owner', 'repo', 'pull_number'],
                        },
                    },
                    {
                        name: 'analyze_code_diff',
                        description: 'Analyze specific code changes for issues and security vulnerabilities',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                diff_content: {
                                    type: 'string',
                                    description: 'Git diff content to analyze',
                                },
                                file_path: {
                                    type: 'string',
                                    description: 'Path of the file being analyzed',
                                },
                                language: {
                                    type: 'string',
                                    description: 'Programming language (auto-detected if not provided)',
                                },
                                include_security: {
                                    type: 'boolean',
                                    description: 'Include security analysis (default: true)',
                                    default: true,
                                },
                            },
                            required: ['diff_content', 'file_path'],
                        },
                    },
                    {
                        name: 'get_repository_prs',
                        description: 'List pull requests for a repository with filtering options',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                owner: {
                                    type: 'string',
                                    description: 'Repository owner (username or organization)',
                                },
                                repo: {
                                    type: 'string',
                                    description: 'Repository name',
                                },
                                state: {
                                    type: 'string',
                                    enum: ['open', 'closed', 'all'],
                                    description: 'PR state filter (default: open)',
                                    default: 'open',
                                },
                                limit: {
                                    type: 'number',
                                    description: 'Maximum number of PRs to return (default: 10, max: 100)',
                                    default: 10,
                                    maximum: 100,
                                },
                                sort: {
                                    type: 'string',
                                    enum: ['created', 'updated', 'popularity', 'long-running'],
                                    description: 'Sort criteria (default: created)',
                                    default: 'created',
                                },
                            },
                            required: ['owner', 'repo'],
                        },
                    },
                ],
            };
        });

        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            try {
                const { name, arguments: args } = request.params;

                switch (name) {
                    case 'get_pull_request':
                        return await this.handleGetPullRequest(args);
                    case 'review_pull_request':
                        return await this.handleReviewPullRequest(args);
                    case 'analyze_code_diff':
                        return await this.handleAnalyzeCodeDiff(args);
                    case 'get_repository_prs':
                        return await this.handleGetRepositoryPRs(args);
                    default:
                        throw new McpError(
                            ErrorCode.MethodNotFound,
                            `Unknown tool: ${name}`
                        );
                }
            } catch (error) {
                if (error instanceof McpError) {
                    throw error;
                }
                throw new McpError(
                    ErrorCode.InternalError,
                    `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`
                );
            }
        });
    }

    private async handleGetPullRequest(args: any) {
        const { owner, repo, pull_number } = args;
        const pr = await this.githubService.getPullRequest(owner, repo, pull_number);
        const files = await this.githubService.getPullRequestFiles(owner, repo, pull_number);

        return {
            content: [
                {
                    type: 'text',
                    text: JSON.stringify({ pr, files }, null, 2),
                },
            ],
        };
    }

    private async handleReviewPullRequest(args: any) {
        const {
            owner,
            repo,
            pull_number,
            include_security = true,
            include_best_practices = true,
            severity_threshold = 'medium',
        } = args;

        const review = await this.prReviewer.reviewPullRequest({
            owner,
            repo,
            pullNumber: pull_number,
            includeSecurity: include_security,
            includeBestPractices: include_best_practices,
            severityThreshold: severity_threshold,
        });

        return {
            content: [
                {
                    type: 'text',
                    text: this.formatReviewReport(review),
                },
            ],
        };
    }

    private async handleAnalyzeCodeDiff(args: any) {
        const { diff_content, file_path, language, include_security = true } = args;

        const analysis = await this.codeAnalyzer.analyzeDiff({
            diffContent: diff_content,
            filePath: file_path,
            language,
            includeSecurity: include_security,
        });

        return {
            content: [
                {
                    type: 'text',
                    text: this.formatCodeAnalysis(analysis),
                },
            ],
        };
    }

    private async handleGetRepositoryPRs(args: any) {
        const { owner, repo, state = 'open', limit = 10, sort = 'created' } = args;

        const prs = await this.githubService.getRepositoryPRs(owner, repo, {
            state,
            limit,
            sort,
        });

        return {
            content: [
                {
                    type: 'text',
                    text: this.formatPRList(prs),
                },
            ],
        };
    }

    private formatReviewReport(review: any): string {
        const { pullRequest, analysis, summary } = review;

        let report = `# 🔍 Pull Request Review Report\n\n`;
        report += `**PR:** ${pullRequest.title}\n`;
        report += `**Number:** #${pullRequest.number}\n`;
        report += `**Author:** ${pullRequest.user.login}\n`;
        report += `**Status:** ${pullRequest.state}\n`;
        report += `**Files Changed:** ${pullRequest.changed_files}\n`;
        report += `**Additions:** +${pullRequest.additions} | **Deletions:** -${pullRequest.deletions}\n\n`;

        if (summary.criticalIssues > 0) {
            report += `## 🚨 Critical Issues Found: ${summary.criticalIssues}\n\n`;
        }

        if (summary.securityIssues > 0) {
            report += `## 🔒 Security Issues Found: ${summary.securityIssues}\n\n`;
        }

        report += `## 📊 Summary\n`;
        report += `- **Total Issues:** ${summary.totalIssues}\n`;
        report += `- **Security Issues:** ${summary.securityIssues}\n`;
        report += `- **Code Quality Issues:** ${summary.codeQualityIssues}\n`;
        report += `- **Best Practice Violations:** ${summary.bestPracticeIssues}\n`;
        report += `- **Overall Risk:** ${summary.overallRisk}\n\n`;

        if (analysis.fileAnalyses && analysis.fileAnalyses.length > 0) {
            report += `## 📁 File Analysis\n\n`;
            for (const fileAnalysis of analysis.fileAnalyses) {
                if (fileAnalysis.issues.length > 0) {
                    report += `### 📄 ${fileAnalysis.fileName}\n\n`;
                    for (const issue of fileAnalysis.issues) {
                        report += `**${issue.severity.toUpperCase()}:** ${issue.title}\n`;
                        report += `- **Line:** ${issue.line || 'N/A'}\n`;
                        report += `- **Description:** ${issue.description}\n`;
                        if (issue.recommendation) {
                            report += `- **Recommendation:** ${issue.recommendation}\n`;
                        }
                        report += `\n`;
                    }
                }
            }
        }

        return report;
    }

    private formatCodeAnalysis(analysis: any): string {
        let result = `# 🔍 Code Diff Analysis\n\n`;
        result += `**File:** ${analysis.filePath}\n`;
        result += `**Language:** ${analysis.language || 'Unknown'}\n`;
        result += `**Issues Found:** ${analysis.issues.length}\n\n`;

        if (analysis.issues.length > 0) {
            result += `## 🐛 Issues Detected\n\n`;
            for (const issue of analysis.issues) {
                result += `### ${issue.severity.toUpperCase()}: ${issue.title}\n`;
                result += `**Line:** ${issue.line || 'N/A'}\n`;
                result += `**Description:** ${issue.description}\n`;
                if (issue.recommendation) {
                    result += `**Recommendation:** ${issue.recommendation}\n`;
                }
                result += `\n`;
            }
        } else {
            result += `✅ No issues detected in this code diff.\n`;
        }

        return result;
    }

    private formatPRList(prs: any[]): string {
        let result = `# 📋 Pull Requests\n\n`;
        result += `Found ${prs.length} pull request(s):\n\n`;

        for (const pr of prs) {
            result += `## #${pr.number} - ${pr.title}\n`;
            result += `**Author:** ${pr.user.login}\n`;
            result += `**State:** ${pr.state}\n`;
            result += `**Created:** ${new Date(pr.created_at).toLocaleDateString()}\n`;
            result += `**Updated:** ${new Date(pr.updated_at).toLocaleDateString()}\n`;
            if (pr.body) {
                result += `**Description:** ${pr.body.substring(0, 200)}${pr.body.length > 200 ? '...' : ''}\n`;
            }
            result += `\n`;
        }

        return result;
    }

    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error('GitHub PR Review MCP server running on stdio');
    }
}

const server = new GitHubPRReviewServer();
server.run().catch(console.error); 
