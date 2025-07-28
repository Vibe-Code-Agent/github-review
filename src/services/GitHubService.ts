import { Octokit } from '@octokit/rest';

export interface PRQueryOptions {
    state?: 'open' | 'closed' | 'all';
    limit?: number;
    sort?: 'created' | 'updated' | 'popularity' | 'long-running';
}

export interface PullRequestFile {
    filename: string;
    status: string;
    additions: number;
    deletions: number;
    changes: number;
    patch: string | undefined;
    contents_url: string;
    raw_url: string;
}

export interface PullRequest {
    number: number;
    title: string;
    body: string | null;
    state: string;
    user: {
        login: string;
        avatar_url: string;
    };
    created_at: string;
    updated_at: string;
    merged_at: string | null;
    head: {
        sha: string;
        ref: string;
        repo: {
            name: string;
            full_name: string;
        };
    };
    base: {
        sha: string;
        ref: string;
        repo: {
            name: string;
            full_name: string;
        };
    };
    changed_files: number;
    additions: number;
    deletions: number;
    commits: number;
}

export class GitHubService {
    private octokit: Octokit;

    constructor() {
        const token = process.env.GITHUB_TOKEN;
        if (!token) {
            throw new Error('GITHUB_TOKEN environment variable is required');
        }

        this.octokit = new Octokit({
            auth: token,
        });
    }

    async getPullRequest(owner: string, repo: string, pullNumber: number): Promise<PullRequest> {
        try {
            const response = await this.octokit.rest.pulls.get({
                owner,
                repo,
                pull_number: pullNumber,
            });

            return this.transformPullRequest(response.data);
        } catch (error) {
            throw new Error(`Failed to fetch pull request: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async getPullRequestFiles(owner: string, repo: string, pullNumber: number): Promise<PullRequestFile[]> {
        try {
            const response = await this.octokit.rest.pulls.listFiles({
                owner,
                repo,
                pull_number: pullNumber,
                per_page: 100, // GitHub's maximum
            });

            return response.data.map(file => ({
                filename: file.filename,
                status: file.status,
                additions: file.additions,
                deletions: file.deletions,
                changes: file.changes,
                patch: file.patch,
                contents_url: file.contents_url,
                raw_url: file.raw_url,
            }));
        } catch (error) {
            throw new Error(`Failed to fetch pull request files: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async getRepositoryPRs(owner: string, repo: string, options: PRQueryOptions = {}): Promise<PullRequest[]> {
        try {
            const {
                state = 'open',
                limit = 10,
                sort = 'created',
            } = options;

            const response = await this.octokit.rest.pulls.list({
                owner,
                repo,
                state,
                sort,
                direction: 'desc',
                per_page: Math.min(limit, 100),
            });

            return response.data.map(pr => this.transformPullRequest(pr));
        } catch (error) {
            throw new Error(`Failed to fetch repository PRs: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async getFileContent(owner: string, repo: string, path: string, ref: string | undefined = undefined): Promise<string> {
        try {
            const response = await this.octokit.rest.repos.getContent({
                owner,
                repo,
                path,
                ...(ref && { ref }),
            });

            if (Array.isArray(response.data) || response.data.type !== 'file') {
                throw new Error(`Path ${path} is not a file`);
            }

            if (response.data.encoding === 'base64') {
                return Buffer.from(response.data.content, 'base64').toString('utf-8');
            }

            return response.data.content;
        } catch (error) {
            throw new Error(`Failed to fetch file content: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async getPullRequestDiff(owner: string, repo: string, pullNumber: number): Promise<string> {
        try {
            const response = await this.octokit.rest.pulls.get({
                owner,
                repo,
                pull_number: pullNumber,
                mediaType: {
                    format: 'diff',
                },
            });

            return response.data as unknown as string;
        } catch (error) {
            throw new Error(`Failed to fetch pull request diff: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async getCommitsInPR(owner: string, repo: string, pullNumber: number) {
        try {
            const response = await this.octokit.rest.pulls.listCommits({
                owner,
                repo,
                pull_number: pullNumber,
            });

            return response.data.map(commit => ({
                sha: commit.sha,
                message: commit.commit.message,
                author: commit.commit.author,
                url: commit.html_url,
                stats: commit.stats,
            }));
        } catch (error) {
            throw new Error(`Failed to fetch commits: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async createPullRequestComment(owner: string, repo: string, pullNumber: number, body: string): Promise<void> {
        try {
            await this.octokit.rest.issues.createComment({
                owner,
                repo,
                issue_number: pullNumber,
                body,
            });
        } catch (error) {
            throw new Error(`Failed to create pull request comment: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async createPullRequestReviewComment(
        owner: string, 
        repo: string, 
        pullNumber: number, 
        body: string,
        path: string,
        line: number,
        side: 'LEFT' | 'RIGHT' = 'RIGHT'
    ): Promise<void> {
        try {
            const pr = await this.octokit.rest.pulls.get({
                owner,
                repo,
                pull_number: pullNumber,
            });

            await this.octokit.rest.pulls.createReviewComment({
                owner,
                repo,
                pull_number: pullNumber,
                body,
                commit_id: pr.data.head.sha,
                path,
                line,
                side,
            });
        } catch (error) {
            throw new Error(`Failed to create pull request review comment: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    private transformPullRequest(data: any): PullRequest {
        return {
            number: data.number,
            title: data.title,
            body: data.body,
            state: data.state,
            user: {
                login: data.user.login,
                avatar_url: data.user.avatar_url,
            },
            created_at: data.created_at,
            updated_at: data.updated_at,
            merged_at: data.merged_at,
            head: {
                sha: data.head.sha,
                ref: data.head.ref,
                repo: {
                    name: data.head.repo.name,
                    full_name: data.head.repo.full_name,
                },
            },
            base: {
                sha: data.base.sha,
                ref: data.base.ref,
                repo: {
                    name: data.base.repo.name,
                    full_name: data.base.repo.full_name,
                },
            },
            changed_files: data.changed_files,
            additions: data.additions,
            deletions: data.deletions,
            commits: data.commits,
        };
    }
} 
