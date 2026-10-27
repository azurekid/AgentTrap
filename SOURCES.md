# Online resources used: AGENTS.md threat analysis

Compiled 2026-10-27. Sources 1–3 came from the original task; 4–59 were fetched by the research agent.
URLs and dates are as reported by the research agent and were not individually re-checked.

## Original task

| # | Title | Publisher/Author | Date | URL | Type |
|---|---|---|---|---|---|
| 1 | AI coding agents hijacked using AGENTS.md file in Downloads folder | BleepingComputer | Oct 2026 | https://www.bleepingcomputer.com/news/security/ai-coding-agents-hijacked-using-agentsmd-file-in-downloads-folder/ | news |
| 2 | Hijacking AI agents via Downloads folder | Forever Security | Oct 2026 | https://forever.security/blog/hijacking-ai-agents-via-downloads-folder | blog (primary source) |
| 3 | Drive-by download PoC page (not visited, it drops a file) | Gal Weizman | Oct 2026 | https://weizmangal.com/public/download-test.html | PoC |

## Deep research

| # | Title | Publisher/Author | Date | URL | Type |
|---|---|---|---|---|---|
| 4 | New Vulnerability in GitHub Copilot and Cursor: "Rules File Backdoor" | Pillar Security | ~Mar 2025 (disclosed Feb 26–May 1, 2025) | https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents | blog |
| 5 | GitHub changelog: warning for hidden Unicode text | GitHub | May 1, 2025 | https://github.blog/changelog/2025-05-01-github-now-provides-a-warning-about-hidden-unicode-text/ | docs/news |
| 6 | Hiding and Finding Text with Unicode Tags | Johann Rehberger (Embrace The Red) | Jan 2024 | https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/ | blog |
| 7 | ASCII Smuggling and Hidden Prompt Instructions | Johann Rehberger | Feb 12, 2024 | https://embracethered.com/blog/posts/2024/ascii-smuggling-and-hidden-prompt-instructions/ | blog |
| 8 | ASCII Smuggler Tool | Johann Rehberger | — | https://embracethered.com/blog/ascii-smuggler.html | tool/docs |
| 9 | Reverse CAPTCHA: Evaluating LLM Susceptibility to Invisible Unicode Instruction Injection | Marcus Graves | Feb 26, 2026 | https://arxiv.org/abs/2603.00164 | paper |
| 10 | Package Hallucination Attacks on Coding Agents through Prompt Injection in Rule Files | Wang, Jiang, Wang, Gong | Oct 7, 2026 | https://arxiv.org/abs/2610.09264 | paper |
| 11 | Aletheia: Permission-Minimality Testing for Coding-Agent Rules | Jieke Shi et al. | Sep 30 2026 (v2 Oct 5 2026) | https://arxiv.org/abs/2609.39678 | paper |
| 12 | CamoLeak: Critical GitHub Copilot Vulnerability | Omer Mayraz, Legit Security | Sep 30, 2025 | https://legitsecurity.com/blog/camoleak-critical-github-copilot-vulnerability-leaks-private-source-code | blog/CVE-2025-59145 |
| 13 | Lies-in-the-Loop: Bypassing AI Agent Defenses | Checkmarx Zero | Sep 15, 2025 | https://checkmarx.com/zero-post/bypassing-ai-agent-defenses-with-lies-in-the-loop/ | blog |
| 14 | Bypassing Claude Code: How Easy Is It To Trick an AI Security Reviewer | Checkmarx Zero | — | https://checkmarx.com/zero-post/bypassing-claude-code-how-easy-is-it-to-trick-an-ai-security-reviewer/ | blog |
| 15 | CVE-2025-54136 (Cursor "MCPoison") | MITRE / Cursor GHSA | reserved Jul 16, pub. Aug 1, 2025 | https://cveawg.mitre.org/api/cve/CVE-2025-54136 ; https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395 | CVE/advisory |
| 16 | Cursor Vulnerability "MCPoison" | Check Point Research | Aug 2025 | https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/ | blog |
| 17 | Cursor AI Code Editor Vulnerability (MCPoison coverage) | The Hacker News | Aug 2025 | https://thehackernews.com/2025/08/cursor-ai-code-editor-vulnerability.html | news |
| 18 | New MCPoison Attack Exploits Cursor IDE | Cyberpress | Aug 2025 | https://cyberpress.org/new-mcpoison-attack-exploits-cursor-ide/ | news |
| 19 | CVE-2025-54135 ("CurXecute") | MITRE / Cursor GHSA | pub. Aug 5, 2025 | https://cveawg.mitre.org/api/cve/CVE-2025-54135 ; https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm | CVE/advisory |
| 20 | FAQ: CVE-2025-54135 & CVE-2025-54136 | Tenable | Aug 2025 | https://tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison | blog |
| 21 | CurXecute: Prompt Injection Flaw in Cursor IDE Enables RCE | Daily Security Review | Aug 2025 | https://dailysecurityreview.com/security-spotlight/curxecute-prompt-injection-flaw-in-cursor-ide-enables-remote-code-execution/ | news |
| 22 | Claude Code Docs: Hooks | Anthropic | — | https://code.claude.com/docs/en/hooks | docs |
| 23 | Claude Code Docs: Settings Reference | Anthropic | — | https://code.claude.com/docs/en/settings-reference | docs |
| 24 | Claude Code Docs: Permissions | Anthropic | — | https://code.claude.com/docs/en/permissions | docs |
| 25 | Claude Code Docs: CLI Reference | Anthropic | — | https://code.claude.com/docs/en/cli-reference | docs |
| 26 | GHSA-ff64-7w26-62rf (Claude Code sandbox/hooks CVE-2026-25725) | Anthropic | fixed v2.1.2+ | https://github.com/anthropics/claude-code/security/advisories/GHSA-ff64-7w26-62rf | advisory/CVE |
| 27 | Codex CLI Config Reference | OpenAI | — | https://learn.chatgpt.com/docs/config-file/config-reference ; https://github.com/openai/codex/blob/main/docs/config.md | docs |
| 28 | Code Exec via Deception: Gemini AI CLI Hijack | Sam Cox, Tracebit | Jul 28, 2025 | https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack | blog |
| 29 | Gemini CLI Configuration Reference | Google | — | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md | docs |
| 30 | Cline Rules Docs | Cline | — | https://docs.cline.bot/customization/cline-rules.md | docs |
| 31 | New Rules File Backdoor Attack (secondary coverage) | The Hacker News | Mar 2025 | https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html | news |
| 32 | AWS Security Bulletin AWS-2025-015 (Amazon Q incident) | AWS | Jul 2025 | https://aws.amazon.com/security/security-bulletins/AWS-2025-015/ | advisory/CVE-2025-8217 |
| 33 | Hacker Plants Computer-Wiping Commands in Amazon's AI Coding Agent | 404 Media | Jul 2025 | https://404media.co/hacker-plants-computer-wiping-commands-in-amazons-ai-coding-agent/ | news |
| 34 | Constructing a Timeline for Amazon Q Prompt Infection | mbgsec.com | Jul 24, 2025 | https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/ | blog |
| 35 | VS Code Release Notes v1.99 | Microsoft | Mar 2025 | https://code.visualstudio.com/updates/v1_99 | docs |
| 36 | VS Code Docs: Tasks (tasks.json) | Microsoft | — | https://code.visualstudio.com/docs/debugtest/tasks | docs |
| 37 | GitHub Copilot Remote Code Execution via Prompt Injection | Johann Rehberger | 2025 | https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/ | blog/CVE-2025-53773 |
| 38 | IDEsaster | Ari "MaccariTA" Marzouk | — | https://maccarita.com/posts/idesaster/ | blog |
| 39 | AWS Security Bulletin AWS-2025-019 | AWS | Oct 7, 2025 | https://aws.amazon.com/security/security-bulletins/AWS-2025-019/ | advisory |
| 40 | s1ngularity Supply Chain Attack | Wiz Threat Research | Aug 29, 2025 | https://wiz.io/blog/s1ngularity-supply-chain-attack | blog |
| 41 | GHSA-cxm3-wv7p-598c (Nx) | Nx/nrwl | Aug 2025 | https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c | advisory |
| 42 | Supply Chain Security Alert: Nx Build System Compromised | StepSecurity | Aug 2025 | https://stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware | blog |
| 43 | Popular Tinycolor npm Package Compromised (Shai-Hulud) | Socket.dev | Sep 15, 2025 | https://socket.dev/blog/tinycolor-supply-chain-attack-affects-40-packages | blog |
| 44 | Updated/Ongoing Supply Chain Attack Targets CrowdStrike npm Packages | Socket.dev | Sep 16, 2025 | https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages | blog |
| 45 | The Rise of Slopsquatting | Sarah Gooding, Socket.dev | Apr 8, 2025 | https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks | blog |
| 46 | We Have a Package for You! Package Hallucinations by Code Generating LLMs | Spracklen et al. | Jun 12, 2024 (v3 Mar 2, 2025) | https://arxiv.org/abs/2406.10279 | paper (USENIX Sec 2025) |
| 47 | MCP Security Notification: Tool Poisoning Attacks | Invariant Labs | ~early Apr 2025 | https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks | blog |
| 48 | AgentCorruption: How A Single Prompt Collapsed The Entire Cloud Security Model | Zenity Labs | Oct 8, 2026 | https://labs.zenity.io/post/agentcorruption-how-a-single-prompt-collapsed-the-entire-cloud-security-model | blog |
| 49 | AWS Bedrock AgentCore Flaw (secondary coverage of #45) | Cyberpress | Oct 2026 | https://cyberpress.org/aws-bedrock-agentcore-flaw-2/ | news |
| 50 | Poisoning Claude Code: One GitHub Issue to Break the Supply Chain | RyotaK, Flatt Security | Jun 1, 2026 | https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/ | blog |
| 51 | Pwning Claude Code in 8 Different Ways | Flatt Security | Jan 12, 2026 | flatt.tech (cited via research pass) | blog |
| 52 | Comment and Control: Prompt Injection Credential Theft (Claude Code/Gemini CLI/Copilot) | Aonan Guan et al. | reported Oct 17, 2025; ACM CCS 2026 | https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/ ; https://arxiv.org/abs/2605.11229 | blog/paper |
| 53 | AI Agent Prompt Injection: The New CI/CD Supply Chain Threat | Cloud Security Alliance | Jun 5, 2026 | https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-github-action-prompt-injection/ | blog |
| 54 | PromptPwnd: GitHub Actions AI Agents | Aikido Security | Dec 4, 2025 (upd. Mar 17, 2026) | https://aikido.dev/blog/promptpwnd-github-actions-ai-agents | blog |
| 55 | Claude Code Exfiltration via DNS Requests | Johann Rehberger | Jun 2025 | https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/ | blog/CVE-2025-55284 |
| 56 | Amazon Q Developer Data Exfil via DNS | Johann Rehberger | Aug 18, 2025 | https://embracethered.com/blog/posts/2025/amazon-q-developer-data-exfil-via-dns/ | blog |
| 57 | Terminal DiLLMas: Prompt Injection via ANSI Sequences | Johann Rehberger | 2024 | https://embracethered.com/blog/posts/2024/terminal-dillmas-prompt-injection-ansi-sequences/ | blog |
| 58 | macOS Terminal DiLLMa DNS Exfil ANSI Escape Code Fix | Johann Rehberger | Jul 16, 2026 | https://embracethered.com/blog/posts/2026/macos-terminal-dillma-dns-exfil-ansi-escape-code-fix/ | blog |
| 59 | Here Comes The AI Worm (Morris-II / ComPromptMized) | Ben Nassi, Stav Cohen, Ron Bitton | Mar 5, 2024 (v2 Jan 30, 2025) | https://arxiv.org/abs/2403.02817 | paper |
