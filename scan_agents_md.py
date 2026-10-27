#!/usr/bin/env python3
"""Static scanner for AI-agent instruction and config files (AGENTS.md, CLAUDE.md, .cursorrules,
.claude/settings.json, .codex/config.toml, .vscode/tasks.json, ...).

Python port of Scan-AgentsMd.ps1 with the same rules, IOCs and SOURCES.md references.
Both scanners load credential_rules.json for embedded-secret detection and redact
credential-bearing finding snippets. Potential secrets are not validated online.

Usage: scan_agents_md.py [--allow DOMAIN ...] [--json] [--include-workflows]
                         [--fail-on LOW|MEDIUM|HIGH|CRITICAL] PATH...
PATH may be a file or a directory (searched recursively). Exit code 1 when any finding is at or
above --fail-on. Each finding has a 'ref' with entry numbers in SOURCES.md.
"""
import argparse, base64, json, os, re, sys, unicodedata
from urllib.parse import urlparse
from pathlib import Path

with Path(__file__).with_name("credential_rules.json").open(encoding="utf-8") as _rules_file:
    SECRET_RULES = [
        (r["id"], r["severity"], r["message"], re.compile(r["pattern"]))
        for r in json.load(_rules_file)
    ]

SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
NAMES = re.compile(r"(^agents?\.md$|^claude\.md$|^gemini\.md$|^copilot-instructions\.md$|"
                   r"\.(instructions|agent|prompt|chatmode)\.md$|^skill\.md$|\.mdc$|^\.cursorrules$|"
                   r"^\.windsurfrules$|^\.clinerules$)", re.I)
# Auto-loaded agent/editor config and rule files, matched on the '/'-normalised full path.
PATHS = re.compile(r"(/\.claude/settings(\.local)?\.json|/\.codex/config\.toml|/\.gemini/settings\.json|/\.cursor/mcp\.json|"
                   r"/\.mcp\.json|/\.vscode/(settings|tasks|mcp)\.json|/\.cursor/rules/[^/]+|/\.windsurf/rules/[^/]+\.md|"
                   r"/\.devin/rules/[^/]+\.md|/\.clinerules/[^/]+|/\.cline/rules/[^/]+|/\.github/(prompts|instructions)/[^/]+\.md|"
                   r"/\.junie/guidelines\.md"
                   # Claude commands/agents/hooks, plugin manifests, Gemini commands, and files bundled with skills.
                   r"|/\.claude/(commands|agents)/(.+/)?[^/]+\.md|/\.claude/hooks/.+|/\.claude-plugin/(plugin|marketplace)\.json|/hooks/hooks\.json|/\.gemini/commands/(.+/)?[^/]+\.toml|/skills/[^/]+/(.+/)?[^/]+\.(md|sh|bash|zsh|py|js|mjs|cjs|ts|ps1|rb|json))$", re.I)
WORKFLOWS = re.compile(r"/\.github/workflows/[^/]+\.ya?ml$", re.I)

R = lambda p: re.compile(p, re.I)
RULES = [
    # (id, severity, description, regex). Kept in sync with Scan-AgentsMd.ps1.
    ('PIPE-TO-SHELL', 'CRITICAL', 'Remote content piped into a shell/interpreter',
     R(r"(curl|wget|iwr|Invoke-WebRequest|irm)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(python3?|node|perl|iex)\b")),
    ('EXFIL-ENV', 'CRITICAL', 'Environment/secrets sent to a network command',
     R(r"(printenv|\benv\b|\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)[A-Z_]*\}?)[^\n]*(curl|wget|nc |netcat|Invoke-WebRequest)|(curl|wget)[^\n]*(\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD)[A-Z_]*|\benv\b|printenv|\.ssh|\.npmrc|\.aws|\.netrc)")),
    ('AUTH-HEADER', 'HIGH', 'Authorization header / bearer token placed in a command or URL',
     R(r"authorization:\s*(bearer|token|basic)|access_token=|[?&](token|api_?key|secret)=")),
    ('CRED-FILES', 'HIGH', 'Reference to credential stores',
     R(r"~/\.ssh|\.ssh/id_|~/\.aws|\.npmrc|\.netrc|\.git-credentials|\.docker/config\.json|gh auth token|keychain|credentials\.json|application_default_credentials|\.config/gh/hosts\.yml|\.copilot/")),
    ('OAUTH-TOKEN', 'MEDIUM', 'References OAuth/GitHub/cloud token material',
     R(r"\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AZURE_[A-Z_]*(SECRET|TOKEN)|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|oauth[ _-]?(access[ _-]?|refresh[ _-]?)?tokens?|(access|refresh|id)_token|client_secret)\b")),
    ('NPM-INSTALL', 'MEDIUM', 'Package installation / execution instruction',
     R(r"\b(npm|pnpm|yarn|bun)\s+(i|install|add|exec|dlx)\b|\bnpx\s+(-y\s+)?\S+|\bpip3?\s+install\b|\buvx?\s+(pip\s+install|run|tool)|\bgo\s+install\b|\bcargo\s+install\b")),
    ('INSTALL-FROM-URL', 'HIGH', 'Package installed from URL, git or tarball (not registry)',
     R(r"\b(npm|pnpm|yarn|pip3?)\s+(i|install|add)\b[^\n]*(https?://|git\+|github:|\.tgz|\.whl|file:)")),
    ('NPX-YES', 'HIGH', 'npx -y / auto-confirm of unvetted package',
     R(r'\bnpx\s+(-y|--yes)\b|\bnpx"?[^\n]*"(-y|--yes)"')),
    ('INSTALL-SCRIPTS', 'MEDIUM', 'Lifecycle scripts enabled or unsafe flags',
     R(r"--unsafe-perm|--ignore-scripts=false|--trusted-host|--no-verify-ssl|--insecure|-k\s+https?://|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|verify\s*=\s*False")),
    ('REGISTRY-REDIRECT', 'HIGH', 'Package registry or index redirected',
     R(r"npm\s+config\s+set\s+registry|--registry[ =]|--index-url|--extra-index-url|PIP_INDEX_URL|NPM_CONFIG_REGISTRY|registry\s*=\s*https?://|GOPROXY\s*=|GONOSUMDB|GOFLAGS=.*-insecure")),
    ('TRAFFIC-REDIRECT', 'HIGH', 'Proxy / base-URL / hosts / DNS override that can redirect traffic',
     R(r"\b(HTTPS?_PROXY|ALL_PROXY|http\.proxy|git\s+config[^\n]*(url\.|proxy)|OPENAI_(API_)?BASE(_URL)?|ANTHROPIC_BASE_URL|AZURE_OPENAI_ENDPOINT|COPILOT_[A-Z_]*(URL|ENDPOINT|HOST)|GITHUB_API_URL|GH_HOST|/etc/hosts|resolv\.conf|mitmproxy|NODE_EXTRA_CA_CERTS|update-ca-certificates|security\s+add-trusted-cert)\b")),
    ('TUNNEL-OAST', 'CRITICAL', 'Known tunnelling / request-capture / OAST domain',
     R(r"(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|localtunnel|serveo\.net|webhook\.site|requestbin|pipedream\.net|burpcollaborator|oast\.(pro|live|site|online|fun|me)|interact\.sh|interactsh|canarytokens|pastebin\.com/raw|transfer\.sh|discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot|\.workers\.dev|\.herokuapp\.com|\.onion\b)")),
    ('MCP-CONFIG', 'HIGH', 'Instruction to add/modify MCP server, hook or agent config',
     R(r'mcpServers|claude mcp add|"command"\s*:\s*"(npx|uvx|bash|sh|node|python3?)"|\b(add|create|write|edit|modify|update|append|insert|register|install|configure|put)\b[^\n]{0,60}(mcp\.json|settings(\.local)?\.json|\.vscode/tasks\.json)|"hooks"\s*:|enableAllProjectMcpServers|autoApprove|auto-approve')),
    ('DISABLE-SAFEGUARDS', 'HIGH', 'Asks agent to bypass approvals/safety',
     R(r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--trust-all-tools|--yolo|--allow-all|--no-confirm|bypassPermissions|without\s+(asking|confirmation|approval)|(do\s+not|don'?t|never)\s+ask\s+(the\s+user\s+)?(for\s+)?(permission|confirmation|approval)|(do\s+not|don'?t|never)\s+ask\s+(the\s+)?user\s+(before|first|to\s+(confirm|approve))|(disable|turn\s+off|skip|bypass)\s+(all\s+)?(the\s+)?(security|safety)\s+(checks|prompts|controls|guardrails)|(disable|turn\s+off|skip)\s+(all\s+)?(the\s+)?(permission|confirmation|approval)\s+(prompts|checks|dialogs)|chmod\s+(-R\s+)?[0-7]*777|git\s+commit[^\n]*--no-verify")),
    ('PROMPT-INJECTION', 'HIGH', 'Prompt-injection / concealment phrasing',
     R(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules)|disregard\s+(the\s+)?(system|previous)|(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|log|disclose)[^\n]{0,40}(user|developer|human)|without\s+(telling|informing|notifying)\s+the\s+user|keep\s+this\s+(secret|hidden)|you\s+are\s+now\s+in\s+(developer|debug|god)\s+mode|system\s+prompt|override\s+(your\s+)?(safety|instructions)|overrides?\s+(all\s+)?(other|previous|conflicting)\s+(skills|instructions|rules)|(report|mark)\s+(it\s+|the\s+task\s+)?(as\s+)?(complete|completed|done|successful)\s+(either\s+way|regardless|no\s+matter\s+what)")),
    ('OBFUSCATION', 'HIGH', 'Decoding / eval / obfuscated execution',
     R(r"base64\s+(-d|--decode)|atob\(|b64decode|\beval\b\s*[\(\$`]|\bexec\(|Function\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|String\.fromCharCode|powershell[^\n]*-(enc|encodedcommand)|xxd\s+-r|openssl\s+enc\s+-d|(&#x?[0-9a-f]+;){4,}")),
    ('PERSISTENCE', 'HIGH', 'Persistence / shell-profile / scheduler modification',
     R(r"crontab|launchctl|LaunchAgents|systemctl\s+enable|~/\.(bash|zsh)(rc|_profile)|\.profile\b|authorized_keys|git\s+config\s+--global\s+core\.hooksPath|\.git/hooks|husky")),
    ('DESTRUCTIVE', 'MEDIUM', 'Destructive command',
     R(r"rm\s+-rf?\s+(/|~|\$HOME)|mkfs\.|dd\s+if=.*of=/dev/|:\(\)\s*\{|git\s+push\s+[^\n]*--force|DROP\s+(TABLE|DATABASE)|\bkill\s+-(9|KILL)\s+-?1\b")),
    # --- Rules added from the deep-research catalog (see SOURCES.md) ---
    ('CLAUDE-HOOKS', 'CRITICAL', 'Claude Code hook that runs shell commands automatically (SessionStart/PreToolUse/...)',
     R(r'"(SessionStart|SessionEnd|PreToolUse|PostToolUse|UserPromptSubmit|Stop|SubagentStop|PreCompact|Notification)"\s*:|"type"\s*:\s*"command"')),
    ('CLAUDE-APIKEYHELPER', 'HIGH', 'apiKeyHelper runs a script to obtain API keys (credential harvesting vector)',
     R(r"\bapiKeyHelper\b")),
    ('PERMISSION-WILDCARD', 'HIGH', 'Wildcard permission auto-approves broad shell/tool use',
     R(r'Bash\(\s*\*?\s*\)|Bash\([^)]*\*\s*\)|"Bash"\s*[,\]]|run_shell_command\(\s*\*?\s*\)|"allow"\s*:\s*\[\s*"\*"')),
    ('CODEX-FULL-ACCESS', 'CRITICAL', 'Codex sandbox/approvals disabled',
     R(r'sandbox_mode\s*=\s*"?danger-full-access|approval_policy\s*=\s*"?never|--dangerously-bypass-approvals-and-sandbox|trust_level\s*=\s*"trusted"')),
    ('GEMINI-TRUST-OFF', 'HIGH', 'Gemini CLI YOLO / folder-trust / auto-accept enabled',
     R(r'--approval-mode[= ]yolo|"folderTrust"[^}]*"enabled"\s*:\s*false|"autoAccept"\s*:\s*true')),
    ('VSCODE-AUTOAPPROVE', 'CRITICAL', 'VS Code / Copilot agent tool auto-approval (CVE-2025-53773 class)',
     R(r"chat\.tools\.(global\.|terminal\.)?autoApprove|chat\.tools\.eligibleForAutoApproval|chat\.permissions\.default")),
    ('VSCODE-TASK-AUTORUN', 'HIGH', 'VS Code task runs automatically when the folder is opened',
     R(r'"runOn"\s*:\s*"folderOpen"')),
    ('FAKE-SYSTEM-TAG', 'HIGH', 'Fake system/priority markup used for tool or prompt poisoning',
     R(r"<\s*/?\s*(IMPORTANT|system|system-prompt|admin|instructions)\s*>|^\s*\[?SYSTEM\]?\s*:|\[SYSTEM\]|<<\s*/?SYS\s*>>|\[/?INST\]|<\|(im_start|im_end|system|endoftext)\|>")),
    ('AI-CLI-SAFETY-BYPASS', 'CRITICAL', 'Local AI CLI invoked with safety-bypass flags (Nx s1ngularity / Amazon Q pattern)',
     R(r"\b(claude|gemini|q|codex|cursor-agent|copilot)\b[^\n]*(--dangerously-skip-permissions|--yolo|--trust-all-tools|--dangerously-bypass-approvals-and-sandbox|--approval-mode[= ]yolo)")),
    ('GH-CLI-EXFIL', 'HIGH', 'GitHub CLI/API used to create repos/gists or read secrets (exfil channel)',
     R(r"\bgh\s+(gist\s+create|repo\s+create|secret\s+(set|list)|auth\s+token)|\bgh\s+api\b[^\n]*(user/repos|gists)|api\.github\.com/(user/repos|gists)")),
    ('DNS-EXFIL', 'CRITICAL', 'DNS lookup with variable/placeholder in hostname (DNS exfiltration)',
     R(r"(?<![\w.-])(ping(\s+-[a-z]\s*\d*)*|nslookup|dig|host)\s+[^\s|;]*(\$\{?[A-Za-z_]|\$\(|`|<[A-Za-z_-]+>|\{[A-Za-z_]+\})")),
    ('ANSI-ESCAPE-EXFIL', 'HIGH', 'Terminal OSC/ANSI escape sequence (link/DNS exfiltration via terminal)',
     re.compile(r"(\x1b|\\x1b|\\e|\\033|\\u001b)\](7|8);")),
    ('MARKDOWN-IMAGE-EXFIL', 'HIGH', 'Markdown image whose URL carries data placeholders (image-based exfiltration)',
     R(r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)=\s]*=(\$|\{|<|%7B|\[)")),
    ('CLOUD-METADATA', 'HIGH', 'Cloud instance-metadata endpoint (credential theft)',
     R(r"169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|metadata\.google\.internal|/latest/meta-data|metadata/identity/oauth2/token")),
    ('WORM-PROPAGATION', 'HIGH', 'Instruction to copy itself into other instruction files/repos (AI worm)',
     R(r"(copy|append|add|insert|replicate|write)\s+(this|these|the\s+following)\s+(instructions?|sections?|text|block|notes?|rules?)\b[^\n]{0,80}(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|copilot-instructions|every\s+(repo|repository|project|file))|(append|copy|insert|replicate)\b[^\n]{0,60}\b(every|all)\s+(other\s+)?(instruction|rules?|agent|prompt)\s+files?|propagate\s+(this|itself)|in\s+every\s+(repo|repository|project)\s+you\s+(touch|open|work)|(copy|install|add|replicate)\s+(this|the)\s+skill\b[^\n]{0,60}\b(all|every)\s+(other\s+)?(projects?|repos|repositories|workspaces?)")),
    ('CI-WORKFLOW-WRITE', 'MEDIUM', 'Instruction creates/edits CI workflows or runs secret scanners',
     R(r"(create|add|write|modify|edit|update)\b[^\n]{0,40}\.github/workflows|\btrufflehog\b")),
    ('WIPER-INSTRUCTION', 'CRITICAL', 'Wiper-style instruction (Amazon Q CVE-2025-8217 pattern)',
     R(r"near[- ]factory|--no-preserve-root|factory\s+(state|reset)|delete\s+(the\s+)?(file-?system|all\s+files|cloud\s+resources)|aws\s+[^\n]*(terminate-instances|delete-bucket|iam\s+delete-user)|s3\s+rm\s+[^\n]*--recursive|az\s+group\s+delete|gcloud\s+[^\n]*\bdelete\b[^\n]*--quiet")),
    ('AUTHORITATIVE-INSTALL', 'MEDIUM', 'Install phrased as mandatory (slopsquatting / package-hallucination pattern)',
     R(r"\b(always|must|required|mandatory|only)\b[^\n]{0,40}\b(npm|pnpm|yarn|pip3?|uv)\s+(i|install|add)\b")),
    ('CI-SECRET-LEAK', 'HIGH', 'Instruction to print/post/commit CI secrets ("Comment and Control" pattern)',
     R(r"(echo|print|post|comment|commit|log)\b[^\n]{0,60}(ANTHROPIC_API_KEY|GEMINI_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)|ps\s+auxeww")),
    ('EXEC-HIJACK', 'MEDIUM', 'Git/SSH/loader hijack (inferred persistence; no AI-specific incident yet)',
     R(r"core\.(sshCommand|fsmonitor|hooksPath|pager)|filter\.[\w-]+\.(clean|smudge)|ProxyCommand|LD_PRELOAD|DYLD_INSERT_LIBRARIES")),
    ('WALLET-BROWSER-THEFT', 'HIGH', 'Crypto wallet, browser profile or keychain access',
     R(r"security\s+(dump-keychain|find-generic-password|find-internet-password)|Login Data|cookies\.sqlite|Application Support/(Google/Chrome|BraveSoftware|Firefox)|\.config/(google-chrome|chromium)|wallet\.dat|MetaMask|\.(electrum|ethereum|solana)\b|keystore")),
    ('MEMORY-POISONING', 'HIGH', 'Instruction to plant persistent memories in the assistant (memory poisoning)',
     R(r"remember\s+(this\s+|that\s+)?(permanently|forever)|(across|for|in)\s+(all\s+)?(future|subsequent)\s+(chats|sessions|conversations)|(store|save|write|add)\s+(this|that|it|the\s+following)\s+(in|to|into)\s+(your\s+)?(long-term\s+|persistent\s+)?memor(y|ies)\b|update\s+(your|the\s+user\W?s?)\s+memor(y|ies)\b")),
    ('FILE-EXFIL', 'HIGH', 'Local file uploaded by a network command (file exfiltration)',
     R(r"(curl|wget|http|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*(\s-d\s*@|--data(-binary|-raw|-urlencode)?[ =]@|\s-F\s*\S*=@|\s-T\s+\S|--upload-file|--post-file|-InFile\b)")),
    ('REMOTE-COMMANDS', 'CRITICAL', 'Instruction to fetch and execute remote commands (agent command-and-control)',
     R(r"(fetch|download|retrieve|poll|check|read)\b[^\n]{0,80}(https?://\S+|\burl\b|endpoint|server)[^\n]{0,40}\b(and\s+)?(then\s+)?(execute|run|eval|follow)\s+(its|the|any|all|whatever)\s+(contents?|commands?|instructions?|response|script|tasks?)")),
    ('CLICKFIX', 'HIGH', 'ClickFix-style lure to paste clipboard commands into a terminal',
     R(r"(paste|run)\b[^\n]{0,60}\bclipboard|clipboard[^\n]{0,60}(terminal|shell|powershell|run\s+dialog|command\s+prompt)|(press|hit)\s+(Win|Windows)\s*\+\s*R\b|are\s+you\s+(a\s+computer|an?\s+(ai|agent|bot|llm))\b")),
    ('OFFENSIVE-TASKING', 'MEDIUM', 'Offensive operation tasking (exploitation, credential harvesting, mass scanning)',
     R(r"exploit\s+(any|all|the|every)\s+[^\n]{0,30}vulnerabilit|harvest\s+(the\s+|all\s+|any\s+)?credentials|dump\s+(the\s+)?(credentials|hashes|lsass)|move\s+laterally|nuclei\b[^\n]{0,60}\b(against|on)\s+(every|all|each)|\b(fofa|shodan|censys)\b[^\n]{0,60}\b(exposed|vulnerable|targets?)\b|\bmasscan\b|\bsqlmap\b")),
    ('AI-PREFILL-LINK', 'HIGH', 'Pre-filled AI assistant link that plants instructions or memories (recommendation poisoning)',
     R(r"https?://(copilot\.microsoft\.com|chatgpt\.com|chat\.openai\.com|claude\.ai|(www\.)?perplexity\.ai|gemini\.google\.com|grok\.com)/\S*[?&](q|prompt|text|query)=\S*(remember|memory|trusted|authoritative|always|future|recommend)")),
    # --- Rules added from the skill-scanner gap analysis (see SOURCES.md) ---
    ('REVERSE-SHELL', 'CRITICAL', 'Reverse shell: interactive shell bound to a network socket',
     R(r"/dev/(tcp|udp)/[^\s/]+/\d+|\b(nc|ncat|netcat)\b[^\n]*\s-[ec]\s+\S*(sh|cmd(\.exe)?|powershell)\b|\bsocat\b[^\n]*\bexec:|\bmkfifo\b[^\n]*\b(nc|ncat|netcat)\b|socket\.socket\([^\n]*(subprocess|pty\.spawn|os\.dup2)|\bpty\.spawn\(|Net\.Sockets\.TCPClient\(")),
    ('JAILBREAK-PERSONA', 'HIGH', 'Jailbreak persona or unrestricted-mode instruction',
     R(r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bact\s+as\s+DAN\b|you\s+are\s+(now\s+)?(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken)\b|(free\s+from|without|ignore|no\s+longer\s+bound\s+by)\s+(any\s+|all\s+|your\s+)?(ethical|moral|safety|content)\s+(guidelines|restrictions|limits|filters|policies)|(developer|jailbreak)\s+mode\s+(is\s+)?(enabled|activated|on)\b")),
    ('CREDENTIAL-PROMPT', 'HIGH', 'Fake password or credential prompt shown to the user',
     R(r"\bdisplay\s+dialog\b[^\n]*(password|passphrase|hidden\s+answer)|\b(zenity|kdialog)\b[^\n]*--(password|passwordbox)|\bzenity\b[^\n]*--hide-text|PromptForCredential|\bGet-Credential\b[^\n]*-(Message|Title)\b|\bpinentry\b[^\n]*\b(GETPIN|SETPROMPT)\b")),
    ('ANTI-FORENSICS', 'HIGH', 'Clears shell history, logs or traces (anti-forensics)',
     R(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE\s*=\s*/dev/null|HISTSIZE\s*=\s*0\b|\bClear-History\b|\bwevtutil\s+cl\b|\bClear-EventLog\b|\b(rm|shred|truncate)\b[^\n]*(\.(bash|zsh)_history|/var/log/)|\bcover\s+(your|its|the)\s+tracks\b|(delete|remove|clear|wipe|erase)\s+(the\s+|all\s+|any\s+)?(traces|evidence|audit\s+(logs?|trail)|(shell|command)\s+history)\b")),
    ('HIDDEN-HTML-TEXT', 'HIGH', 'HTML element hidden with CSS or the hidden attribute (invisible instructions)',
     R(r"""<[a-z][^>]*\bstyle\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em)?\s*(;|["'])|opacity\s*:\s*0(\.0+)?\s*(;|["']))|<(div|span|p|section)\b[^>]*\shidden\b""")),
    ('PRIVILEGE-ESCALATION', 'HIGH', 'Root shell, sudoers change or setuid (privilege escalation)',
     R(r"\bsudo\s+(su\b|-i\b|-s\b|(ba|z)?sh\b)|\bsu\s+(-\s+)?root\b|\bsu\s+-\s*$|NOPASSWD|/etc/sudoers|\bchmod\s+([ugo]*\+s\b|[2467][0-7]{3}\b)|\busermod\s+-a?G\s+(sudo|wheel|admin|docker)\b|Add-LocalGroupMember\b[^\n]*Administrators|net\s+localgroup\s+administrators\b[^\n]*/add")),
    ('REVIEW-BYPASS', 'HIGH', 'Claims prior approval or discourages review (human-trust exploitation)',
     R(r"\b(has|have)\s+(already\s+)?pre-?approved\b|\bpre-?approved\s+by\s+(the\s+)?(user|admin|security|owner|maintainers?)|\bno\s+need\s+to\s+(review|verify|inspect|confirm)\b|\b(skip|bypass)\s+(the\s+)?(code\s+|security\s+)?review\b|\b(too\s+long|not\s+necessary|unnecessary)\s+to\s+(review|read|inspect)\b|\bjust\s+(run|execute)\s+it\b|\btrust\s+me\b|(do\s+not|don'?t)\s+(review|inspect|verify)\s+(the\s+|this\s+)?(script|code|commands?|contents?|file)")),
    ('TOOL-EXFIL', 'HIGH', 'Agent tools told to move secrets or data to another repo, project or tenant',
     R(r"\b(create_or_update_file|push_files|create_issue|add_issue_comment|create_gist|create_pull_request|create_work_item|update_work_item|wit_[a-z_]+|send_email|post_message|upload_file)\b[^\n]{0,120}\b(another|other|different|external|separate|personal)\s+(repo|repository|project|organi[sz]ation|org|tenant|account|workspace)\b|\b(secrets?|credentials|tokens?|service\s+connections?|connection\s+strings?|environment\s+variables|\.env)\b[^\n]{0,80}\b(to|into|in)\s+(a\s+|an\s+|the\s+)?(another|other|different|external|separate|personal|public)\s+(repo|repository|project|organi[sz]ation|tenant|gist|work\s+item|issue)\b")),
    ('SKILL-TRIGGER-HIJACK', 'MEDIUM', 'Skill or tool claims every request or overrides other skills (trigger hijacking)',
     R(r"\b(always|must)\s+(use|invoke|load|run|call)\s+this\s+(skill|tool|agent)\b|\buse\s+this\s+(skill|tool)\s+(for|on|with)\s+(any|every|all)\s+(tasks?|requests?|prompts?|questions?|messages?)\b|\b(before|instead\s+of)\s+(any|every|all)\s+other\s+(skills|tools|agents)\b")),
    ('TOOL-SHADOWING', 'HIGH', 'Instruction changes how another tool behaves (tool shadowing)',
     R(r"\b(when|whenever|before|after)\s+(using|calling|invoking|running)\s+(any|the|another|other)\s+([\w.-]+\s+){0,2}tools?\b[^\n]{0,80}\b(always|also|first|instead|secretly|silently)\b|\b(bcc|cc|forward|copy)\s+(all|every|each)\s+(e-?mails?|messages?)\s+to\b")),
    ('PRIVILEGE-GRANT', 'HIGH', 'Agent told to grant access, roles or group membership',
     R(r"\b(add_member|add_team_member|add_collaborator|add_user_to_group|add_group_member|update_team_membership|set_collaborator_permission)\b|\baz\s+role\s+assignment\s+create\b|\bNew-AzRoleAssignment\b|\bgh\s+api\b[^\n]*(collaborators|memberships)|\badd\s+(\S+\s+){0,3}(as\s+)?(an?\s+)?(owner|admin(istrator)?|maintainer|collaborator|member)\s+(of|to)\s+(the\s+)?\S+\s+(group|team|org|organi[sz]ation|project|repo|repository|subscription)\b|\bgrant\s+(\S+\s+){0,3}(owner|admin|contributor|write)\s+(access|role|permissions?)\b")),
]
RULE_REFS = {
    "CI-SECRET-LEAK": "52", "MEMORY-POISONING": "60,67", "FILE-EXFIL": "61", "REMOTE-COMMANDS": "63", "CLICKFIX": "64", "OFFENSIVE-TASKING": "65,66", "AI-PREFILL-LINK": "67", "FAKE-SYSTEM-TAG": "47", "CLAUDE-APIKEYHELPER": "23", "CRED-FILES": "40",
    "EXFIL-ENV": "1", "ANSI-ESCAPE-EXFIL": "57,58", "CLAUDE-HOOKS": "22,26", "GH-CLI-EXFIL": "40,50,54",
    "MCP-CONFIG": "15,19,47", "DISABLE-SAFEGUARDS": "25,40", "VARIATION-SELECTOR-SMUGGLING": "8", "AUTHORITATIVE-INSTALL": "10,45,46",
    "CLOUD-METADATA": "48", "GEMINI-TRUST-OFF": "28,29", "PERSISTENCE": "40", "WORM-PROPAGATION": "59,63",
    "WIPER-INSTRUCTION": "32,33,34,62", "AI-CLI-SAFETY-BYPASS": "32,40", "MARKDOWN-IMAGE-EXFIL": "12", "UNICODE-TAG-SMUGGLING": "6,7,9",
    "HIDDEN-COMMENT": "12", "AUTH-HEADER": "1", "PROMPT-INJECTION": "4,13", "NPX-YES": "1",
    "DNS-EXFIL": "55,56", "UNTRUSTED-LOCATION": "1,2", "TUNNEL-OAST": "43", "PERMISSION-WILDCARD": "11,24",
    "VSCODE-TASK-AUTORUN": "36", "CI-WORKFLOW-WRITE": "43,53,54", "NPM-INSTALL": "1,10", "OAUTH-TOKEN": "1",
    "HIDDEN-UNICODE": "4,5", "CODEX-FULL-ACCESS": "27", "TRAFFIC-REDIRECT": "1,2", "VSCODE-AUTOAPPROVE": "35,37",
    "REVERSE-SHELL": "69,71", "JAILBREAK-PERSONA": "69,71", "CREDENTIAL-PROMPT": "71", "ANTI-FORENSICS": "71",
    "HIDDEN-HTML-TEXT": "12,71", "PRIVILEGE-ESCALATION": "71", "REVIEW-BYPASS": "68,71", "TOOL-EXFIL": "68,72",
    "PRIVILEGE-GRANT": "68,72", "SKILL-TRIGGER-HIJACK": "69,70", "TOOL-SHADOWING": "47,69",
}

# (value, description, SOURCES.md refs); matched case-insensitively.
IOCS = [
    ("function-color", "Malicious npm package (AGENTS.md-in-Downloads incident)", "1,2"),
    ("s1ngularity-repository", "Nx s1ngularity exfiltration repo name", "40,41"),
    ("/tmp/inventory.txt", "Nx s1ngularity loot file", "40"),
    ("shai-hulud", "Shai-Hulud npm worm artefact", "43,44"),
    ("webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7", "Shai-Hulud exfiltration webhook", "43"),
    ("crowdstrike-publisher", "Shai-Hulud attacker npm account", "44"),
    ("lkmanka58", "Amazon Q wiper-prompt committer account", "34"),
    ("wuzzi.net", "DNS-exfiltration PoC domain (research)", "55,56"),
]
UNTRUSTED_DIRS = re.compile(r"/(Downloads|Desktop|Temp|tmp|var/folders)(/|$)", re.I)
URL = re.compile(r"(?:https?|wss?|ftp)://[^\s<>\"')\]`]+", re.I)
IPHOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$", re.I)
SUSP_TLD = re.compile(r"\.(zip|mov|tk|ml|ga|cf|gq|top|xyz|click|work|support|cc|ru|su)$", re.I)
BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
with Path(__file__).with_name("allowlist.json").open(encoding="utf-8") as _allow_file:
    DEFAULT_ALLOW = [d.strip().lower() for d in json.load(_allow_file)["domains"]]
INVIS = {"Cf", "Co", "Cn"}


def finding(line, sev, rule, msg, snippet, ref=None):
    if any(rx.search(snippet) for _, _, _, rx in SECRET_RULES):
        snippet = "[REDACTED: potential credential]"
    return {"line": line, "severity": sev, "rule": rule, "message": msg,
            "snippet": snippet.strip()[:160], "ref": RULE_REFS.get(rule, "") if ref is None else ref}


def escape(s):
    return "".join(c if 32 <= ord(c) <= 126 else f"\\u{ord(c):04x}" for c in s)


def host_allowed(host, allow):
    host = host.lower()
    return any(host == a or host.endswith("." + a) for a in allow)


def has_hidden_chars(ln):
    for c in ln:
        cp = ord(c)
        if 0xE0000 <= cp <= 0xE007F or cp >= 0xF0000:
            return True
        if c in "\u200d\ufe0f":
            continue
        if unicodedata.category(c) in INVIS:
            return True
    return bool(BIDI.search(ln))


def unicode_smuggling(i, ln):
    """Decode Unicode Tag-block payloads (ASCII smuggling) and flag variation-selector runs."""
    out, run, vmax = [], 0, 0
    decoded = "".join(chr(ord(c) - 0xE0000) for c in ln if 0xE0020 <= ord(c) <= 0xE007E)
    for c in ln:
        cp = ord(c)
        run = run + 1 if (0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF) else 0
        vmax = max(vmax, run)
    if decoded:
        out.append(finding(i, "CRITICAL", "UNICODE-TAG-SMUGGLING",
                           "Invisible Unicode Tag characters carry hidden text (ASCII smuggling)", f"decoded: {decoded}"))
    # A single U+FE0F is normal emoji styling; runs of selectors can encode a payload.
    if vmax >= 2:
        out.append(finding(i, "HIGH", "VARIATION-SELECTOR-SMUGGLING",
                           f"Run of {vmax} Unicode variation selectors (possible hidden payload)", escape(ln)))
    return out


def url_findings(i, ln, allow):
    out = []
    for u in URL.findall(ln):
        try:
            p = urlparse(u)
            host = (p.hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if p.username or p.password:
            out.append(finding(i, "CRITICAL", "URL-CREDENTIALS", "Credentials embedded in URL", u))
        elif IPHOST.match(host) and host not in ("127.0.0.1", "::1"):
            out.append(finding(i, "HIGH", "RAW-IP-URL", "URL points to a raw IP address", u))
        elif p.scheme == "http" and host not in ("localhost", "127.0.0.1"):
            out.append(finding(i, "MEDIUM", "PLAIN-HTTP", "Unencrypted HTTP URL", u))
        elif SUSP_TLD.search(host):
            out.append(finding(i, "MEDIUM", "SUSPICIOUS-TLD", "Domain with TLD commonly abused", u))
        elif host.startswith("xn--") or ".xn--" in host:
            out.append(finding(i, "HIGH", "PUNYCODE", "Punycode (possible homograph) domain", u))
        elif not host_allowed(host, allow):
            out.append(finding(i, "LOW", "UNLISTED-DOMAIN", f"Domain not on allowlist: {host}", u))
    return out


def base64_findings(i, ln):
    out = []
    for b in re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", ln):
        try:
            t = b.rstrip("=")
            dec = base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        if re.search(r"curl|wget|http|bash|eval|token|import ", dec, re.I):
            out.append(finding(i, "CRITICAL", "BASE64-PAYLOAD", "Base64 blob decodes to command/URL", dec[:100]))
        else:
            out.append(finding(i, "LOW", "BASE64-BLOB", "Long base64-like blob", b[:60]))
    return out


def scan_text(text, allow):
    out = []
    for i, ln in enumerate(re.split(r"\r?\n", text), 1):
        for rid, sev, msg, rx in SECRET_RULES:
            if rx.search(ln):
                out.append(finding(i, sev, rid, msg, "[REDACTED: potential credential]"))
        for rid, sev, msg, rx in RULES:
            if rx.search(ln):
                out.append(finding(i, sev, rid, msg, ln))
        out += url_findings(i, ln, allow)
        out += base64_findings(i, ln)
        out += unicode_smuggling(i, ln)
        if has_hidden_chars(ln):
            out.append(finding(i, "CRITICAL", "HIDDEN-UNICODE",
                               "Invisible/bidi/tag Unicode characters (hidden instructions)", escape(ln)))
    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        body = m.group(1)
        sev = "HIGH" if re.search(r"\b(run|execute|curl|npm|npx|ignore|instruction|token|http)", body, re.I) else "LOW"
        out.append(finding(text.count("\n", 0, m.start()) + 1, sev, "HIDDEN-COMMENT",
                           "HTML comment (invisible when rendered) contains text", re.sub(r"\r?\n", " ", body)))
    seen, res = set(), []
    for f in out:
        k = (f["line"], f["rule"], f["snippet"])
        if k not in seen:
            seen.add(k)
            res.append(f)
    return res


def scan_file(path, text, allow):
    fnd = scan_text(text, allow)
    for i, ln in enumerate(re.split(r"\r?\n", text), 1):
        low = ln.lower()
        for value, kind, ref in IOCS:
            if value in low:
                fnd.append(finding(i, "CRITICAL", "KNOWN-IOC", f"{kind}: {value}", ln, ref))
    full = os.path.abspath(path)
    if UNTRUSTED_DIRS.search(full.replace("\\", "/")):
        fnd.append(finding(0, "HIGH", "UNTRUSTED-LOCATION",
                           "Instruction file in a web-writable/untrusted folder (Downloads, Desktop, tmp); "
                           "agents launched here will auto-load it", full))
    secret_lines = {f["line"] for f in fnd if f["rule"].startswith("SECRET-")}
    # Companion detectors can emit truncated/decoded fragments of the same secret.
    for f in fnd:
        if f["line"] in secret_lines:
            f["snippet"] = "[REDACTED: potential credential]"
    if any(f["rule"] == "SECRET-PRIVATE-KEY" for f in fnd):
        for f in fnd:
            f["snippet"] = "[REDACTED: file contains private key]"
    return sorted(fnd, key=lambda f: (f["line"], -SEV[f["severity"]]))


def collect(paths, include_workflows=False):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
                for f in files:
                    full = os.path.abspath(os.path.join(root, f))
                    norm = full.replace("\\", "/")
                    if NAMES.search(f) or PATHS.search(norm) or (include_workflows and WORKFLOWS.search(norm)):
                        yield full
        elif os.path.exists(p):
            yield os.path.abspath(p)
        else:
            print(f"warning: path not found: {p}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--allow", action="append", default=[], help="extra trusted domain (repeatable)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--include-workflows", action="store_true",
                    help="also scan .github/workflows/*.yml (noisier: CI files legitimately use tokens/installs)")
    ap.add_argument("--fail-on", default="HIGH", choices=SEV)
    a = ap.parse_args()
    allow = DEFAULT_ALLOW + a.allow
    report, worst = {}, 0
    for f in collect(a.paths, a.include_workflows):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                txt = fh.read()
        except OSError as e:
            print(f"cannot read {f}: {e}", file=sys.stderr)
            continue
        report[f] = fnd = scan_file(f, txt, allow)
        worst = max([worst] + [SEV[x["severity"]] for x in fnd])
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        counts = {s: 0 for s in SEV}
        for f, fnd in report.items():
            print(f"\n== {f}: {len(fnd)} finding(s)")
            for x in fnd:
                counts[x["severity"]] += 1
                print(f"  L{x['line']:<4} [{x['severity']:<8}] {x['rule']}: {x['message']}\n         > {x['snippet']}")
                if x["ref"]:
                    print(f"         ref: SOURCES.md #{x['ref'].replace(',', ', #')}")
        total = sum(counts.values())
        print(f"\nScanned {len(report)} file(s), {total} finding(s): "
              + ", ".join(f"{s} {counts[s]}" for s in reversed(list(SEV))))
        print(f"Verdict: {'FAIL' if worst >= SEV[a.fail_on] else 'PASS'} (threshold: {a.fail_on})")
    sys.exit(1 if worst >= SEV[a.fail_on] else 0)


if __name__ == "__main__":
    main()
