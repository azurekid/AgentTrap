<#
.SYNOPSIS
  Static scanner for agent instruction files (AGENTS.md, CLAUDE.md, copilot-instructions.md, ...).

.DESCRIPTION
  Detects instructions that could hijack an AI coding agent: token/credential
  exfiltration, rogue package installs, traffic redirection, prompt injection,
  hidden Unicode/comments and files dropped into web-writable folders.
  Shared credential_rules.json patterns also detect potentially embedded credentials.
  Credential-bearing finding snippets are redacted; secrets are never validated online.

  The script is organised as small, testable functions. Dot-source it to reuse
  individual pieces (e.g. Invoke-AgentFileScan) or run it directly to scan paths.

.EXAMPLE
  ./Scan-AgentsMd.ps1 -Path ~/Downloads, ./repo -Allow corp.example.com -FailOn HIGH

.EXAMPLE
  ./Scan-AgentsMd.ps1 -Path . -Json | Set-Content findings.json

.EXAMPLE
  ./Scan-AgentsMd.ps1 -Path ./repo -IncludeWorkflows
  Also scans .github/workflows/*.yml (opt-in: CI files legitimately use tokens and installs, so expect more noise).

.NOTES
  Besides instruction files (AGENTS.md, CLAUDE.md, .cursorrules, ...) the scanner discovers auto-loaded
  agent/editor config: .claude/settings*.json, .codex/config.toml, .gemini/settings.json, .cursor/mcp.json,
  .mcp.json, .vscode/{settings,tasks,mcp}.json, .windsurfrules, .clinerules, .github/prompts|instructions.
  Each finding carries a 'ref' pointing to the source entry number in SOURCES.md.
  Exit code 1 when any finding is at or above -FailOn. Works on PowerShell 5.1+ and 7+.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string[]]$Path,
    [string[]]$Allow = @(),
    [switch]$Json,
    [switch]$NoColor,
    [switch]$IncludeWorkflows,
    [ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')][string]$FailOn = 'HIGH'
)

#region Configuration -----------------------------------------------------------

$script:Severity = @{ LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4 }
$script:SecretRules = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'credential_rules.json') -Raw | ConvertFrom-Json

function Get-ScannerConfig {
    <# Returns the static configuration (patterns, allowlist, IOCs) as one object. #>
    [CmdletBinding()]
    param([string[]]$ExtraAllow = @())

    $opt = [Text.RegularExpressions.RegexOptions]::IgnoreCase
    $rx = { param($p) [regex]::new($p, $opt) }

    [pscustomobject]@{
        NamePattern   = '(^agents?\.md$|^claude\.md$|^gemini\.md$|^copilot-instructions\.md$|\.(instructions|agent|prompt|chatmode)\.md$|^skill\.md$|\.mdc$|^\.cursorrules$|^\.windsurfrules$|^\.clinerules$)'
        # Auto-loaded agent/editor config and rule files, matched on the '/'-normalised full path.
        PathPattern   = ('(/\.claude/settings(\.local)?\.json|/\.codex/config\.toml|/\.gemini/settings\.json|/\.cursor/mcp\.json|/\.mcp\.json|' +
            '/\.vscode/(settings|tasks|mcp)\.json|/\.cursor/rules/[^/]+|/\.windsurf/rules/[^/]+\.md|/\.devin/rules/[^/]+\.md|' +
            '/\.clinerules/[^/]+|/\.cline/rules/[^/]+|/\.github/(prompts|instructions)/[^/]+\.md|/\.junie/guidelines\.md' +
            # Claude commands/agents/hooks, plugin manifests, Gemini commands, and files bundled with skills.
            '|/\.claude/(commands|agents)/(.+/)?[^/]+\.md|/\.claude/hooks/.+|/\.claude-plugin/(plugin|marketplace)\.json|/hooks/hooks\.json|/\.gemini/commands/(.+/)?[^/]+\.toml|/skills/[^/]+/(.+/)?[^/]+\.(md|sh|bash|zsh|py|js|mjs|cjs|ts|ps1|rb|json))$')
        WorkflowPattern = '/\.github/workflows/[^/]+\.ya?ml$'
        # Ref = entry number in SOURCES.md
        IOCs          = @(
            @{ Value = 'function-color'; Kind = 'Malicious npm package (AGENTS.md-in-Downloads incident)'; Ref = '1,2' }
            @{ Value = 's1ngularity-repository'; Kind = 'Nx s1ngularity exfiltration repo name'; Ref = '40,41' }
            @{ Value = '/tmp/inventory.txt'; Kind = 'Nx s1ngularity loot file'; Ref = '40' }
            @{ Value = 'shai-hulud'; Kind = 'Shai-Hulud npm worm artefact'; Ref = '43,44' }
            @{ Value = 'webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7'; Kind = 'Shai-Hulud exfiltration webhook'; Ref = '43' }
            @{ Value = 'crowdstrike-publisher'; Kind = 'Shai-Hulud attacker npm account'; Ref = '44' }
            @{ Value = 'lkmanka58'; Kind = 'Amazon Q wiper-prompt committer account'; Ref = '34' }
            @{ Value = 'wuzzi.net'; Kind = 'DNS-exfiltration PoC domain (research)'; Ref = '55,56' }
        )
        RuleRefs      = @{
            'AI-CLI-SAFETY-BYPASS' = '32,40'; 'AI-PREFILL-LINK' = '67'; 'ANSI-ESCAPE-EXFIL' = '57,58'; 'ANTI-FORENSICS' = '71'
            'AUTH-HEADER' = '1'; 'AUTHORITATIVE-INSTALL' = '10,45,46'; 'CI-SECRET-LEAK' = '52'; 'CI-WORKFLOW-WRITE' = '43,53,54'
            'CLAUDE-APIKEYHELPER' = '23'; 'CLAUDE-HOOKS' = '22,26'; 'CLICKFIX' = '64'; 'CLOUD-METADATA' = '48'
            'CODEX-FULL-ACCESS' = '27'; 'CRED-FILES' = '40'; 'CREDENTIAL-PROMPT' = '71'; 'DISABLE-SAFEGUARDS' = '25,40'
            'DNS-EXFIL' = '55,56'; 'EXFIL-ENV' = '1'; 'FAKE-SYSTEM-TAG' = '47'; 'FILE-EXFIL' = '61'
            'GEMINI-TRUST-OFF' = '28,29'; 'GH-CLI-EXFIL' = '40,50,54'; 'HIDDEN-COMMENT' = '12'; 'HIDDEN-HTML-TEXT' = '12,71'
            'HIDDEN-UNICODE' = '4,5'; 'JAILBREAK-PERSONA' = '69,71'; 'MARKDOWN-IMAGE-EXFIL' = '12'; 'MCP-CONFIG' = '15,19,47'
            'MEMORY-POISONING' = '60,67'; 'NPM-INSTALL' = '1,10'; 'NPX-YES' = '1'; 'OAUTH-TOKEN' = '1'
            'OFFENSIVE-TASKING' = '65,66'; 'PERMISSION-WILDCARD' = '11,24'; 'PERSISTENCE' = '40'; 'PRIVILEGE-ESCALATION' = '71'
            'PRIVILEGE-GRANT' = '68,72'; 'PROMPT-INJECTION' = '4,13'; 'REMOTE-COMMANDS' = '63'; 'REVERSE-SHELL' = '69,71'
            'REVIEW-BYPASS' = '68,71'; 'SKILL-TRIGGER-HIJACK' = '69,70'; 'TOOL-EXFIL' = '68,72'; 'TOOL-SHADOWING' = '47,69'
            'TRAFFIC-REDIRECT' = '1,2'; 'TUNNEL-OAST' = '43'; 'UNICODE-TAG-SMUGGLING' = '6,7,9'; 'UNTRUSTED-LOCATION' = '1,2'
            'VARIATION-SELECTOR-SMUGGLING' = '8'; 'VSCODE-AUTOAPPROVE' = '35,37'; 'VSCODE-TASK-AUTORUN' = '36'; 'WIPER-INSTRUCTION' = '32,33,34,62'
            'WORM-PROPAGATION' = '59,63'
        }
        UntrustedDirs = '[/\\](Downloads|Desktop|Temp|tmp|var[/\\]folders)([/\\]|$)'
        AllowList     = @('github.com', 'githubusercontent.com', 'npmjs.com', 'npmjs.org', 'nodejs.org', 'python.org',
            'pypi.org', 'microsoft.com', 'learn.microsoft.com', 'azure.com', 'docs.github.com', 'w3.org',
            'mozilla.org', 'shields.io', 'readthedocs.io', 'localhost', '127.0.0.1', 'example.com', 'example.org') + $ExtraAllow
        UrlRx         = & $rx '(?:https?|wss?|ftp)://[^\s<>"'')\]`]+'
        IpRx          = & $rx '^\d{1,3}(\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$'
        TldRx         = & $rx '\.(zip|mov|tk|ml|ga|cf|gq|top|xyz|click|work|support|cc|ru|su)$'
        Base64Rx      = [regex]'[A-Za-z0-9+/]{60,}={0,2}'
        BidiRx        = [regex]'[\u202a-\u202e\u2066-\u2069]'
        Rules         = @(
            , @('PIPE-TO-SHELL', 'CRITICAL', 'Remote content piped into a shell/interpreter',
                (& $rx '(curl|wget|iwr|Invoke-WebRequest|irm)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(python3?|node|perl|iex)\b'))
            , @('EXFIL-ENV', 'CRITICAL', 'Environment/secrets sent to a network command',
                (& $rx '(printenv|\benv\b|\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)[A-Z_]*\}?)[^\n]*(curl|wget|nc |netcat|Invoke-WebRequest)|(curl|wget)[^\n]*(\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD)[A-Z_]*|\benv\b|printenv|\.ssh|\.npmrc|\.aws|\.netrc)'))
            , @('AUTH-HEADER', 'HIGH', 'Authorization header / bearer token placed in a command or URL',
                (& $rx 'authorization:\s*(bearer|token|basic)|access_token=|[?&](token|api_?key|secret)='))
            , @('CRED-FILES', 'HIGH', 'Reference to credential stores',
                (& $rx '~/\.ssh|\.ssh/id_|~/\.aws|\.npmrc|\.netrc|\.git-credentials|\.docker/config\.json|gh auth token|keychain|credentials\.json|application_default_credentials|\.config/gh/hosts\.yml|\.copilot/'))
            , @('OAUTH-TOKEN', 'MEDIUM', 'References OAuth/GitHub/cloud token material',
                (& $rx '\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AZURE_[A-Z_]*(SECRET|TOKEN)|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|oauth[ _-]?(access[ _-]?|refresh[ _-]?)?tokens?|(access|refresh|id)_token|client_secret)\b'))
            , @('NPM-INSTALL', 'MEDIUM', 'Package installation / execution instruction',
                (& $rx '\b(npm|pnpm|yarn|bun)\s+(i|install|add|exec|dlx)\b|\bnpx\s+(-y\s+)?\S+|\bpip3?\s+install\b|\buvx?\s+(pip\s+install|run|tool)|\bgo\s+install\b|\bcargo\s+install\b'))
            , @('INSTALL-FROM-URL', 'HIGH', 'Package installed from URL, git or tarball (not registry)',
                (& $rx '\b(npm|pnpm|yarn|pip3?)\s+(i|install|add)\b[^\n]*(https?://|git\+|github:|\.tgz|\.whl|file:)'))
            , @('NPX-YES', 'HIGH', 'npx -y / auto-confirm of unvetted package',
                (& $rx '\bnpx\s+(-y|--yes)\b|\bnpx"?[^\n]*"(-y|--yes)"'))
            , @('INSTALL-SCRIPTS', 'MEDIUM', 'Lifecycle scripts enabled or unsafe flags',
                (& $rx '--unsafe-perm|--ignore-scripts=false|--trusted-host|--no-verify-ssl|--insecure|-k\s+https?://|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|verify\s*=\s*False'))
            , @('REGISTRY-REDIRECT', 'HIGH', 'Package registry or index redirected',
                (& $rx 'npm\s+config\s+set\s+registry|--registry[ =]|--index-url|--extra-index-url|PIP_INDEX_URL|NPM_CONFIG_REGISTRY|registry\s*=\s*https?://|GOPROXY\s*=|GONOSUMDB|GOFLAGS=.*-insecure'))
            , @('TRAFFIC-REDIRECT', 'HIGH', 'Proxy / base-URL / hosts / DNS override that can redirect traffic',
                (& $rx '\b(HTTPS?_PROXY|ALL_PROXY|http\.proxy|git\s+config[^\n]*(url\.|proxy)|OPENAI_(API_)?BASE(_URL)?|ANTHROPIC_BASE_URL|AZURE_OPENAI_ENDPOINT|COPILOT_[A-Z_]*(URL|ENDPOINT|HOST)|GITHUB_API_URL|GH_HOST|/etc/hosts|resolv\.conf|mitmproxy|NODE_EXTRA_CA_CERTS|update-ca-certificates|security\s+add-trusted-cert)\b'))
            , @('TUNNEL-OAST', 'CRITICAL', 'Known tunnelling / request-capture / OAST domain',
                (& $rx '(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|localtunnel|serveo\.net|webhook\.site|requestbin|pipedream\.net|burpcollaborator|oast\.(pro|live|site|online|fun|me)|interact\.sh|interactsh|canarytokens|pastebin\.com/raw|transfer\.sh|discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot|\.workers\.dev|\.herokuapp\.com|\.onion\b)'))
            , @('MCP-CONFIG', 'HIGH', 'Instruction to add/modify MCP server, hook or agent config',
                (& $rx 'mcpServers|claude mcp add|"command"\s*:\s*"(npx|uvx|bash|sh|node|python3?)"|\b(add|create|write|edit|modify|update|append|insert|register|install|configure|put)\b[^\n]{0,60}(mcp\.json|settings(\.local)?\.json|\.vscode/tasks\.json)|"hooks"\s*:|enableAllProjectMcpServers|autoApprove|auto-approve'))
            , @('DISABLE-SAFEGUARDS', 'HIGH', 'Asks agent to bypass approvals/safety',
                (& $rx '--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--trust-all-tools|--yolo|--allow-all|--no-confirm|bypassPermissions|without\s+(asking|confirmation|approval)|(do\s+not|don''?t|never)\s+ask\s+(the\s+user\s+)?(for\s+)?(permission|confirmation|approval)|(do\s+not|don''?t|never)\s+ask\s+(the\s+)?user\s+(before|first|to\s+(confirm|approve))|(disable|turn\s+off|skip|bypass)\s+(all\s+)?(the\s+)?(security|safety)\s+(checks|prompts|controls|guardrails)|(disable|turn\s+off|skip)\s+(all\s+)?(the\s+)?(permission|confirmation|approval)\s+(prompts|checks|dialogs)|chmod\s+(-R\s+)?[0-7]*777|git\s+commit[^\n]*--no-verify'))
            , @('PROMPT-INJECTION', 'HIGH', 'Prompt-injection / concealment phrasing',
                (& $rx 'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules)|disregard\s+(the\s+)?(system|previous)|(do\s+not|don''?t|never)\s+(tell|inform|mention|reveal|show|log|disclose)[^\n]{0,40}(user|developer|human)|without\s+(telling|informing|notifying)\s+the\s+user|keep\s+this\s+(secret|hidden)|you\s+are\s+now\s+in\s+(developer|debug|god)\s+mode|system\s+prompt|override\s+(your\s+)?(safety|instructions)|overrides?\s+(all\s+)?(other|previous|conflicting)\s+(skills|instructions|rules)|(report|mark)\s+(it\s+|the\s+task\s+)?(as\s+)?(complete|completed|done|successful)\s+(either\s+way|regardless|no\s+matter\s+what)'))
            , @('OBFUSCATION', 'HIGH', 'Decoding / eval / obfuscated execution',
                (& $rx 'base64\s+(-d|--decode)|atob\(|b64decode|\beval\b\s*[\(\$`]|\bexec\(|Function\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|String\.fromCharCode|powershell[^\n]*-(enc|encodedcommand)|xxd\s+-r|openssl\s+enc\s+-d|(&#x?[0-9a-f]+;){4,}'))
            , @('PERSISTENCE', 'HIGH', 'Persistence / shell-profile / scheduler modification',
                (& $rx 'crontab|launchctl|LaunchAgents|systemctl\s+enable|~/\.(bash|zsh)(rc|_profile)|\.profile\b|authorized_keys|git\s+config\s+--global\s+core\.hooksPath|\.git/hooks|husky'))
            , @('DESTRUCTIVE', 'MEDIUM', 'Destructive command',
                (& $rx 'rm\s+-rf?\s+(/|~|\$HOME)|mkfs\.|dd\s+if=.*of=/dev/|:\(\)\s*\{|git\s+push\s+[^\n]*--force|DROP\s+(TABLE|DATABASE)|\bkill\s+-(9|KILL)\s+-?1\b'))
            , @('CLAUDE-HOOKS', 'CRITICAL', 'Claude Code hook that runs shell commands automatically (SessionStart/PreToolUse/...)',
                (& $rx '"(SessionStart|SessionEnd|PreToolUse|PostToolUse|UserPromptSubmit|Stop|SubagentStop|PreCompact|Notification)"\s*:|"type"\s*:\s*"command"'))
            , @('CLAUDE-APIKEYHELPER', 'HIGH', 'apiKeyHelper runs a script to obtain API keys (credential harvesting vector)',
                (& $rx '\bapiKeyHelper\b'))
            , @('PERMISSION-WILDCARD', 'HIGH', 'Wildcard permission auto-approves broad shell/tool use',
                (& $rx 'Bash\(\s*\*?\s*\)|Bash\([^)]*\*\s*\)|"Bash"\s*[,\]]|run_shell_command\(\s*\*?\s*\)|"allow"\s*:\s*\[\s*"\*"'))
            , @('CODEX-FULL-ACCESS', 'CRITICAL', 'Codex sandbox/approvals disabled',
                (& $rx 'sandbox_mode\s*=\s*"?danger-full-access|approval_policy\s*=\s*"?never|--dangerously-bypass-approvals-and-sandbox|trust_level\s*=\s*"trusted"'))
            , @('GEMINI-TRUST-OFF', 'HIGH', 'Gemini CLI YOLO / folder-trust / auto-accept enabled',
                (& $rx '--approval-mode[= ]yolo|"folderTrust"[^}]*"enabled"\s*:\s*false|"autoAccept"\s*:\s*true'))
            , @('VSCODE-AUTOAPPROVE', 'CRITICAL', 'VS Code / Copilot agent tool auto-approval (CVE-2025-53773 class)',
                (& $rx 'chat\.tools\.(global\.|terminal\.)?autoApprove|chat\.tools\.eligibleForAutoApproval|chat\.permissions\.default'))
            , @('VSCODE-TASK-AUTORUN', 'HIGH', 'VS Code task runs automatically when the folder is opened',
                (& $rx '"runOn"\s*:\s*"folderOpen"'))
            , @('FAKE-SYSTEM-TAG', 'HIGH', 'Fake system/priority markup used for tool or prompt poisoning',
                (& $rx '<\s*/?\s*(IMPORTANT|system|system-prompt|admin|instructions)\s*>|^\s*\[?SYSTEM\]?\s*:|\[SYSTEM\]|<<\s*/?SYS\s*>>|\[/?INST\]|<\|(im_start|im_end|system|endoftext)\|>'))
            , @('AI-CLI-SAFETY-BYPASS', 'CRITICAL', 'Local AI CLI invoked with safety-bypass flags (Nx s1ngularity / Amazon Q pattern)',
                (& $rx '\b(claude|gemini|q|codex|cursor-agent|copilot)\b[^\n]*(--dangerously-skip-permissions|--yolo|--trust-all-tools|--dangerously-bypass-approvals-and-sandbox|--approval-mode[= ]yolo)'))
            , @('GH-CLI-EXFIL', 'HIGH', 'GitHub CLI/API used to create repos/gists or read secrets (exfil channel)',
                (& $rx '\bgh\s+(gist\s+create|repo\s+create|secret\s+(set|list)|auth\s+token)|\bgh\s+api\b[^\n]*(user/repos|gists)|api\.github\.com/(user/repos|gists)'))
            , @('DNS-EXFIL', 'CRITICAL', 'DNS lookup with variable/placeholder in hostname (DNS exfiltration)',
                (& $rx '\b(ping(\s+-[a-z]\s*\d*)*|nslookup|dig|host)\s+[^\s|;]*(\$\{?[A-Za-z_]|\$\(|`|<[A-Za-z_-]+>|\{[A-Za-z_]+\})'))
            , @('ANSI-ESCAPE-EXFIL', 'HIGH', 'Terminal OSC/ANSI escape sequence (link/DNS exfiltration via terminal)',
                [regex]'(\x1b|\\x1b|\\e|\\033|\\u001b)\](7|8);')
            , @('MARKDOWN-IMAGE-EXFIL', 'HIGH', 'Markdown image whose URL carries data placeholders (image-based exfiltration)',
                (& $rx '!\[[^\]]*\]\(https?://[^)\s]*[?&][^)=\s]*=(\$|\{|<|%7B|\[)'))
            , @('CLOUD-METADATA', 'HIGH', 'Cloud instance-metadata endpoint (credential theft)',
                (& $rx '169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|metadata\.google\.internal|/latest/meta-data|metadata/identity/oauth2/token'))
            , @('WORM-PROPAGATION', 'HIGH', 'Instruction to copy itself into other instruction files/repos (AI worm)',
                (& $rx '(copy|append|add|insert|replicate|write)\s+(this|these|the\s+following)\s+(instructions?|sections?|text|block|notes?|rules?)\b[^\n]{0,80}(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|copilot-instructions|every\s+(repo|repository|project|file))|(append|copy|insert|replicate)\b[^\n]{0,60}\b(every|all)\s+(other\s+)?(instruction|rules?|agent|prompt)\s+files?|propagate\s+(this|itself)|in\s+every\s+(repo|repository|project)\s+you\s+(touch|open|work)|(copy|install|add|replicate)\s+(this|the)\s+skill\b[^\n]{0,60}\b(all|every)\s+(other\s+)?(projects?|repos|repositories|workspaces?)'))
            , @('CI-WORKFLOW-WRITE', 'MEDIUM', 'Instruction creates/edits CI workflows or runs secret scanners',
                (& $rx '(create|add|write|modify|edit|update)\b[^\n]{0,40}\.github/workflows|\btrufflehog\b'))
            , @('WIPER-INSTRUCTION', 'CRITICAL', 'Wiper-style instruction (Amazon Q CVE-2025-8217 pattern)',
                (& $rx 'near[- ]factory|--no-preserve-root|factory\s+(state|reset)|delete\s+(the\s+)?(file-?system|all\s+files|cloud\s+resources)|aws\s+[^\n]*(terminate-instances|delete-bucket|iam\s+delete-user)|s3\s+rm\s+[^\n]*--recursive|az\s+group\s+delete|gcloud\s+[^\n]*\bdelete\b[^\n]*--quiet'))
            , @('AUTHORITATIVE-INSTALL', 'MEDIUM', 'Install phrased as mandatory (slopsquatting / package-hallucination pattern)',
                (& $rx '\b(always|must|required|mandatory|only)\b[^\n]{0,40}\b(npm|pnpm|yarn|pip3?|uv)\s+(i|install|add)\b'))
            , @('CI-SECRET-LEAK', 'HIGH', 'Instruction to print/post/commit CI secrets ("Comment and Control" pattern)',
                (& $rx '(echo|print|post|comment|commit|log)\b[^\n]{0,60}(ANTHROPIC_API_KEY|GEMINI_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)|ps\s+auxeww'))
            , @('EXEC-HIJACK', 'MEDIUM', 'Git/SSH/loader hijack (inferred persistence; no AI-specific incident yet)',
                (& $rx 'core\.(sshCommand|fsmonitor|hooksPath|pager)|filter\.[\w-]+\.(clean|smudge)|ProxyCommand|LD_PRELOAD|DYLD_INSERT_LIBRARIES'))
            , @('WALLET-BROWSER-THEFT', 'HIGH', 'Crypto wallet, browser profile or keychain access',
                (& $rx 'security\s+(dump-keychain|find-generic-password|find-internet-password)|Login Data|cookies\.sqlite|Application Support/(Google/Chrome|BraveSoftware|Firefox)|\.config/(google-chrome|chromium)|wallet\.dat|MetaMask|\.(electrum|ethereum|solana)\b|keystore'))
            , @('MEMORY-POISONING', 'HIGH', 'Instruction to plant persistent memories in the assistant (memory poisoning)',
                (& $rx 'remember\s+(this\s+|that\s+)?(permanently|forever)|(across|for|in)\s+(all\s+)?(future|subsequent)\s+(chats|sessions|conversations)|(store|save|write|add)\s+(this|that|it|the\s+following)\s+(in|to|into)\s+(your\s+)?(long-term\s+|persistent\s+)?memor(y|ies)\b|update\s+(your|the\s+user\W?s?)\s+memor(y|ies)\b'))
            , @('FILE-EXFIL', 'HIGH', 'Local file uploaded by a network command (file exfiltration)',
                (& $rx '(curl|wget|http|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*(\s-d\s*@|--data(-binary|-raw|-urlencode)?[ =]@|\s-F\s*\S*=@|\s-T\s+\S|--upload-file|--post-file|-InFile\b)'))
            , @('REMOTE-COMMANDS', 'CRITICAL', 'Instruction to fetch and execute remote commands (agent command-and-control)',
                (& $rx '(fetch|download|retrieve|poll|check|read)\b[^\n]{0,80}(https?://\S+|\burl\b|endpoint|server)[^\n]{0,40}\b(and\s+)?(then\s+)?(execute|run|eval|follow)\s+(its|the|any|all|whatever)\s+(contents?|commands?|instructions?|response|script|tasks?)'))
            , @('CLICKFIX', 'HIGH', 'ClickFix-style lure to paste clipboard commands into a terminal',
                (& $rx '(paste|run)\b[^\n]{0,60}\bclipboard|clipboard[^\n]{0,60}(terminal|shell|powershell|run\s+dialog|command\s+prompt)|(press|hit)\s+(Win|Windows)\s*\+\s*R\b|are\s+you\s+(a\s+computer|an?\s+(ai|agent|bot|llm))\b'))
            , @('OFFENSIVE-TASKING', 'MEDIUM', 'Offensive operation tasking (exploitation, credential harvesting, mass scanning)',
                (& $rx 'exploit\s+(any|all|the|every)\s+[^\n]{0,30}vulnerabilit|harvest\s+(the\s+|all\s+|any\s+)?credentials|dump\s+(the\s+)?(credentials|hashes|lsass)|move\s+laterally|nuclei\b[^\n]{0,60}\b(against|on)\s+(every|all|each)|\b(fofa|shodan|censys)\b[^\n]{0,60}\b(exposed|vulnerable|targets?)\b|\bmasscan\b|\bsqlmap\b'))
            , @('AI-PREFILL-LINK', 'HIGH', 'Pre-filled AI assistant link that plants instructions or memories (recommendation poisoning)',
                (& $rx 'https?://(copilot\.microsoft\.com|chatgpt\.com|chat\.openai\.com|claude\.ai|(www\.)?perplexity\.ai|gemini\.google\.com|grok\.com)/\S*[?&](q|prompt|text|query)=\S*(remember|memory|trusted|authoritative|always|future|recommend)'))
            , @('REVERSE-SHELL', 'CRITICAL', 'Reverse shell: interactive shell bound to a network socket',
                (& $rx '/dev/(tcp|udp)/[^\s/]+/\d+|\b(nc|ncat|netcat)\b[^\n]*\s-[ec]\s+\S*(sh|cmd(\.exe)?|powershell)\b|\bsocat\b[^\n]*\bexec:|\bmkfifo\b[^\n]*\b(nc|ncat|netcat)\b|socket\.socket\([^\n]*(subprocess|pty\.spawn|os\.dup2)|\bpty\.spawn\(|Net\.Sockets\.TCPClient\('))
            , @('JAILBREAK-PERSONA', 'HIGH', 'Jailbreak persona or unrestricted-mode instruction',
                (& $rx '\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bact\s+as\s+DAN\b|you\s+are\s+(now\s+)?(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken)\b|(free\s+from|without|ignore|no\s+longer\s+bound\s+by)\s+(any\s+|all\s+|your\s+)?(ethical|moral|safety|content)\s+(guidelines|restrictions|limits|filters|policies)|(developer|jailbreak)\s+mode\s+(is\s+)?(enabled|activated|on)\b'))
            , @('CREDENTIAL-PROMPT', 'HIGH', 'Fake password or credential prompt shown to the user',
                (& $rx '\bdisplay\s+dialog\b[^\n]*(password|passphrase|hidden\s+answer)|\b(zenity|kdialog)\b[^\n]*--(password|passwordbox)|\bzenity\b[^\n]*--hide-text|PromptForCredential|\bGet-Credential\b[^\n]*-(Message|Title)\b|\bpinentry\b[^\n]*\b(GETPIN|SETPROMPT)\b'))
            , @('ANTI-FORENSICS', 'HIGH', 'Clears shell history, logs or traces (anti-forensics)',
                (& $rx '\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE\s*=\s*/dev/null|HISTSIZE\s*=\s*0\b|\bClear-History\b|\bwevtutil\s+cl\b|\bClear-EventLog\b|\b(rm|shred|truncate)\b[^\n]*(\.(bash|zsh)_history|/var/log/)|\bcover\s+(your|its|the)\s+tracks\b|(delete|remove|clear|wipe|erase)\s+(the\s+|all\s+|any\s+)?(traces|evidence|audit\s+(logs?|trail)|(shell|command)\s+history)\b'))
            , @('HIDDEN-HTML-TEXT', 'HIGH', 'HTML element hidden with CSS or the hidden attribute (invisible instructions)',
                (& $rx '<[a-z][^>]*\bstyle\s*=\s*["''][^"'']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em)?\s*(;|["''])|opacity\s*:\s*0(\.0+)?\s*(;|["'']))|<(div|span|p|section)\b[^>]*\shidden\b'))
            , @('PRIVILEGE-ESCALATION', 'HIGH', 'Root shell, sudoers change or setuid (privilege escalation)',
                (& $rx '\bsudo\s+(su\b|-i\b|-s\b|(ba|z)?sh\b)|\bsu\s+(-\s+)?root\b|\bsu\s+-\s*$|NOPASSWD|/etc/sudoers|\bchmod\s+([ugo]*\+s\b|[2467][0-7]{3}\b)|\busermod\s+-a?G\s+(sudo|wheel|admin|docker)\b|Add-LocalGroupMember\b[^\n]*Administrators|net\s+localgroup\s+administrators\b[^\n]*/add'))
            , @('REVIEW-BYPASS', 'HIGH', 'Claims prior approval or discourages review (human-trust exploitation)',
                (& $rx '\b(has|have)\s+(already\s+)?pre-?approved\b|\bpre-?approved\s+by\s+(the\s+)?(user|admin|security|owner|maintainers?)|\bno\s+need\s+to\s+(review|verify|inspect|confirm)\b|\b(skip|bypass)\s+(the\s+)?(code\s+|security\s+)?review\b|\b(too\s+long|not\s+necessary|unnecessary)\s+to\s+(review|read|inspect)\b|\bjust\s+(run|execute)\s+it\b|\btrust\s+me\b|(do\s+not|don''?t)\s+(review|inspect|verify)\s+(the\s+|this\s+)?(script|code|commands?|contents?|file)'))
            , @('TOOL-EXFIL', 'HIGH', 'Agent tools told to move secrets or data to another repo, project or tenant',
                (& $rx '\b(create_or_update_file|push_files|create_issue|add_issue_comment|create_gist|create_pull_request|create_work_item|update_work_item|wit_[a-z_]+|send_email|post_message|upload_file)\b[^\n]{0,120}\b(another|other|different|external|separate|personal)\s+(repo|repository|project|organi[sz]ation|org|tenant|account|workspace)\b|\b(secrets?|credentials|tokens?|service\s+connections?|connection\s+strings?|environment\s+variables|\.env)\b[^\n]{0,80}\b(to|into|in)\s+(a\s+|an\s+|the\s+)?(another|other|different|external|separate|personal|public)\s+(repo|repository|project|organi[sz]ation|tenant|gist|work\s+item|issue)\b'))
            , @('SKILL-TRIGGER-HIJACK', 'MEDIUM', 'Skill or tool claims every request or overrides other skills (trigger hijacking)',
                (& $rx '\b(always|must)\s+(use|invoke|load|run|call)\s+this\s+(skill|tool|agent)\b|\buse\s+this\s+(skill|tool)\s+(for|on|with)\s+(any|every|all)\s+(tasks?|requests?|prompts?|questions?|messages?)\b|\b(before|instead\s+of)\s+(any|every|all)\s+other\s+(skills|tools|agents)\b'))
            , @('TOOL-SHADOWING', 'HIGH', 'Instruction changes how another tool behaves (tool shadowing)',
                (& $rx '\b(when|whenever|before|after)\s+(using|calling|invoking|running)\s+(any|the|another|other)\s+([\w.-]+\s+){0,2}tools?\b[^\n]{0,80}\b(always|also|first|instead|secretly|silently)\b|\b(bcc|cc|forward|copy)\s+(all|every|each)\s+(e-?mails?|messages?)\s+to\b'))
            , @('PRIVILEGE-GRANT', 'HIGH', 'Agent told to grant access, roles or group membership',
                (& $rx '\b(add_member|add_team_member|add_collaborator|add_user_to_group|add_group_member|update_team_membership|set_collaborator_permission)\b|\baz\s+role\s+assignment\s+create\b|\bNew-AzRoleAssignment\b|\bgh\s+api\b[^\n]*(collaborators|memberships)|\badd\s+(\S+\s+){0,3}(as\s+)?(an?\s+)?(owner|admin(istrator)?|maintainer|collaborator|member)\s+(of|to)\s+(the\s+)?\S+\s+(group|team|org|organi[sz]ation|project|repo|repository|subscription)\b|\bgrant\s+(\S+\s+){0,3}(owner|admin|contributor|write)\s+(access|role|permissions?)\b'))
        )
    }
}

#endregion

#region Helpers -----------------------------------------------------------------

function New-Finding {
    <# Builds a normalised finding object with a trimmed, length-capped snippet. #>
    param([int]$Line, [string]$Severity, [string]$Rule, [string]$Message, [string]$Snippet, [string]$Ref = '')
    $s = "$Snippet".Trim()
    foreach ($r in $script:SecretRules) {
        if ([regex]::IsMatch($s, $r.pattern)) { $s = '[REDACTED: potential credential]'; break }
    }
    if ($s.Length -gt 160) { $s = $s.Substring(0, 160) }
    [pscustomobject]@{ line = $Line; severity = $Severity; rule = $Rule; message = $Message; snippet = $s; ref = $Ref }
}

function Get-UnicodeSmugglingFinding {
    <# Decodes Unicode Tag-block payloads (ASCII smuggling) and flags variation-selector runs. #>
    param([int]$LineNo, [string]$Line, [hashtable]$Refs)
    $decoded = [Text.StringBuilder]::new()
    $vsRun = 0; $vsMax = 0
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $c = $Line[$i]
        if ([char]::IsHighSurrogate($c) -and $i + 1 -lt $Line.Length) {
            $cp = [char]::ConvertToUtf32($c, $Line[$i + 1]); $i++
            if ($cp -ge 0xE0020 -and $cp -le 0xE007E) { [void]$decoded.Append([char]($cp - 0xE0000)) }
            if ($cp -ge 0xE0100 -and $cp -le 0xE01EF) { $vsRun++; $vsMax = [Math]::Max($vsMax, $vsRun) } else { $vsRun = 0 }
            continue
        }
        if ([int]$c -ge 0xFE00 -and [int]$c -le 0xFE0F) { $vsRun++; $vsMax = [Math]::Max($vsMax, $vsRun) } else { $vsRun = 0 }
    }
    if ($decoded.Length) {
        New-Finding $LineNo 'CRITICAL' 'UNICODE-TAG-SMUGGLING' 'Invisible Unicode Tag characters carry hidden text (ASCII smuggling)' "decoded: $decoded" $Refs['UNICODE-TAG-SMUGGLING']
    }
    # A single U+FE0F is normal emoji styling; runs of selectors can encode a payload.
    if ($vsMax -ge 2) {
        New-Finding $LineNo 'HIGH' 'VARIATION-SELECTOR-SMUGGLING' "Run of $vsMax Unicode variation selectors (possible hidden payload)" (ConvertTo-EscapedString $Line) $Refs['VARIATION-SELECTOR-SMUGGLING']
    }
}

function Test-HostAllowed {
    param([string]$HostName, [string[]]$AllowList)
    $h = $HostName.ToLower()
    foreach ($a in $AllowList) { if ($h -eq $a -or $h.EndsWith(".$a")) { return $true } }
    $false
}

function Test-HiddenCharacter {
    <# True when a line contains invisible/bidi/tag/private-use characters. #>
    param([string]$Text, [regex]$BidiRx)
    $special = 'Format', 'PrivateUse', 'OtherNotAssigned'
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ([char]::IsHighSurrogate($c) -and $i + 1 -lt $Text.Length) {
            $cp = [char]::ConvertToUtf32($c, $Text[$i + 1]); $i++
            if (($cp -ge 0xE0000 -and $cp -le 0xE007F) -or ($cp -ge 0xF0000)) { return $true }  # tag chars / private planes
            continue
        }
        if ($c -eq [char]0x200D -or $c -eq [char]0xFE0F) { continue }  # ZWJ / variation selector
        if ($special -contains [Globalization.CharUnicodeInfo]::GetUnicodeCategory($c).ToString()) { return $true }
    }
    $BidiRx.IsMatch($Text)
}

function ConvertTo-EscapedString {
    param([string]$Text)
    -join ($Text.ToCharArray() | ForEach-Object {
            if ([int]$_ -gt 126 -or [int]$_ -lt 32) { '\u{0:x4}' -f [int]$_ } else { "$_" }
        })
}

#endregion

#region Detectors ---------------------------------------------------------------

function Get-RuleMatch {
    param([int]$LineNo, [string]$Line, [array]$Rules, [hashtable]$Refs = @{})
    foreach ($r in $Rules) {
        if ($r[3].IsMatch($Line)) { New-Finding $LineNo $r[1] $r[0] $r[2] $Line $Refs[$r[0]] }
    }
}

function Get-UrlFinding {
    param([int]$LineNo, [string]$Line, [pscustomobject]$Config)
    foreach ($m in $Config.UrlRx.Matches($Line)) {
        $u = $m.Value
        try { $uri = [uri]$u } catch { continue }
        $h = $uri.Host.ToLower()
        if (-not $h) { continue }
        if ($uri.UserInfo) { New-Finding $LineNo 'CRITICAL' 'URL-CREDENTIALS' 'Credentials embedded in URL' $u }
        elseif ($Config.IpRx.IsMatch($h) -and $h -notin '127.0.0.1', '[::1]') { New-Finding $LineNo 'HIGH' 'RAW-IP-URL' 'URL points to a raw IP address' $u }
        elseif ($uri.Scheme -eq 'http' -and $h -notin 'localhost', '127.0.0.1') { New-Finding $LineNo 'MEDIUM' 'PLAIN-HTTP' 'Unencrypted HTTP URL' $u }
        elseif ($Config.TldRx.IsMatch($h)) { New-Finding $LineNo 'MEDIUM' 'SUSPICIOUS-TLD' 'Domain with TLD commonly abused' $u }
        elseif ($h.StartsWith('xn--') -or $h.Contains('.xn--')) { New-Finding $LineNo 'HIGH' 'PUNYCODE' 'Punycode (possible homograph) domain' $u }
        elseif (-not (Test-HostAllowed $h $Config.AllowList)) { New-Finding $LineNo 'LOW' 'UNLISTED-DOMAIN' "Domain not on allowlist: $h" $u }
    }
}

function Get-Base64Finding {
    param([int]$LineNo, [string]$Line, [pscustomobject]$Config)
    foreach ($m in $Config.Base64Rx.Matches($Line)) {
        $b = $m.Value
        try {
            $trim = $b.TrimEnd('=')
            $pad = '=' * ((4 - $trim.Length % 4) % 4)
            $dec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($trim + $pad))
            if ($dec -match '(?i)curl|wget|http|bash|eval|token|import ') {
                New-Finding $LineNo 'CRITICAL' 'BASE64-PAYLOAD' 'Base64 blob decodes to command/URL' $dec.Substring(0, [Math]::Min(100, $dec.Length))
            }
            else { New-Finding $LineNo 'LOW' 'BASE64-BLOB' 'Long base64-like blob' $b.Substring(0, 60) }
        }
        catch { }
    }
}

function Get-HiddenCommentFinding {
    param([string]$Text, [string]$Ref = '')
    foreach ($m in [regex]::Matches($Text, '<!--(.*?)-->', 'Singleline')) {
        $body = $m.Groups[1].Value
        $ln = ($Text.Substring(0, $m.Index) -split "\n").Count
        $sev = if ($body -match '(?i)\b(run|execute|curl|npm|npx|ignore|instruction|token|http)') { 'HIGH' } else { 'LOW' }
        New-Finding $ln $sev 'HIDDEN-COMMENT' 'HTML comment (invisible when rendered) contains text' ($body.Trim() -replace '\r?\n', ' ') $Ref
    }
}

function Get-ContentFinding {
    <# Runs every content detector over the text and returns de-duplicated findings. #>
    param([string]$Text, [pscustomobject]$Config)
    $out = [Collections.Generic.List[object]]::new()
    $lines = $Text -split "\r?\n"
    for ($n = 1; $n -le $lines.Count; $n++) {
        $ln = $lines[$n - 1]
        foreach ($r in $script:SecretRules) {
            if ([regex]::IsMatch($ln, $r.pattern)) {
                $out.Add((New-Finding $n $r.severity $r.id $r.message '[REDACTED: potential credential]'))
            }
        }
        Get-RuleMatch     $n $ln $Config.Rules $Config.RuleRefs | ForEach-Object { $out.Add($_) }
        Get-UrlFinding    $n $ln $Config                        | ForEach-Object { $out.Add($_) }
        Get-Base64Finding $n $ln $Config                        | ForEach-Object { $out.Add($_) }
        Get-UnicodeSmugglingFinding $n $ln $Config.RuleRefs     | ForEach-Object { $out.Add($_) }
        if (Test-HiddenCharacter $ln $Config.BidiRx) {
            $out.Add((New-Finding $n 'CRITICAL' 'HIDDEN-UNICODE' 'Invisible/bidi/tag Unicode characters (hidden instructions)' (ConvertTo-EscapedString $ln) $Config.RuleRefs['HIDDEN-UNICODE']))
        }
    }
    Get-HiddenCommentFinding $Text $Config.RuleRefs['HIDDEN-COMMENT'] | ForEach-Object { $out.Add($_) }
    $out | Group-Object line, rule, snippet | ForEach-Object { $_.Group[0] }
}

function Get-FileContextFinding {
    <# File-level checks: known IOC strings and untrusted/web-writable location. #>
    param([string]$File, [string]$Text, [pscustomobject]$Config)
    $lines = $Text -split "\r?\n"
    for ($n = 1; $n -le $lines.Count; $n++) {
        foreach ($ioc in $Config.IOCs) {
            if ($lines[$n - 1].IndexOf($ioc.Value, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                New-Finding $n 'CRITICAL' 'KNOWN-IOC' "$($ioc.Kind): $($ioc.Value)" $lines[$n - 1] $ioc.Ref
            }
        }
    }
    $full = [IO.Path]::GetFullPath($File)
    if ($full -match $Config.UntrustedDirs) {
        New-Finding 0 'HIGH' 'UNTRUSTED-LOCATION' 'Instruction file in a web-writable/untrusted folder (Downloads, Desktop, tmp); agents launched here will auto-load it' $full $Config.RuleRefs['UNTRUSTED-LOCATION']
    }
}

function Invoke-AgentFileScan {
    <# Scans a single file's text and returns sorted findings. #>
    [CmdletBinding()]
    param([string]$File, [string]$Text, [pscustomobject]$Config)
    $all = [Collections.Generic.List[object]]::new()
    Get-ContentFinding $Text $Config | ForEach-Object { $all.Add($_) }
    Get-FileContextFinding $File $Text $Config | ForEach-Object { $all.Add($_) }
    $secretLines = @{}
    $privateKey = $false
    foreach ($f in $all) {
        if ($f.rule -like 'SECRET-*') { $secretLines[$f.line] = $true }
        if ($f.rule -eq 'SECRET-PRIVATE-KEY') { $privateKey = $true }
    }
    foreach ($f in $all) {
        if ($privateKey) { $f.snippet = '[REDACTED: file contains private key]' }
        elseif ($secretLines.ContainsKey($f.line)) { $f.snippet = '[REDACTED: potential credential]' }
    }
    $all | Sort-Object line, @{ Expression = { -$script:Severity[$_.severity] } }
}

#endregion

#region Discovery & Output ------------------------------------------------------

function Get-ScanTarget {
    <# Expands paths: a file is returned as-is, a directory is searched recursively. #>
    param([string[]]$Paths, [pscustomobject]$Config, [switch]$IncludeWorkflows)
    foreach ($p in $Paths) {
        if (Test-Path -LiteralPath $p -PathType Container) {
            Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $norm = $_.FullName -replace '\\', '/'
                    $norm -notmatch '/(\.git|node_modules)/' -and (
                        $_.Name -match $Config.NamePattern -or
                        $norm -match $Config.PathPattern -or
                        ($IncludeWorkflows -and $norm -match $Config.WorkflowPattern))
                } |
                ForEach-Object FullName
        }
        elseif (Test-Path -LiteralPath $p) { (Resolve-Path -LiteralPath $p).ProviderPath }
        else { Write-Warning "path not found: $p" }
    }
}

$script:SeverityStyle = [ordered]@{
    CRITICAL = @{ Color = 'Red';        Glyph = [char]0x25CF }  # ●
    HIGH     = @{ Color = 'DarkYellow'; Glyph = [char]0x25B2 }  # ▲
    MEDIUM   = @{ Color = 'Yellow';     Glyph = [char]0x25C6 }  # ◆
    LOW      = @{ Color = 'Gray';       Glyph = [char]0x00B7 }  # ·
}

function Write-Line {
    param([string]$Text, [string]$Color, [switch]$NoColor)
    if ($NoColor -or -not $Color) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

function Write-ScanReport {
    <# Pretty console report: per-file findings plus an aggregate summary table. #>
    [CmdletBinding()]
    param([System.Collections.IDictionary]$Report, [string]$FailOn, [switch]$NoColor)

    $bar = [string][char]0x2500 * 74
    $totals = [ordered]@{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    $filesWithFindings = 0

    Write-Line "`n$([char]0x256D)$bar$([char]0x256E)" -Color Cyan -NoColor:$NoColor
    Write-Line ("$([char]0x2502) {0,-72} $([char]0x2502)" -f 'AGENT INSTRUCTION FILE SCAN') -Color Cyan -NoColor:$NoColor
    Write-Line "$([char]0x2570)$bar$([char]0x256F)" -Color Cyan -NoColor:$NoColor

    foreach ($kv in $Report.GetEnumerator()) {
        $findings = @($kv.Value)
        $name = $kv.Key
        if (-not $findings.Count) {
            Write-Line "`n  $([char]0x2714) $name" -Color Green -NoColor:$NoColor
            Write-Line '      no findings' -Color DarkGray -NoColor:$NoColor
            continue
        }
        $filesWithFindings++
        $top = ($findings | Sort-Object @{ Expression = { $script:Severity[$_.severity] } } -Descending | Select-Object -First 1).severity
        Write-Line "`n  $([char]0x2716) $name" -Color $script:SeverityStyle[$top].Color -NoColor:$NoColor
        Write-Line ("      {0} finding(s)" -f $findings.Count) -Color DarkGray -NoColor:$NoColor
        foreach ($x in $findings) {
            $totals[$x.severity]++
            $style = $script:SeverityStyle[$x.severity]
            $loc = if ($x.line -gt 0) { "L$($x.line)" } else { 'file' }
            Write-Line ("      {0} {1,-9} {2,-5} {3,-28} {4}" -f $style.Glyph, $x.severity, $loc, $x.rule, $x.message) -Color $style.Color -NoColor:$NoColor
            Write-Line ("          {0}" -f $x.snippet) -Color DarkGray -NoColor:$NoColor
            if ($x.ref) { Write-Line ("          ref: SOURCES.md #{0}" -f ($x.ref -replace ',', ', #')) -Color DarkCyan -NoColor:$NoColor }
        }
    }

    Write-Line "`n$([char]0x256D)$bar$([char]0x256E)" -Color Cyan -NoColor:$NoColor
    Write-Line ("$([char]0x2502) {0,-72} $([char]0x2502)" -f 'SUMMARY') -Color Cyan -NoColor:$NoColor
    Write-Line "$([char]0x251C)$bar$([char]0x2524)" -Color Cyan -NoColor:$NoColor
    foreach ($s in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW') {
        $style = $script:SeverityStyle[$s]
        $meter = [string][char]0x2588 * [Math]::Min($totals[$s], 54)
        Write-Line ("$([char]0x2502) {0} {1,-9} {2,4}  {3,-54} $([char]0x2502)" -f $style.Glyph, $s, $totals[$s], $meter) -Color $style.Color -NoColor:$NoColor
    }
    Write-Line "$([char]0x2570)$bar$([char]0x256F)" -Color Cyan -NoColor:$NoColor

    $worst = ($totals.Keys | Where-Object { $totals[$_] -gt 0 } | ForEach-Object { $script:Severity[$_] } | Measure-Object -Maximum).Maximum
    if (-not $worst) { $worst = 0 }
    $totalFindings = ($totals.Values | Measure-Object -Sum).Sum
    $verdict = if ($worst -ge $script:Severity[$FailOn]) { 'FAIL' } else { 'PASS' }
    $vColor = if ($verdict -eq 'FAIL') { 'Red' } else { 'Green' }
    Write-Line ("`n  Scanned {0} file(s), {1} with findings, {2} finding(s) total." -f $Report.Count, $filesWithFindings, $totalFindings) -Color White -NoColor:$NoColor
    Write-Line ("  Verdict: {0}  (threshold: {1})" -f $verdict, $FailOn) -Color $vColor -NoColor:$NoColor

    $worst
}

#endregion

#region Main --------------------------------------------------------------------

function Invoke-AgentScan {
    <# Top-level entry point. Returns the worst severity level encountered (0-4). #>
    [CmdletBinding()]
    param([string[]]$Path, [string[]]$Allow = @(), [switch]$Json, [switch]$NoColor, [switch]$IncludeWorkflows, [string]$FailOn = 'HIGH')

    $config = Get-ScannerConfig -ExtraAllow $Allow
    $report = [ordered]@{}

    foreach ($f in Get-ScanTarget -Paths $Path -Config $config -IncludeWorkflows:$IncludeWorkflows) {
        try { $txt = [IO.File]::ReadAllText($f) }
        catch { Write-Warning "cannot read ${f}: $_"; continue }
        $report[$f] = @(Invoke-AgentFileScan -File $f -Text $txt -Config $config)
    }

    if ($Json) {
        $report | ConvertTo-Json -Depth 5
        $worst = 0
        foreach ($v in $report.Values) { foreach ($x in $v) { $worst = [Math]::Max($worst, $script:Severity[$x.severity]) } }
        return $worst
    }
    Write-ScanReport -Report $report -FailOn $FailOn -NoColor:$NoColor
}

# Only run when invoked directly (not when dot-sourced for reuse/testing).
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $Path) { Write-Error 'Specify -Path with one or more files or directories.'; exit 2 }
    # In -Json mode the JSON text precedes the worst-severity number in the output stream.
    $out = @(Invoke-AgentScan -Path $Path -Allow $Allow -Json:$Json -NoColor:$NoColor -IncludeWorkflows:$IncludeWorkflows -FailOn $FailOn)
    $worst = $out[-1]
    if ($out.Count -gt 1) { $out[0..($out.Count - 2)] }
    exit $(if ($worst -ge $script:Severity[$FailOn]) { 1 } else { 0 })
}

#endregion
