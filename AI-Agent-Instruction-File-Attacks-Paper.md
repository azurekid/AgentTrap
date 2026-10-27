# How Attackers Hijack AI Coding Agents Through Instruction Files

### A Plain-Language Research Paper

**Version 1.0 — 27 October 2026**

---

## A note for the reader

This paper is written in simple English. Many readers do not speak English
as their first language, so the paper uses short sentences and explains
technical words the first time they appear. Each important term is shown in
**bold** and then defined.

The paper is based on public security research published between 2024 and 2026.
A full list of sources is at the end. The companion file `SOURCES.md` lists all
59 sources with links.

---

## Abstract

**AI coding agents** are programs that write and change software for you. You
give them a task in plain words, and they edit files, run commands, and install
software on your computer. To do their job well, these agents read small text
files that contain project rules. A common example is a file named `AGENTS.md`.

This paper shows a serious problem. If an attacker can place or change one of
these rule files, the agent will read the attacker's words and treat them as
trusted orders. The agent may then steal secrets, install harmful software, or
send your data to a stranger's computer. The agent does this while believing it
is being helpful.

We explain how the attack works, we review real incidents, we group the attack
methods into clear categories, and we describe how to defend against them,
including a static scanner we built. The main message is simple: **a rule file
is executable power, so it must be treated as untrusted input, not as
documentation.**

---

## 1. Background: what is an AI coding agent?

An **AI coding agent** is a tool like OpenAI Codex, Claude Code, Google Gemini
CLI, Cursor, GitHub Copilot, Amazon Q, Windsurf, or Cline. It uses a **large
language model** (an "LLM" — a program trained to understand and produce text)
to help you build software.

The key point is that the agent does not only talk. It **acts**. With your
permission, it can:

- read and write files on your computer,
- run commands in the terminal (the text window where you type system commands),
- install software packages from the internet,
- change its own settings.

To act correctly, the agent needs **context** — background information about
your project. Where does it get this context? Partly from **instruction files**.

### 1.1 What is an instruction file?

An **instruction file** is a plain-text file that tells the agent how to work on
a project. It might say "run the tests with this command" or "follow this coding
style". Different tools use different file names. Common ones include:

- `AGENTS.md` (used by several tools)
- `CLAUDE.md` (Claude Code)
- `GEMINI.md` (Gemini CLI)
- `.github/copilot-instructions.md` (GitHub Copilot)
- `.cursorrules` and `.cursor/rules/` (Cursor)
- `.windsurfrules` (Windsurf)
- `SKILL.md` (agent "skills")

There are also **configuration files** (short: "config files"). These store
settings, such as which tools the agent may run without asking. Examples:

- `.claude/settings.json`
- `.codex/config.toml`
- `.gemini/settings.json`
- `.cursor/mcp.json`
- `.vscode/settings.json`

**The crucial fact:** agents load these files **automatically** when they start
in a folder. The user is often not asked and may not even notice. The agent
reads the file and follows it.

---

## 2. The core problem

Here is the problem in one sentence:

> The agent cannot tell the difference between instructions from **you** (the
> trusted owner) and instructions from a **file** that an attacker controls.

To the agent, text is text. If the file says "install package X", the agent
tends to do it. If the file says "do not tell the user", the agent may stay
silent. This kind of trick has a name: **prompt injection**. A **prompt** is the
text given to the language model. **Prompt injection** means hiding harmful
orders inside normal-looking text so that the model obeys them.

When the harmful text comes from a document the agent reads (not typed directly
by the attacker into the chat), we call it **indirect prompt injection**. A
poisoned `AGENTS.md` file is a perfect example.

As one research team put it, there is "nothing to patch" in the usual sense. An
agent that follows the `AGENTS.md` in its folder is doing exactly what it was
built to do [1][2]. The weakness is in the **design and trust model**, not in a
single line of broken code.

---

## 3. The starting incident: a rogue file in the Downloads folder

In October 2026, researchers at Forever Security found a real attack on a
customer's computer [1][2]. The story is important because it shows every step.

**Step 1 — The bait.** A file named `AGENTS.md` appeared in the user's
`~/Downloads` folder. (The symbol `~` means "your home folder". So `~/Downloads`
is your normal download location.)

**Step 2 — Why Downloads is dangerous.** The `~/Downloads` folder is special. It
is the one folder that a web page can write to on its own. When you visit some
web pages, your browser can save a file there **without asking you**. Chrome,
Edge, and Firefox do this by default and only show a small notification. So an
attacker can drop an `AGENTS.md` file onto your machine just by getting you to
open a web page.

**Step 3 — The trigger.** Many people open their AI agent inside `~/Downloads`,
for example to sort or clean the folder. When the agent starts there, it
automatically reads the malicious `AGENTS.md`.

**Step 4 — The payload.** The **payload** (the harmful action) in this case was
an order to install a malicious software package called `function-color`. The
agent tried to install it. The researchers reproduced this against OpenAI Codex
with a 90% success rate using a harmless stand-in action [1].

**Step 5 — A second, worse version.** In a related test, the researchers used a
malicious `CLAUDE.md` file to redirect the agent's network traffic to a server
they controlled. This exposed the agent's **OAuth token** — a secret key that
proves who you are to a service. With that token, the attacker's server could
impersonate the model and send back commands that ran code, succeeding in about
50% of tests [1].

This single story contains the two biggest dangers: **running attacker code**
and **stealing secret tokens**. The rest of this paper widens the picture.

---

## 4. A taxonomy of attack techniques

A **taxonomy** is an organised list of categories. We group the known
techniques into eight families. Each family explains the idea, gives a real
example, and names the warning signs a defender can look for.

### 4.1 Family A — Stealing secrets (exfiltration)

**Exfiltration** means secretly sending data out of your computer to the
attacker. Secrets include API keys, OAuth tokens, SSH private keys (used to log
in to servers), and cloud credentials.

- **Direct send.** The file tells the agent to read a secret and send it with a
  network command such as `curl` or `wget`. Example pattern: read the
  environment variable `GITHUB_TOKEN`, then `curl` it to a remote address.
- **Credential files.** The file points the agent at secret stores like
  `~/.ssh`, `~/.npmrc`, `~/.aws`, or `~/.git-credentials`.
- **DNS exfiltration.** A clever method. The agent hides a secret inside a
  **domain name** and then looks that domain up (for example with `ping`,
  `nslookup`, or `dig`). The lookup travels to the attacker's DNS server, which
  reads the secret from the name. This was shown against Claude Code
  (CVE-2025-55284) and Amazon Q [55][56].
- **Image exfiltration.** The agent is told to show a picture whose web address
  contains your data. Loading the image sends the data out. The "CamoLeak"
  attack against GitHub Copilot (CVE-2025-59145) used GitHub's own image proxy
  to leak private source code, one character at a time [12].
- **Terminal escape codes.** Some terminals treat special hidden character
  sequences (called **ANSI escape codes**) as clickable links or lookups. An
  agent can print such a sequence to leak data [57][58].

**Warning signs:** secret variable names next to `curl`/`wget`; references to
credential files; `ping`/`nslookup`/`dig` followed by odd domain names; image
links or escape sequences that carry data.

### 4.2 Family B — Installing harmful software (supply-chain attacks)

A **supply-chain attack** poisons the software you depend on, so that trusting a
normal-looking package infects you.

- **Rogue package install.** The file tells the agent to install a specific bad
  package, as with `function-color` in the opening story [1].
- **Slopsquatting.** LLMs sometimes "hallucinate" (invent) package names that do
  not exist. Attackers register those invented names in advance. If the agent
  later suggests the invented name, it installs the attacker's code. Socket
  named this trend "slopsquatting" [45]. A 2026 paper showed rule files can be
  used to push such packages on purpose [10].
- **Registry redirection.** The file changes where packages come from, for
  example `npm config set registry` or `pip --index-url`, pointing to an
  attacker's store instead of the official one.
- **CI worm files.** Some attacks create a hidden automation file (a GitHub
  Actions workflow under `.github/workflows/`) so the attack keeps running and
  spreads. The "Shai-Hulud" npm worm did this across hundreds of packages
  [43][44].

**Warning signs:** install commands for unusual packages, especially phrased as
"always use X"; registry or index changes; new workflow files that scan for
secrets.

### 4.3 Family C — Redirecting network traffic

Here the attacker does not steal a file directly. Instead, the attacker changes
**where the agent connects**, so that all later traffic flows through their
server.

- **Base-URL override.** Settings like `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL`
  tell the agent which server to talk to. If an attacker sets these to their own
  address, they see the agent's token and can send fake replies. This is exactly
  the second attack in the opening story [1].
- **Proxy and host overrides.** Variables like `HTTPS_PROXY`, or changing
  `GH_HOST` (the GitHub host), or editing the system `/etc/hosts` file, all
  redirect traffic.
- **Certificate tricks.** Adding a new trusted security certificate
  (`NODE_EXTRA_CA_CERTS`, or installing a custom CA) lets the attacker read
  encrypted traffic without warnings.

**Warning signs:** any `*_BASE_URL` or proxy variable; edits to `/etc/hosts`;
new trusted certificates.

### 4.4 Family D — Weakening the safety switches

Modern agents ask for permission before dangerous actions. These attacks try to
turn that protection off.

- **Bypass flags.** Command options such as `--yolo`,
  `--dangerously-skip-permissions`, or `--trust-all-tools` make the agent act
  without asking. These exact flags were abused in the Nx "s1ngularity" attack,
  where malware invoked local AI CLIs to help it steal data [40][41].
- **Auto-approve settings.** A single setting like
  `"chat.tools.autoApprove": true` in `.vscode/settings.json` lets GitHub
  Copilot run any tool, including terminal commands, without a prompt. Because an
  injected instruction can itself write this setting, it enables remote code
  execution (CVE-2025-53773) [37].
- **Over-broad permissions.** A permission entry like `Bash(*)` in a Claude Code
  settings file means "allow any shell command". Codex has a similar risk with
  `sandbox_mode = "danger-full-access"` and `approval_policy = "never"` [27].

**Warning signs:** bypass flags; auto-approve settings set to true; wildcard
permission entries such as `Bash(*)`.

### 4.5 Family E — Abusing agent and editor configuration

Agents and code editors have powerful features that an attacker can turn against
you by editing a config file.

- **Hooks.** Claude Code supports **hooks** — commands that run automatically at
  certain moments (for example, when a session starts). A poisoned
  `.claude/settings.json` can plant a hook that runs attacker code every time
  [22][26].
- **Key helper.** The `apiKeyHelper` setting names a script that returns your API
  key. If repointed, it can harvest credentials [23].
- **MCP server swap.** **MCP** (Model Context Protocol) lets agents use external
  tools. Cursor trusted an MCP entry by its name, not its content, so an attacker
  could approve a harmless tool and later swap in a harmful command. This was
  "MCPoison" (CVE-2025-54136). A related flaw, "CurXecute" (CVE-2025-54135),
  abused the *creation* of a new `.cursor/mcp.json` file [15][16][19][20].
- **Auto-run tasks.** A `.vscode/tasks.json` set to `"runOn": "folderOpen"` runs
  a command the moment you open the folder [36].

**Warning signs:** `hooks`, `apiKeyHelper`, or MCP server definitions in config
files; tasks set to run on folder open.

### 4.6 Family F — Hiding the attack (obfuscation)

**Obfuscation** means hiding the true meaning so a human reviewer does not see
it, while the machine still reads it.

- **Invisible Unicode.** Computers store text using **Unicode**, a system that
  includes thousands of characters. Some Unicode characters are invisible, such
  as "zero-width" spaces or "Tags-block" characters that mirror normal letters
  but do not show on screen. An attacker can write hidden orders using them. The
  language model reads them; the human does not. This is the basis of the
  "Rules File Backdoor" against Cursor and Copilot [4], and of Johann Rehberger's
  "ASCII smuggling" research [6][7]. GitHub now warns about hidden Unicode in
  files [5].
- **Bidirectional text tricks.** Special direction-control characters can reorder
  how text appears, so a line looks safe but means something else.
- **Base64 and encoding.** Harmful commands can be hidden as **Base64** (a way to
  write data as a block of letters and numbers). The file tells the agent to
  decode and run it.
- **Hidden HTML comments.** Text inside `<!-- ... -->` does not appear when
  Markdown is displayed, but the agent still reads it.

**Warning signs:** invisible or direction-control characters; long Base64 blocks;
hidden comments containing commands.

### 4.7 Family G — Manipulating the human and the agent's mind

These attacks target trust and attention rather than a specific command.

- **"Do not tell the user".** The file orders the agent to hide its actions.
  Combined with another attack, this delays discovery.
- **"Ignore previous instructions".** A direct attempt to cancel the real rules
  and the system's safety text.
- **Fake system messages.** The file pretends to be the trusted system by using
  tags like `<system>` or writing `SYSTEM:`.
- **Lies-in-the-loop.** When the agent must ask a human to approve a step, the
  injected text shapes the question so the human approves something harmful,
  believing it is routine [13].

**Warning signs:** concealment phrases; "ignore/disregard previous"; fake system
tags; approval text that pushes a specific command.

### 4.8 Family H — Spreading and staying (worms and persistence)

- **Self-propagation (worms).** The file tells the agent to copy the malicious
  text into *other* instruction files, in this and other projects. This can
  create a self-spreading "AI worm", a risk described in the academic "Morris-II"
  work [59].
- **Persistence.** The attack installs itself so it survives restarts, for
  example by editing shell start-up files (`~/.bashrc`, `~/.zshrc`), scheduling
  jobs (`crontab`, `launchctl`), or adding Git hooks.

**Warning signs:** orders to edit other instruction files; edits to shell
start-up files, schedulers, or Git hooks.

---

## 5. Real incidents, briefly

These public cases show the families above are not theoretical.

- **AGENTS.md in Downloads (Oct 2026).** The opening story: rogue package install
  and token theft via base-URL redirect [1][2].
- **Rules File Backdoor (Mar 2025).** Hidden Unicode in Cursor/Copilot rule files
  made agents insert insecure code silently [4].
- **Cursor MCPoison & CurXecute (Aug 2025).** Config-file flaws let attackers run
  code through MCP (CVE-2025-54136, CVE-2025-54135) [15][16][19].
- **GitHub Copilot auto-approve RCE (2025).** A settings edit enabled silent
  command execution (CVE-2025-53773) [37].
- **CamoLeak (Sep 2025).** Private source code leaked through image requests
  (CVE-2025-59145) [12].
- **Amazon Q wiper (Jul 2025).** A malicious prompt added to the Amazon Q
  extension told the agent to wipe systems (CVE-2025-8217) [32][33][34].
- **Nx "s1ngularity" (Aug 2025).** Malware used local AI CLIs with bypass flags
  to steal data [40][41].
- **Shai-Hulud npm worm (Sep 2025).** A self-spreading supply-chain worm hit
  hundreds of packages [43][44].

---

## 6. Why normal defences are not enough

Three facts make this threat hard to stop:

1. **Automatic loading.** Agents read instruction and config files without
   asking. The dangerous moment happens before the user can react.
2. **Intended features.** Many "attacks" simply use features working as designed
   (hooks, MCP, base-URL settings). There is no bug to patch.
3. **Human blindness.** Hidden Unicode and comments mean a human review can miss
   the attack even when looking straight at the file.

So defence must combine **user habits**, **tool settings**, and **automatic
checking of the files themselves**.

---

## 7. Defences

### 7.1 For users (habits)

- **Do not start an agent in `~/Downloads`, `~/Desktop`, or `/tmp`.** These
  folders can hold untrusted files. Start the agent in the specific project
  folder it should work on, and keep that scope narrow. This is the official
  advice from both OpenAI and Anthropic [1].
- **Read unfamiliar instruction files** before letting an agent follow them.
- **Keep approval prompts and sandboxing switched on.** A **sandbox** is a
  limited space where code cannot harm the rest of the system.
- **Test untrusted code in an isolated environment** first.

### 7.2 For tool builders

- Treat instruction and config files as **untrusted input**, not trusted
  documentation.
- Bind trust to **file content**, not just a name, so a later swap is detected
  (the lesson of MCPoison) [15].
- **Warn about hidden Unicode**, as GitHub now does [5].
- Make dangerous settings (auto-approve, full-access sandbox) **hard to enable**
  and never enablable by the agent itself.

### 7.3 Automatic scanning (our tool)

We built a **static scanner** — a program that reads the files and looks for
warning signs **without running anything**. ("Static" means it analyses the text;
it does not execute it.) The scanner:

- finds the instruction and config files that agents auto-load, in a folder tree;
- applies about 45 rules that match the warning signs from every family in
  Section 4;
- also reads the **config files** agents trust automatically, such as
  `.claude/settings.json` (hooks, `apiKeyHelper`), `.codex/config.toml`,
  `.gemini/settings.json`, `.cursor/mcp.json`, `.mcp.json` and
  `.vscode/settings.json` / `tasks.json`;
- **decodes hidden Unicode "Tag" text** and shows what it says, and warns about
  long runs of invisible variation selectors;
- checks known **IOCs** (**Indicators of Compromise** — specific known-bad names,
  such as the `function-color` package, the `s1ngularity-repository` name, or the
  Shai-Hulud workflow file);
- flags files that sit in risky locations like `~/Downloads`;
- gives each finding a severity (Critical, High, Medium, Low), a short reason, and
  a **reference number** pointing to the source in `SOURCES.md`;
- can optionally scan CI workflow files (`.github/workflows/`). This is off by
  default, because normal workflows often use tokens and installs;
- can stop an automated pipeline when the risk is too high.

A scanner cannot catch everything. A careful attacker can still hide. So the
scanner is **one layer**, used together with good habits and safe tool settings.
A finding means "a human should review this", not "this is certainly an attack".

---

## 8. Limitations and honest notes

- Some of the techniques in Section 4 are proven by specific incidents; a few are
  **reasonable extensions** of known attacks with no public case yet (for
  example, Git-hook persistence planted by an agent). We mark these as
  well-founded guesses, not confirmed events.
- The package `function-color` is named in the opening report [1]; we have not
  found a second independent public confirmation.
- Security moves fast. New agents and new features will create new versions of
  these attacks. The families, however, are likely to stay stable.

---

## 9. Conclusion

AI coding agents are powerful because they can act on your computer. That same
power is the danger. A small text file, placed by an attacker, can turn a helpful
agent into a tool for stealing secrets, installing malware, or redirecting your
traffic. The agent obeys because it cannot tell trusted orders from untrusted
text.

The fix is not a single patch. It is a change of mindset: **treat every
instruction and config file as untrusted until checked.** Combine careful user
habits, safer tool defaults, and automatic scanning of the files themselves. With
these layers together, the convenience of AI agents can be kept without handing
attackers the keys.

---

## References

Full details and links are in the companion file `SOURCES.md`. The numbers
below are the same as the numbers in `SOURCES.md`. Key sources:

1. BleepingComputer, *AI coding agents hijacked using AGENTS.md file in Downloads
   folder* (Oct 2026).
2. Forever Security, *Hijacking AI agents via Downloads folder* (Oct 2026).
4. Pillar Security, *Rules File Backdoor in GitHub Copilot and Cursor* (2025).
5. GitHub, *Warning about hidden Unicode text* (May 2025).
6–7. J. Rehberger (Embrace The Red), *Hiding and Finding Text with Unicode Tags*
   and *ASCII Smuggling and Hidden Prompt Instructions* (2024).
10. Wang et al., *Package Hallucination Attacks on Coding Agents through Prompt
    Injection in Rule Files*, arXiv (2026).
12. Legit Security, *CamoLeak* (CVE-2025-59145, Sep 2025).
13. Checkmarx Zero, *Lies-in-the-Loop* (Sep 2025).
15–20. Cursor *MCPoison* (CVE-2025-54136) and *CurXecute* (CVE-2025-54135):
    advisories, Check Point Research and Tenable (2025).
22–27. Anthropic Claude Code and OpenAI Codex documentation.
32–34. Amazon Q wiper incident (AWS-2025-015, CVE-2025-8217, Jul 2025).
36. Microsoft, *VS Code Docs: Tasks*.
37. J. Rehberger, *GitHub Copilot RCE via Prompt Injection* (CVE-2025-53773).
40–41. Wiz and Nx, *s1ngularity Supply Chain Attack* (Aug 2025).
43–45. Socket.dev, *Shai-Hulud worm* and *The Rise of Slopsquatting* (2025).
55–56. J. Rehberger, *DNS exfiltration in Claude Code and Amazon Q* (2025).
57–58. J. Rehberger, *Terminal DiLLMas* (ANSI escape codes).
59. Nassi et al., *Here Comes the AI Worm (Morris-II)*, arXiv (2024).
