# Building risk-translator with Claude Code

About 15 hours for v1, best done after the TB1 hand-ins (from Fri 11 Dec) and over the winter break. Six phases of 1.5 to 3 hours. Each one ends with something that works, a passing test run and a commit you made yourself.

---

## One-time setup (about 45 minutes, you do this)

1. **Install Claude Code** in Terminal: `curl -fsSL https://claude.ai/install.sh | bash`, then check with `claude --version`. (Homebrew alternative: `brew install --cask claude-code`.)
2. **Install Nmap:** `brew install nmap`. The `vulners` script that lists CVEs comes with it.
3. **Make the repo outside iCloud** (git and iCloud sync don't mix well):
   ```
   mkdir -p ~/Developer/risk-translator && cd ~/Developer/risk-translator
   git init
   ```
   Then create an empty **private** GitHub repo called `risk-translator` and connect it (GitHub shows you the two commands). Make it public at v0.1.
4. **Copy in the starter files:** `CLAUDE.md` at the top level, `SPEC.md` and `BUILD-PROMPTS.md` in `docs/`. Create `docs/decisions.md` with one line: `# Design decisions`.
5. **Edit `docs/SPEC.md` into your own words**, and settle the first DECIDE items (asset criticality scale, likelihood rules, risk bands). Log each in `docs/decisions.md`: the decision, the options you rejected, and why.
6. **Request a free NVD API key** from the NVD developers page. You'll paste it into `.env` in phase 2.
7. **First commit:** `git add . && git commit -m "Project brief and working rules"`.

## The loop for every phase

1. `cd ~/Developer/risk-translator`, then `claude`. Type `/clear` to start fresh if you're continuing a session. CLAUDE.md loads automatically, so Claude always knows the rules.
2. **Plan mode first:** press `Shift+Tab` until the mode shows Plan (or start your message with `/plan`). In this mode Claude reads and proposes but can't edit files.
3. **Paste the phase prompt** from below.
4. **Read the plan properly.** Push back on anything you don't understand or wouldn't choose. When it's right, approve it with **"Yes, manually approve edits"**, so you see each change as it lands.
5. **Let it build.** It should run `pytest` and `ruff` at the end. If it goes off track, press `Esc` to stop it, and use `/rewind` to roll the code back to an earlier point.
6. **Review it yourself:** run `git diff`, run the tool on the sample data, and ask about anything you can't explain (use the explain prompt below).
7. **Commit it yourself** with your own message, then tick the Things to-do.

**Output style:** use `/output-style Explanatory` for most phases (Claude adds short "Insight" notes explaining its choices). Switch to `/output-style Learning` for phase 3: Claude leaves `TODO(human)` markers at the real design decisions and waits for you to write those lines. That's the part of the project interviewers will ask about, so it should be your code. (If `/output-style` isn't recognised, update Claude Code.)

---

## Phase 1: skeleton and CVE-list input (about 2 hours)

```
Read CLAUDE.md and docs/SPEC.md. We're doing phase 1 only.

Goal: a working project skeleton that reads a CSV of asset,cve pairs and an assets.yaml file, validates them, and prints a simple table.

Please:
1. Propose the folder layout (src/ layout, package risk_translator), pyproject.toml with a risk-translator console command, .gitignore (including .venv, .env, .cache, out/), .env.example, and an empty README.md.
2. Propose data models (dataclasses) for Asset and Finding. Explain each field and why it's there.
3. Write the CSV and YAML readers, with clear errors for malformed CVE IDs, duplicate rows, and CVEs whose asset isn't in assets.yaml.
4. Create samples/cves.csv (about 8 rows across 3 made-up assets, including well-known CVEs such as CVE-2021-44228 and CVE-2014-0160) and samples/assets.yaml using the criticality scale in docs/decisions.md.
5. Tests for the readers, including the error cases.

Show me the plan first. Don't build anything yet. Stop when phase 1 is done and the tests pass.
```

## Phase 2: enrichment from KEV, EPSS and NVD (about 3 hours)

Put your NVD key in `.env` first (`NVD_API_KEY=...`).

```
Phase 2 only. Read CLAUDE.md and docs/SPEC.md first.

Goal: enrich each Finding with data from the CISA KEV catalogue, the FIRST EPSS API and the NVD CVE API 2.0.

Please:
1. Explain each API in two or three sentences: the endpoint, what fields we'll use, rate limits and how we'll stay within them.
2. Build one small client module per source, plus a shared on-disk cache in .cache/ so a second run makes no network calls.
3. KEV: download the JSON catalogue once per run. EPSS: batch CVEs in one request where possible. NVD: one CVE per request, using NVD_API_KEY from .env, with backoff and retry on 403 or 429.
4. Pull out: CVSS base score and severity (prefer CVSS v3.1, fall back sensibly and tell me how), description, CWE IDs, EPSS score and percentile, KEV yes/no and date added.
5. Record a few real responses as fixtures in tests/fixtures/ (run each API once to capture them), then write tests that use only the fixtures.
6. If an API is down, carry on and mark the affected fields as missing.

Plan first, then build. Stop when the tests pass and a real run on samples/cves.csv prints the enriched table.
```

## Phase 3: scoring, asset criticality and ISO mapping (about 3 hours, Learning style)

Run `/output-style Learning` before this one.

```
Phase 3 only. Read CLAUDE.md, docs/SPEC.md and docs/decisions.md first.

Goal: score each finding (likelihood x impact on a 5 x 5 matrix), assign a band, and map it to ISO/IEC 27001:2022 Annex A controls.

Rules for this phase:
- Scoring rules and thresholds are my decisions. Use what's in docs/decisions.md. Where something isn't decided yet, give me 2 or 3 options with trade-offs and leave a TODO(human) for me to write it.
- The ISO mapping lives in mappings/iso27001.yaml. Every finding maps to 8.8; a second control comes from the CWE IDs. Build the loader and the lookup, but leave the mapping entries for me to write. Control numbers and short names only, never text from the standard.
- Add a suggested treatment per band (for example "patch within 7 days" for Critical) and leave the actual wording to me.

Tests: a table of example inputs with the expected likelihood, impact, score and band, including the edge cases (on KEV, no EPSS score, no CVSS score, critical asset, low-criticality asset).

Plan first. Stop when the tests pass.
```

## Phase 4: Nmap input (about 2 hours)

First make a real sample by scanning **your own lab VM only**: `nmap -sV --script vulners -oX samples/lab-scan.xml <your VM's IP>`. Add the VM to `samples/assets.yaml` by its IP.

```
Phase 4 only. Read CLAUDE.md first.

Goal: accept an Nmap XML file produced with -sV --script vulners as input, alongside the CSV.

Please:
1. Explain the structure of the Nmap XML and where the vulners script puts CVE IDs.
2. Write a parser, using defusedxml rather than the standard library XML parser, that turns each host and service into Findings, matching hosts to assets.yaml by IP. Unknown hosts should be reported clearly, not dropped silently.
3. Choose the input type from the file extension, with an --input-type flag to override.
4. Tests using samples/lab-scan.xml plus a small hand-made XML with edge cases (no CVEs, several ports, a host not in assets.yaml).

Plan first. Stop when the tests pass and a full run on samples/lab-scan.xml works.
```

## Phase 5: the three outputs (about 3 hours)

```
Phase 5 only. Read CLAUDE.md and docs/SPEC.md first.

Goal: write the three outputs to the --out folder.

1. register.csv and register.xlsx: columns as in docs/SPEC.md, sorted by score, highest first. In the Excel file, freeze the header row, colour the band column, and add a filter.
2. heatmap.png: the 5 x 5 matrix, likelihood up the side, impact along the bottom, count of risks in each cell, cells coloured by band. Readable when printed in black and white.
3. summary.md: one page for a board. Headline numbers, the top five risks in plain English (what it is, which system, why it matters to the business, what to do), everything on KEV, three recommended actions, a short "how this was scored" note, and the data credits including the NVD notice. British English, no em dashes, no unexplained jargon.

Show me a draft of summary.md for the sample data before writing the generator, so I can change the structure.

Tests: the files exist, have the right columns and row counts, and the summary contains the required sections.
```

## Phase 6: polish and release v0.1 (about 2 hours, mostly you)

```
Phase 6. Read CLAUDE.md first.

1. Review the whole codebase for bugs, unclear names, missing tests and anything that would embarrass me in a code review. List the issues first; don't fix anything until I've picked which ones.
2. Check for security problems: secrets in code or git history, XML parsing that doesn't go through defusedxml, unsafe file paths.
3. Suggest an outline for README.md (problem, how it works, scoring model and why, quick start, sample output, data credits, limitations, what's next). Don't write the prose: I will.
```

Then: write the README yourself, add a screenshot of the heat map and a link to a sample summary, tag `v0.1`, make the repo public, and post the LinkedIn milestone.

---

## Prompts to use any time

**Explain before you commit**
```
Explain [file or function] as if I'm being asked about it in an interview: what it does, why it's built this way, what the alternatives were, and what would break first if the input got 100 times bigger.
```

**Quiz me**
```
Ask me five interview questions about this project, one at a time, the way a cyber risk interviewer at a Big Four firm would. Wait for my answer each time, then tell me what a strong answer would add.
```

**Stuck for 20 minutes**
```
Stop. Summarise what we tried, what failed and your best guess at the cause, then suggest the smallest next step. Don't change any code yet.
```

**Session getting long**

Use `/compact` to summarise the conversation and free up space, or `/clear` and start the phase prompt again. Your files and CLAUDE.md stay as they are.

---

## Interview story (fill in as you go)

- The problem in one sentence:
- Why CVSS alone ranks risk wrongly, with one example from your own sample:
- Your scoring model and the decision you changed your mind on:
- What you'd build next, and why:
