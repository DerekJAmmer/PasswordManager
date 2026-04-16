# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**PasswordManager** — a local-first Python password manager. Stores credentials in an AES-256-GCM encrypted JSON vault on disk, unlocked by a master password. Ships with a Tk GUI (default) and an argparse CLI. No server, no network, no database.

## Purpose

Personal password storage with portfolio-quality desktop-app fundamentals: strong crypto, audit logging, rate limiting, auto-lock, and secure clipboard handling. The code is meant to be clean enough to stand up to review.

## Workflow — the mini SDLC

Every task, no exceptions:

1. **PLAN FIRST.** Enter plan mode (or write a short plan inline) before touching code. No edits until the plan is agreed.
2. **IMPLEMENT SECOND.** Execute the plan exactly. No scope creep, no "while I'm here" detours.
3. **VERIFY LAST.** Run tests, exercise the feature end-to-end, inspect actual output. Do not report "done" based on the code looking right.
4. **FIX AND RE-VERIFY.** If verification fails, diagnose the root cause, fix it, and re-verify. Loop until clean. Never paper over a failing check.
5. **PUSH.** After verify passes and the commit lands, run `git push origin main` so the work is visible at `https://github.com/DerekJAmmer/PasswordManager`. A phase is not done until it is on the remote. Never claim "phase complete" while commits sit only in the local repo.

## Task decomposition

Break any large or complex task into small, individually-verifiable pieces. Work one piece at a time. Do not start the next piece until the current one passes verification. If a piece turns out to be larger than expected, stop and re-decompose — don't just push through.

## Rules

- **Best practices only.** No shortcuts, no hacks that would embarrass in review, no `--no-verify` / `--force` on git.
- **Never hallucinate.** Don't invent APIs, function names, file paths, CLI flags, or library behavior. If unsure, read the source or ask.
- **Never duplicate.** Search for existing implementations before writing new ones. Reuse first, extend second, create third.
- **Never fake systems.** No placeholder stubs, no "TODO: real implementation later", no references to files/functions/modules that don't exist.
- **Never claim done without verification.** A passing type-check is not verification of behavior. Actually run the thing.

## Project memory

Deep project knowledge — architecture, file roles, key APIs, crypto/vault schema, backup format versions, KDF docs/code mismatch, rate-limit and auto-lock internals, data locations, dependency notes — lives in the Obsidian vault:

```
C:\ClaudeVault\wiki\projects\PasswordManager\
```

Read these at session start, in order:

1. `roadmap.md` — current milestone, in-progress, up-next
2. `docs.md` — architecture + APIs + tech decisions
3. `deps.md` — commands, dependencies, data locations, setup gotchas
4. `devlog.md` — recent work log

Update `devlog.md` at end of session (or on "update memory"): one dated bullet per session. Rotate oldest 20 entries to `devlog-archive.md` when `devlog.md` passes ~40 entries.

This file (`CLAUDE.md`) holds only what you are looking at now. Do not re-home architecture detail here — that belongs in the vault.
