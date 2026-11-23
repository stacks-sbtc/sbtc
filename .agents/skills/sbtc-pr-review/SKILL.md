---
name: sbtc-pr-review
description: Review sBTC changes the way Copilot reviews pull requests in this repository. Use for requests such as "review my changes", "review this branch", "review this diff", "review PR #123" or "pre-review before I open a PR". Applies the repository's review instructions in .github/ as review criteria, not as code-generation rules.
---

# sBTC PR review

This is a read-only workflow. Do not edit files unless separately asked to.

## 1. Establish the review scope

1. If the user names a PR, commit, range or set of files, review exactly that.
2. Otherwise, find the base branch from the PR metadata or the branch's
   upstream. If neither is available, use `main` and say so.
3. The scope is every change from the merge base with the base branch
   through `HEAD`. For a local review, also include staged, unstaged and
   relevant untracked files.
4. Build the full list of changed files before choosing which instructions
   apply.

## 2. Load the review policy

1. Read `.github/copilot-instructions.md`. It applies to every review.
2. For each `*.instructions.md` file in `.github/instructions/`, read only
   its frontmatter first. Match its comma-separated `applyTo` globs against
   the changed files.
3. Read and apply every file with at least one matching glob in full.

## 3. Review the changes

- Read the PR description, if there is one, alongside the diff. Check the
  code against what it claims, and treat any caveats or known limitations
  it states as leads.
- Report defects that the change introduces or exposes, not problems that
  were already there and are unaffected.
- Follow the comment threshold in `.github/copilot-instructions.md`.
- If useful, run focused validation, for example
  `cargo test -p signer --lib <module>`, `make lint` or `make test`. Report
  what you ran and what you did not run.

## 4. Report findings

Order findings by severity:

- **critical**: loss or theft of funds, signers diverging or disagreeing
  on consensus-relevant decisions, a security compromise, irreversible data
  loss, or a break in compatibility with signers or contracts already
  deployed.
- **major**: incorrect behavior with a realistic trigger and a material
  impact.
- **minor**: a real but limited defect.

For each finding, cite the file and line, describe the trigger and the
impact, and suggest a fix or a way to validate it. Report one finding per
root cause.

End with the scope you reviewed, the instruction files you applied, and the
validation you ran. If there are no findings, say so and mention any gaps in
validation.

If any review guidance turned out to be stale (an instruction or this skill
names a file, function, command or behavior that no longer matches the
code, or a suggested command fails), list it under a separate "Stale
guidance" heading so it can be fixed.
