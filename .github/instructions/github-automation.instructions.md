---
applyTo: ".github/workflows/**,.github/actions/**"
---

# GitHub Actions review guidance

- Check that referenced paths, scripts, Make targets and artifact names
  exist and match exactly, including case.
- Check triggers, branch filters and which commit is checked out (the PR
  head, the merge commit or the target branch).
- Check that secrets and write tokens are not exposed to code from forks,
  and that pull request runs cannot move deployed tags or parameters.
- Check that required checks cannot pass silently, for example because of
  `continue-on-error`, `|| true`, pipes that hide exit codes, or conditions
  that skip the step.
- Check that actions come from the `stacks-sbtc/actions` repository and are
  pinned to a full commit SHA, as the existing workflows do. A newly used
  action path must exist at that SHA; say so if you cannot confirm it.
