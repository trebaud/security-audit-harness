# Security Audit Harness

A harness for security audits that stores and dedups its findings in a SARIF format.

- **Agent Skill**: `/security-audit <scope> [--sarif]` traces sources to sinks, proves
  reachability, triages every candidate through a critic subagent, and emits a failing regression
  test per Critical/High. Bootstraps `THREAT_MODEL.md` when absent.
- **Scan skill**: `/scan [scope] [--sarif]` splits a large audit by module, by groups of ~25
  endpoints or by a custom split you describe, runs `/security-audit` headless in one git worktree per group (native `git worktree`
  or [mori](https://github.com/trebaud/mori)), then folds every group into one deduped SARIF run,
  a cross-group chain pass and one report.
- **SARIF log**: `security/audit/baseline.sarif`, deduped on `<ruleId>|<file>|<symbol>`.

## Install

```sh
./install.sh /path/to/repo [--scope app]   # default scope: src
```

Then run `/security-audit <scope> --sarif` one time from your agent. The skill writes
`THREAT_MODEL.md` in the root folder if your repository has no threat model.

## License

MIT.
