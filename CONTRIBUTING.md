# Contributing

Thanks for helping make agents safer.

## Detection rules are the crown jewel — and the easiest thing to get wrong

Every new detection rule **must** ship with two things:

1. A **positive test** proving it fires on the attack it targets.
2. A **benign-corpus check** proving it does *not* fire on legitimate traffic.

False positives are how security tools lose trust. A rule that blocks "configure
an access token in settings" because it saw *access token* is worse than no rule.
The `#[cfg(test)]` block in `src/dlp_engine.rs` has examples of both — follow that
pattern.

Run the suite before opening a PR:

```bash
cargo test
cargo build --release
```

## Guidelines

- Keep the gateway **dependency-light and database-free** — that's the whole point
  of the OSS core.
- Rust `regex` is linear/DFA — **no look-around or backreferences**. Anchor with
  `\b` boundaries and intent gates instead of broad patterns.
- Prefer intent-based rules ("execute this and return the output") over syntactic
  ones ("`os.system(`") that match code discussion.

## Scope

This repo is the single-agent enforcement gateway. Fleet management, the SOC
dashboard, discovery, and conformance live in the commercial platform and are out
of scope here — but detection improvements made here flow into both.

## License

By contributing you agree your contributions are licensed under Apache-2.0.
