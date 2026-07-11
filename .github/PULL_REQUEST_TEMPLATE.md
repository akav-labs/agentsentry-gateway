## What & why

<!-- What does this change, and why? Link any related issue (#123). -->

## Checklist

- [ ] `cargo build --release` and `cargo test` pass locally
- [ ] For a **new/changed detection rule**: added a **positive test** (it fires on the attack)
- [ ] ...**and** a **benign-corpus test** (it does *not* fire on legitimate traffic)
- [ ] No real secrets/tokens in the diff — credential-shaped test fixtures are assembled at runtime (see the `fn f(...)` pattern in `dlp_engine.rs` tests)
- [ ] Regexes stay linear (no look-around/backreferences) and prefer intent gates over broad matches
- [ ] Docs / `.env.example` updated if behavior or config changed

## Notes for reviewers

<!-- Anything that needs context: trade-offs, false-positive risk, benchmarks. -->
