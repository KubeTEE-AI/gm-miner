# Unified text-to-speech transport validation

This records the miner-side implementation and local validation. Static image
features describe compiled transport support; they do not prove a provider
credential is configured, a reviewed route is admitted, an offer is live, or
confidential execution is available.

## Transport scope

- Gemini keeps its native `generateContent` request shape. The dedicated
  `gemini-3.8-flash-tts` route uses the Google AI Studio key and has no Envoy
  retry policy. Existing Gemini chat paths retain their current retry behavior.
- DeepInfra and Together use their OpenAI-compatible `POST /v1/audio/speech`
  path. DeepInfra rewrites that path to `/v1/openai/audio/speech`; Together
  sends it to `api.together.xyz`. Both speech routes have no retry policy.
- Chutes AudioDojo is a separate host and TLS identity at
  `vonkaiser-audiodojo.chutes.ai`, with only the reviewed `/tts/kokoro` and
  `/tts/qwen3custom` path/model pairs. It is not covered by the current Chutes
  TEE verifier; `-TEE` selectors are rejected before routing. No confidential
  serving claim is made for AudioDojo.
- Google Cloud's global Gemini `:generateContent` source at
  `aiplatform.googleapis.com` is not implemented. It uses OAuth credentials
  and project/location resource paths, unlike the Google AI Studio API-key
  route; this miner does not support that Cloud auth/path profile. This is not
  the [legacy Cloud Text-to-Speech API](https://docs.cloud.google.com/text-to-speech/docs/gemini-tts),
  which is not the relevant Gemini 3.8 TTS endpoint. See Google's [Cloud Gemini
  speech guide](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/text-to-speech/overview).
  Existing Google AI Studio Gemini support remains separate.

The image advertises `speech-openai-v1`, `speech-gemini-v1`, and
`speech-chutes-audiodojo-v1` as transport implementation flags. Registry
eligibility still requires the exact reviewed source profile, matching product
capability, worker readiness and credentials, and live supply. Those runtime
admission gates have not been demonstrated by this local validation.

## Validation evidence

The test-first baseline was run before implementation:

```sh
CARGO_TARGET_DIR=/Users/mark/Contracts/gm-miner/target CARGO_BUILD_JOBS=2 \
  cargo test -p gmcli --test start_render_test
```

It reported 53 tests: 48 passed and the five new speech transport regressions
failed as intended (AudioDojo fell through to the generic Chutes route, TEE
selection was not rejected, Gemini and DeepInfra speech inherited transparent
retries, and Together was not a configured provider key). The feature projection
also failed before adding the three speech flags:

```sh
CARGO_TARGET_DIR=/Users/mark/Contracts/gm-miner/target CARGO_BUILD_JOBS=2 \
  cargo test -p gmcli --lib image_version::tests::admin_request_omits_status_and_empty_options
```

That single feature test failed because the expected projection lacked the
three speech transport flags.

After implementation, the focused rendering suite passed 54 tests. The full
`cargo test -p gmcli --quiet` suite passed with 806 tests passing and one
read-only live RPC test intentionally ignored, including the package unit, CLI,
and integration tests. Those counts are from the transport-only implementation
before the character-price CLI regression below.

The final character-price regression uses the canonical buyer tuple `hexgrad` /
`kokoro-82m` with a `$0.99/Mchar` input rate, plus a DeepInfra source tuple
whose native model is `hexgrad/Kokoro-82M`. The initial red fixture used the
same Kokoro model family under an OpenAI-compatible product key; the registry
tuple was corrected to `hexgrad` / `kokoro-82m` before implementation. Before
the CLI fix, the declaration dropped the character rate and the sourcing
table rendered only zero-valued token anchors. The red run was:

```sh
CARGO_TARGET_DIR=/Users/mark/Contracts/gm-miner/target CARGO_BUILD_JOBS=2 \
  cargo test -p gmcli --bin gmcli character_priced -- --nocapture
```

Both character-priced regression tests failed as intended. After adding the
optional serde field and shared price-unit metadata, the focused run passed 2
tests. The test also checks that a 15% discount floors to `$0.8415/Mchar` in
declaration and status output, that source retail shows `$0.990/Mchar`, and
that neither figure is labelled per Mtok.

The source summary then regressed for token-priced Gemini products with
cache-storage pricing: the generic distinct-unit headline returned only the
storage rate, hiding the input/output anchors and extra-dimension count. A
catalog-shaped Gemini 2.5 Pro fixture with nonzero input/output, long-context,
and cache-storage prices was added first. It failed before the fix with
`$0.375 per Mtok-hour` instead of `$1.250 in / $5.000 out +3 per Mtok`.
`flat_or_character_price_summary` now uses the shared price-unit metadata and
returns a unit-only headline only when token anchors are zero and every priced
dimension uses a character, image, or video unit. Token-priced products retain
their anchors and extras count; the existing Kokoro and video source tests
continue to verify unit-only display. The focused source test run passed all
27 tests.

The final workspace-wide `cargo test --all-features --quiet` run passed 1086
tests; one read-only live RPC test was intentionally ignored. Strict Clippy
passed:

```sh
CARGO_TARGET_DIR=/Users/mark/Contracts/gm-miner/target CARGO_BUILD_JOBS=2 \
  cargo clippy --all-targets --all-features -- -D warnings
```

`cargo fmt --all -- --check` passed. `scripts/validate-envoy.sh`, using the
miner-pinned Envoy image and a rendered direct-all configuration with Together
enabled, passed every config variant and its Chutes/KubeTEE runtime checks:

```sh
GMCLI_BIN=/Users/mark/Contracts/gm-miner/target/debug/gmcli scripts/validate-envoy.sh
```

No supplier requests, paid synthesis calls, live route admission, buyer billing,
or settlement checks are performed by these tests. A paid speech canary remains
deferred because gmcli has no safe buyer-authenticated gateway request and
reconciliation path. `doctor` remains a free local configuration check and does
not claim live TTS serving.
