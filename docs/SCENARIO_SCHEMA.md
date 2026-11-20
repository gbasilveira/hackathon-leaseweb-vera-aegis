# Scenario configuration

Each scenario is a local JSON document. The schema lives in `scenarios/schemas/scenario.schema.json`. The loader checks references across collections. IDs used by replay, edges, policies and proposals must resolve in the same document.

The tenant and infrastructure collections form the initial inventory. Dependencies run from consumer to provider. The configured change adds a new directed dependency. Session grants name a registered operation and target. Replay entries can record an observation or request an operation against the simulator. Stable evidence IDs let offline proposal templates refer to earlier journal entries. A replay result comes from the current control-plane state.

The incident process maps a state and event signal to a destination state. Runtime components emit signals after completing their work. Policy rules carry a numeric priority, condition, result and stable reason code. A terminal default denial protects unmatched combinations. The proposal phases select the initial or alternative responses for deterministic investigation.

Inspect either bundled fixture with `python -m aegis config-export SCENARIO`. Use `config-import` to validate and create a new local scenario file. This command refuses to overwrite an existing file.

The incident classification table maps observed event IDs to severity levels. As fixture evidence arrives, the highest matching severity is reflected in the incident snapshot. Session validity durations are relative to scenario load time, so the configured expired and active sessions behave consistently on the presentation machine.
