# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`c3g-flask-opa` is the Flask library every C3G **Tier 3** app adopts (3a: oauth2-proxy stays
in front; 3b: in-app OIDC via `c3g-oidc`) — see
[web-app-template](https://github.com/c3g/web-app-template)'s `for-app-developers.md`
(`#flask`) and `README.md` for the tier framework this fits into. It's a thin adapter, not a
policy engine: a `before_request` hook that reads groups from wherever the app's tier puts
them, shapes an OPA `input` document, calls the app's local OPA sidecar, and enforces the
`allow`/`deny` answer. The actual rules live as Rego in
[c3g-opa-policies](https://github.com/c3g/c3g-opa-policies), never here and never in the
consuming app.

**Status: working and verified**, unlike this stack's other in-progress libraries
(`c3g-oidc`, `c3g.shiny.authz`). Nothing about this library is security-sensitive the way
Bearer-token validation is — it's an HTTP client and a Flask hook — so there was no reason to
ship it as a stub. `tests/test_integration_opa_server.py` runs it against a real
`opa run --server` loaded with an example policy written for the default input shape, and
asserts its allow/deny outcomes end to end (12 cases).

**This repo is public; `c3g-opa-policies` is private.** Never copy a real app's policy,
`data.json`, or real COmanage group names into this repo (tests, fixtures, or docs) — use the
generic `example-*` groups in `tests/fixtures/example_app/`.

## Repo layout

```
c3g_flask_opa/
  extension.py    # FlaskOPA -- the before_request hook, exempt() decorator
  groups.py       # groups_header_from_request() (Tier 3a), groups_header_from_g() (Tier 3b)
  opa_client.py   # OPAClient -- low-level, fail-closed HTTP call to OPA's data API
tests/
  test_extension.py                    # FlaskOPA behaviour, mocked OPAClient
  test_groups.py                       # the two built-in groups sources
  test_opa_client.py                   # OPAClient's fail-closed HTTP behaviour, mocked
  test_integration_opa_server.py       # real opa run --server + an example policy, see below
  fixtures/example_app/                # made-up example policy, generic group names
```

## Design notes

- **Groups are a comma-separated string, not a pre-split list**, all the way from the two
  built-in `groups_*` sources through to the default `input_builder`. This matches
  the `groups_header` field C3G's policies read, which splits it itself
  (`split(input.groups_header, ",")`) — a policy is free to parse it however it wants; this
  library doesn't impose a list shape on the Rego side. Don't "helpfully" pre-split it into a
  list in a future change; that would silently break every existing policy's `groups_header`
  parsing.
- **Fail closed everywhere.** `OPAClient.allow()` treats any network error, timeout, non-2xx
  response, or malformed/missing `result` field as `False` — never raises, never returns a
  "maybe". `FlaskOPA._enforce()` in turn `abort(403)`s on any non-`True` result. An OPA outage
  should block requests, not silently disable authorization. If you're tempted to add a
  fallback ("allow if OPA is unreachable, log a warning") — don't; that's the one behavior
  change this design deliberately forecloses.
- **The `exempt()` pattern matches Flask-WTF's `CSRFProtect.exempt`**: it records the view
  *function object*, then checks `current_app.view_functions.get(request.endpoint)` against
  that set on each request — not the endpoint *name* — so it keeps working regardless of
  blueprint prefixes or a custom `endpoint=`.
- **`input_builder` is one-argument (`groups_header -> dict`), not zero-argument.** Its only
  job is shaping the OPA input; anything else it needs (method, path, whatever) it reads from
  Flask's `request` directly, same as the default builder does. Don't widen the signature to
  take `request` explicitly — that just duplicates what's already globally available inside a
  Flask request context.

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[test]"
.venv/bin/pytest -v
```

`test_integration_opa_server.py` needs the `opa` CLI on `PATH` (`brew install
opa`/see [openpolicyagent.org](https://www.openpolicyagent.org)) — it's skipped, not failed,
if `opa` isn't found. It spins up a real `opa run --server` on a free local port, loaded from
`tests/fixtures/example_app/`, and tears it down after the module's tests finish.

If the default `input_builder`'s shape ever changes, update `tests/fixtures/example_app/authz.rego`
and this test's cases to match — see `tests/fixtures/example_app/README.md`.

(No CI workflow yet — see repo TODOs / issues. Licensed GPL-3.0, matching `project_tracking`,
`project_tracking_cli`, `c3g-oidc`, and `c3g.shiny.authz` — see `LICENSE`.)
