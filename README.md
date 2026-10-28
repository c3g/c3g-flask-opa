# c3g-flask-opa

The Flask library every **Tier 3** C3G app adopts, whether it's 3a (oauth2-proxy stays in
front) or 3b (in-app OIDC via `c3g-oidc`) — see
[web-app-template](https://github.com/c3g/web-app-template)'s `for-app-developers.md`
(`#flask`) and `README.md` for where this fits among the authentication/authorization tiers.

A `before_request` hook, not a policy engine: it reads your app's groups from wherever your
tier puts them, shapes them into whatever input your app's OPA policy expects, calls your
app's local OPA sidecar, and enforces the answer. The actual authorization rules never live
here or in your app — they live as Rego in
[c3g-opa-policies](https://github.com/c3g/c3g-opa-policies), one directory per app.

**Status: working, and verified against a real OPA server.** Its default input shape
(`{method, path, groups_header}`) is the one C3G's policies in `c3g-opa-policies` are written
for, and this repo's test suite runs the library against a real `opa run --server` instance
loaded with an example policy of that shape, asserting its allow/deny outcomes end to end. See
[CLAUDE.md](CLAUDE.md) for how to run that yourself.

**Pre-1.0:** the API may change between minor versions until a first app has adopted it.

## Install

```bash
pip install c3g-flask-opa
```

## Usage

```python
from flask import Flask, request
from c3g_flask_opa import FlaskOPA, groups_header_from_request

app = Flask(__name__)

opa = FlaskOPA(
    app,
    groups_source=groups_header_from_request(),  # Tier 3a: reads X-Forwarded-Groups
    policy_path="project_tracking/authz/allow",   # matches the Rego package + rule name
)

@app.route("/healthz")
@opa.exempt
def healthz():
    return "ok"
```

That's the whole integration for an app whose OPA input shape is `{method, path,
groups_header}` (the default). If your app's policy expects something else, pass your own
`input_builder`:

```python
opa = FlaskOPA(
    app,
    groups_source=groups_header_from_request(),
    input_builder=lambda groups_header: {"action": request.view_args.get("action"), "groups": groups_header},
    policy_path="my_app/authz/allow",
)
```

For a Tier 3b app (in-app OIDC, no oauth2-proxy), swap the groups source for the one that
reads `flask.g` after `c3g-oidc` has validated the Bearer token:

```python
from c3g_flask_opa import groups_header_from_g

opa = FlaskOPA(app, groups_source=groups_header_from_g(), policy_path="project_tracking/authz/allow")
```

`FlaskOPA` reads the OPA sidecar's URL from the `C3G_OPA_URL` environment variable by default,
falling back to `http://127.0.0.1:8181` — OPA runs in the app's own podman pod, per
`web-app-template`'s deployment docs — or pass `opa_url=` explicitly.

**Fails closed.** Any error reaching OPA (network failure, timeout, non-2xx response,
malformed body) is treated as a deny, not an allow — an OPA outage should block requests, not
silently disable authorization.
