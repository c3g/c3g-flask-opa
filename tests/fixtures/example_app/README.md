`authz.rego` and `data.json` here are a made-up example policy, written for the library's
default input shape (`{method, path, groups_header}`) — the same shape real policies in
[c3g-opa-policies](https://github.com/c3g/c3g-opa-policies) use. They give
`test_integration_opa_server.py` a real policy to run `c3g-flask-opa` against end to end.

Group names and routes are deliberately generic: this repo is public, and real group names
and policies stay in the private `c3g-opa-policies` repo. Don't copy a real app's policy or
`data.json` in here.

If the default `input_builder`'s shape ever changes, update `authz.rego` and the integration
test's cases to match.
