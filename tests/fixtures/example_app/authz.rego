package example_app.authz

# Input shape expected from c3g-flask-opa's default input_builder:
# {
#   "method": "GET",
#   "path": "/items/ITEM-1/upload_file",
#   "groups_header": "example-admins,example-editors"
# }
#
# Group membership per tier lives in data.groups (see data.json), not here, so
# who's in which tier can change without touching this file.

default allow := false

read_methods := {"GET", "HEAD", "OPTIONS"}

# Groups forwarded by the trusted upstream proxy, as a set.
forwarded_groups contains group if {
	some part in split(input.groups_header, ",")
	group := trim_space(part)
	group != ""
}

# Exactly one tier applies per request, in priority order:
# admin > edit > upload > read > write.
required_tier := "admin" if {
	startswith(input.path, "/admin/")
} else := "edit" if {
	startswith(input.path, "/edit/")
} else := "upload" if {
	contains(input.path, "/upload_")
} else := "read" if {
	input.method in read_methods
} else := "write"

# An empty group list for a tier means that tier isn't configured yet — allow
# through unrestricted, so tiers can be rolled out one at a time.
allow if {
	count(data.groups[required_tier]) == 0
}

allow if {
	some group in data.groups[required_tier]
	group in forwarded_groups
}
