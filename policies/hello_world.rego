package model_management

# Rego v1 requires explicit 'contains' for partial set rules
default allow := false

# Input schema validation
valid_input if {
	input.user
	input.action
}

# Rule to allow the user to perform the action on the resource
allow if {
	valid_input
}

deny[msg] if {
	not valid_input
	msg := "Invalid input structure"
}

# Role-based permissions configuration
allowed_actions := {
	"admin": {"create", "read", "update", "delete", "train", "deploy"},
	"data_scientist": {"create", "read", "update", "train", "deploy"},
	"analyst": {"read"},
}

# Actions requiring ownership verification
ownership_required := {"update", "delete", "train", "deploy"}

# Main authorization rule
allow if {
	# Check role-based permission
	input.action in allowed_actions[input.user.role]

	# Check ownership requirement
	not input.action in ownership_required
}

allow if {
	# Check role-based permission
	input.action in allowed_actions[input.user.role]

	# Check ownership requirement
	input.action in ownership_required

	# Verify model ownership
	model := data.models[input.model_id]
	model.owner == input.user.username
}
