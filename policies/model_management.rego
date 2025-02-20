package model_management

import future.keywords.in

# Default to deny
default allow = false

# Input schema validation
valid_input {
    input.user
    input.action
    input.resource
    input.resource.type == "model"
}

# Define roles and their permissions
roles = {
    "admin": ["create", "read", "update", "delete", "deploy", "train"],
    "data_scientist": ["create", "read", "update", "train"],
    "ml_engineer": ["read", "deploy"],
    "viewer": ["read"]
}

# Check if user has required role
has_role(user, required_role) {
    user.role == required_role
}

# Check if action is allowed for role
action_allowed_for_role(role, action) {
    roles[role][_] == action
}

# Model state transitions
valid_state_transition(from, to) {
    from == "draft"
    to == "in_review"
} {
    from == "in_review"
    to == "approved"
} {
    from == "in_review"
    to == "rejected"
} {
    from == "approved"
    to == "deployed"
} {
    from == "deployed"
    to == "archived"
}

# Main allow rule
allow {
    # Validate input
    valid_input
    
    # Extract variables for readability
    user := input.user
    action := input.action
    resource := input.resource
    
    # Check if user has a valid role
    user.role
    
    # Check if action is allowed for user's role
    action_allowed_for_role(user.role, action)
    
    # Additional checks based on action type
    action_specific_checks[action]
}

# Action specific validation rules
action_specific_checks = {
    # Create model
    "create": valid_create,
    
    # Update model
    "update": valid_update,
    
    # Deploy model
    "deploy": valid_deploy,
    
    # Train model
    "train": valid_train,
    
    # Read model
    "read": valid_read,
    
    # Delete model
    "delete": valid_delete
}

# Validation rules for each action
valid_create {
    input.resource.metadata.name
    input.resource.metadata.version
    input.resource.metadata.framework
}

valid_update {
    # Must provide state transition if changing state
    not input.resource.state_transition
} {
    valid_state_transition(input.resource.current_state, input.resource.state_transition)
}

# List of valid environments
valid_environments = ["dev", "staging", "prod"]

valid_deploy {
    # Only approved models can be deployed
    input.resource.current_state == "approved"
    
    # Must specify deployment environment
    input.resource.deployment.environment
    
    # Environment must be valid
    some env in valid_environments
    input.resource.deployment.environment == env
    
    # Production deployments require additional approvals
    input.resource.deployment.environment != "prod"
} {
    # Additional rule for production deployments
    input.resource.deployment.environment == "prod"
    input.resource.approvals.technical_review == true
    input.resource.approvals.business_review == true
}

valid_train {
    # Must specify training parameters
    input.resource.training.dataset_version
    input.resource.training.hyperparameters
    
    # If using GPU, must specify requirements
    not input.resource.training.use_gpu
} {
    input.resource.training.use_gpu == true
    input.resource.training.gpu_requirements
}

valid_read {
    true  # No additional checks for read
}

valid_delete {
    # Can only delete models in draft or rejected state
    input.resource.current_state == "draft"
} {
    input.resource.current_state == "rejected"
}

# Example violation messages
deny[msg] {
    not valid_input
    msg := "Invalid input structure"
}

deny[msg] {
    not input.user.role
    msg := "User role not specified"
}

deny[msg] {
    not action_allowed_for_role(input.user.role, input.action)
    msg := sprintf("User with role '%v' is not allowed to perform action '%v'", [input.user.role, input.action])
}
