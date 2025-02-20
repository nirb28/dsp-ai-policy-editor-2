package model_management

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
    from == "draft" ; to == "in_review"
} {
    from == "in_review" ; to == "approved"
} {
    from == "in_review" ; to == "rejected"
} {
    from == "approved" ; to == "deployed"
} {
    from == "deployed" ; to == "archived"
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
action_specific_checks := {
    # Create model
    "create": {
        input.resource.metadata.name
        input.resource.metadata.version
        input.resource.metadata.framework
    },
    
    # Update model
    "update": {
        # Must provide state transition if changing state
        not input.resource.state_transition
        or
        valid_state_transition(input.resource.current_state, input.resource.state_transition)
    },
    
    # Deploy model
    "deploy": {
        # Only approved models can be deployed
        input.resource.current_state == "approved"
        
        # Must specify deployment environment
        input.resource.deployment.environment
        
        # Environment must be valid
        input.resource.deployment.environment in ["dev", "staging", "prod"]
        
        # Production deployments require additional approvals
        not input.resource.deployment.environment == "prod"
        or
        input.resource.approvals.technical_review
        input.resource.approvals.business_review
    },
    
    # Train model
    "train": {
        # Must specify training parameters
        input.resource.training.dataset_version
        input.resource.training.hyperparameters
        
        # If using GPU, must specify requirements
        not input.resource.training.use_gpu
        or
        input.resource.training.gpu_requirements
    },
    
    # Read model
    "read": {
        true  # No additional checks for read
    },
    
    # Delete model
    "delete": {
        # Can only delete models in draft or rejected state
        input.resource.current_state in ["draft", "rejected"]
    }
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
