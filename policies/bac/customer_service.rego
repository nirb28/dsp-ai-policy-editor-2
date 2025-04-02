package dspai_policy

# Default deny all access
default allow := false

# Input schema validation
valid_input {
    input.user
    input.action
    input.resource
    input.usecase == "customer_service"
    input.resource.type == "llm_model"
}

# Define allowed models for customer service
allowed_models := ["gpt-4", "claude-2", "llama-2-70b"]

# Define roles and their permissions
roles := {
    "llm_admin": ["create", "read", "update", "delete", "deploy", "train", "infer"],
    "data_scientist": ["read", "train", "infer"],
    "ml_engineer": ["read", "deploy", "infer"],
    "business_user": ["infer"]
}

# Check if model is allowed for customer service
model_allowed_for_usecase {
    some i
    allowed_models[i] == input.resource.model_id
}

# Check if user has required role
has_role {
    some role
    role == input.user.role
    roles[role]
}

# Check if action is allowed for role
action_allowed_for_role {
    some i
    role := input.user.role
    action := input.action
    roles[role][i] == action
}

# Main allow rule
allow {
    # Validate input
    valid_input
    
    # Basic authorization checks
    has_role
    action_allowed_for_role
    
    # Model-specific checks
    model_allowed_for_usecase
    
    # Additional checks based on action type
    action_specific_checks[input.action]
}

# Action specific validation rules
action_specific_checks := {
    "train": valid_train,
    "infer": valid_infer,
    "deploy": valid_deploy
}

# Training validation
valid_train {
    # Must have approved training data
    input.resource.training_data.approved == true
    
    # Must have risk assessment
    input.resource.risk_assessment.completed == true
    input.resource.risk_assessment.approved == true
    
    # Must have MRM review for training
    input.resource.mrm_review.completed == true
    input.resource.mrm_review.approved == true
}

# Inference validation
valid_infer {
    # Model must be in approved state
    input.resource.status == "approved"
    
    # Must have active monitoring
    input.resource.monitoring.active == true
}

# Deployment validation
valid_deploy {
    # Must have all required approvals
    input.resource.approvals.security == true
    input.resource.approvals.compliance == true
    input.resource.approvals.mrm == true
    
    # Must have deployment plan
    input.resource.deployment_plan.exists == true
    input.resource.deployment_plan.approved == true
}
