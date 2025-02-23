package bac_model

# Declare version
version = 1

# Default deny all access
default allow := false

# Input schema validation
valid_input if {
    input.user
    input.action
    input.resource
    input.usecase
    input.resource.type == "llm_model"
}

# Define allowed models per usecase
allowed_models := {
    "customer_service": ["gpt-4", "claude-2", "llama-2-70b"],
    "fraud_detection": ["gpt-4", "claude-2"],
    "document_analysis": ["gpt-4", "claude-2", "palm-2"],
    "trading_analysis": ["claude-2"]
}

# Define required security levels per usecase
required_security_level := {
    "customer_service": 2,
    "fraud_detection": 3,
    "document_analysis": 2,
    "trading_analysis": 3
}

# Define roles and their permissions
roles := {
    "llm_admin": ["create", "read", "update", "delete", "deploy", "train", "infer"],
    "data_scientist": ["read", "train", "infer"],
    "ml_engineer": ["read", "deploy", "infer"],
    "business_user": ["infer"]
}

# Check if model is allowed for usecase
model_allowed_for_usecase if {
    some model, usecase
    model == input.resource.model_id
    usecase == input.usecase
    model in allowed_models[usecase]
}

# Check if user has required security clearance
has_security_clearance if {
    some usecase
    usecase == input.usecase
    input.user.security_level >= required_security_level[usecase]
}

# Check if user has required role
has_role if {
    some role
    role == input.user.role
    roles[role]
}

# Check if action is allowed for role
action_allowed_for_role if {
    some role, action
    role == input.user.role
    action == input.action
    action in roles[role]
}

# Main allow rule
allow if {
    # Validate input
    valid_input
    
    # Basic authorization checks
    has_role
    action_allowed_for_role
    has_security_clearance
    
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
valid_train if {
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
valid_infer if {
    # Model must be in approved state
    input.resource.status == "approved"
    
    # Must have active monitoring
    input.resource.monitoring.active == true
}

# Deployment validation
valid_deploy if {
    # Must have all required approvals
    input.resource.approvals.security == true
    input.resource.approvals.compliance == true
    input.resource.approvals.mrm == true
    
    # Must have deployment plan
    input.resource.deployment_plan.exists == true
    input.resource.deployment_plan.approved == true
}