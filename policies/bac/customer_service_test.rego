package dspai_policy_test

import data.dspai_policy

# Test valid customer service access for data scientist
test_allow_data_scientist_infer {
    # Mock input
    input := {
        "user": {
            "role": "data_scientist"
        },
        "action": "infer",
        "usecase": "customer_service",
        "resource": {
            "type": "llm_model",
            "model_id": "gpt-4",
            "status": "approved",
            "monitoring": {
                "active": true
            }
        }
    }
    
    # Verify policy allows access
    dspai_policy.allow with input as input
}

# Test valid customer service access for llm_admin
test_allow_llm_admin_train {
    # Mock input
    input := {
        "user": {
            "role": "llm_admin"
        },
        "action": "train",
        "usecase": "customer_service",
        "resource": {
            "type": "llm_model",
            "model_id": "claude-2",
            "training_data": {
                "approved": true
            },
            "risk_assessment": {
                "completed": true,
                "approved": true
            },
            "mrm_review": {
                "completed": true,
                "approved": true
            }
        }
    }
    
    # Verify policy allows access
    dspai_policy.allow with input as input
}

# Test valid customer service access for ml_engineer
test_allow_ml_engineer_deploy {
    # Mock input
    input := {
        "user": {
            "role": "ml_engineer"
        },
        "action": "deploy",
        "usecase": "customer_service",
        "resource": {
            "type": "llm_model",
            "model_id": "llama-2-70b",
            "approvals": {
                "security": true,
                "compliance": true,
                "mrm": true
            },
            "deployment_plan": {
                "exists": true,
                "approved": true
            }
        }
    }
    
    # Verify policy allows access
    dspai_policy.allow with input as input
}

# Test business user can only infer
test_deny_business_user_train {
    # Mock input
    input := {
        "user": {
            "role": "business_user"
        },
        "action": "train",
        "usecase": "customer_service",
        "resource": {
            "type": "llm_model",
            "model_id": "gpt-4",
            "training_data": {
                "approved": true
            },
            "risk_assessment": {
                "completed": true,
                "approved": true
            },
            "mrm_review": {
                "completed": true,
                "approved": true
            }
        }
    }
    
    # Verify policy denies access
    not dspai_policy.allow with input as input
}

# Test disallowed model for customer service
test_deny_disallowed_model {
    # Mock input with a model not in the allowed list
    input := {
        "user": {
            "role": "data_scientist"
        },
        "action": "infer",
        "usecase": "customer_service",
        "resource": {
            "type": "llm_model",
            "model_id": "llama-3", # Not in allowed models
            "status": "approved",
            "monitoring": {
                "active": true
            }
        }
    }
    
    # Verify policy denies access
    not dspai_policy.allow with input as input
}

# Test missing required approvals for deployment
test_deny_missing_approvals {
    # Mock input with missing security approval
    input := {
        "user": {
            "role": "ml_engineer"
        },
        "action": "deploy",
        "usecase": "customer_service",
        "resource": {
            "type": "llm_model",
            "model_id": "gpt-4",
            "approvals": {
                "security": false, # Missing security approval
                "compliance": true,
                "mrm": true
            },
            "deployment_plan": {
                "exists": true,
                "approved": true
            }
        }
    }
    
    # Verify policy denies access
    not dspai_policy.allow with input as input
}

# Test invalid usecase
test_deny_invalid_usecase {
    # Mock input with wrong usecase
    input := {
        "user": {
            "role": "data_scientist"
        },
        "action": "infer",
        "usecase": "fraud_detection", # Not customer_service
        "resource": {
            "type": "llm_model",
            "model_id": "gpt-4",
            "status": "approved",
            "monitoring": {
                "active": true
            }
        }
    }
    
    # Verify policy denies access
    not dspai_policy.allow with input as input
}

# Test missing monitoring for inference
test_deny_missing_monitoring {
    # Mock input with inactive monitoring
    input := {
        "user": {
            "role": "business_user"
        },
        "action": "infer",
        "usecase": "customer_service",
        "resource": {
            "type": "llm_model",
            "model_id": "claude-2",
            "status": "approved",
            "monitoring": {
                "active": false # Monitoring not active
            }
        }
    }
    
    # Verify policy denies access
    not dspai_policy.allow with input as input
}
