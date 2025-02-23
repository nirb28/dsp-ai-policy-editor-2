package bac_model_test

import data.bac_model

# Test valid customer service inference
test_allow_customer_service_inference if {
    bac_model.allow with input as {
        "user": {
            "role": "business_user",
            "security_level": 2
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
}

# Test invalid model for usecase
test_deny_invalid_model if {
    not bac_model.allow with input as {
        "user": {
            "role": "business_user",
            "security_level": 2
        },
        "action": "infer",
        "usecase": "trading_analysis",
        "resource": {
            "type": "llm_model",
            "model_id": "llama-2-70b",
            "status": "approved",
            "monitoring": {
                "active": true
            }
        }
    }
}

# Test insufficient security level
test_deny_insufficient_security if {
    not bac_model.allow with input as {
        "user": {
            "role": "business_user",
            "security_level": 2
        },
        "action": "infer",
        "usecase": "trading_analysis",
        "resource": {
            "type": "llm_model",
            "model_id": "claude-2",
            "status": "approved",
            "monitoring": {
                "active": true
            }
        }
    }
}

# Test valid training request
test_allow_training if {
    bac_model.allow with input as {
        "user": {
            "role": "data_scientist",
            "security_level": 3
        },
        "action": "train",
        "usecase": "fraud_detection",
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
}

# Test invalid role for action
test_deny_invalid_role if {
    not bac_model.allow with input as {
        "user": {
            "role": "business_user",
            "security_level": 3
        },
        "action": "train",
        "usecase": "fraud_detection",
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
}

# Test valid deployment request
test_allow_deployment if {
    bac_model.allow with input as {
        "user": {
            "role": "ml_engineer",
            "security_level": 3
        },
        "action": "deploy",
        "usecase": "fraud_detection",
        "resource": {
            "type": "llm_model",
            "model_id": "gpt-4",
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
}

# Test missing required approvals for deployment
test_deny_missing_approvals if {
    not bac_model.allow with input as {
        "user": {
            "role": "ml_engineer",
            "security_level": 3
        },
        "action": "deploy",
        "usecase": "fraud_detection",
        "resource": {
            "type": "llm_model",
            "model_id": "gpt-4",
            "approvals": {
                "security": true,
                "compliance": false,
                "mrm": true
            },
            "deployment_plan": {
                "exists": true,
                "approved": true
            }
        }
    }
}

# Test admin full access
test_allow_admin_access if {
    bac_model.allow with input as {
        "user": {
            "role": "llm_admin",
            "security_level": 3
        },
        "action": "deploy",
        "usecase": "trading_analysis",
        "resource": {
            "type": "llm_model",
            "model_id": "claude-2",
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
}
