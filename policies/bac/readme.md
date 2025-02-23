# Bank of America LLM Policy

## Overview
This policy governs the usage of Large Language Models (LLMs) within Bank of America's infrastructure. It implements role-based access control, use case-specific model restrictions, and security level requirements using Open Policy Agent (OPA) with Rego v1.0.

## Policy Components

### Use Cases
The policy supports different use cases with specific model allowlists:
- **Customer Service**: `gpt-4`, `claude-2`, `llama-2-70b`
- **Fraud Detection**: `gpt-4`, `claude-2`
- **Document Analysis**: `gpt-4`, `claude-2`, `palm-2`
- **Trading Analysis**: `claude-2`

### Security Levels
Each use case requires a minimum security clearance:
| Use Case | Security Level |
|----------|---------------|
| Customer Service | 2 |
| Fraud Detection | 3 |
| Document Analysis | 2 |
| Trading Analysis | 3 |

### Roles and Permissions
| Role | Permissions |
|------|------------|
| `llm_admin` | create, read, update, delete, deploy, train, infer |
| `data_scientist` | read, train, infer |
| `ml_engineer` | read, deploy, infer |
| `business_user` | infer |

## Operations

### Training Requirements
- Approved training data
- Completed and approved risk assessment
- Completed and approved MRM review

### Deployment Requirements
- Security approval
- Compliance approval
- MRM approval
- Approved deployment plan

### Inference Requirements
- Model must be in approved state
- Active monitoring must be enabled

## Usage

### Input Format
```json
{
    "user": {
        "role": "data_scientist",
        "security_level": 3
    },
    "action": "train",
    "usecase": "fraud_detection",
    "resource": {
        "type": "llm_model",
        "model_id": "gpt-4",
        ...
    }
}
```

### Running Tests
```bash
opa test policies/bac/bac-model.rego policies/bac/bac-model_test.rego -v
```

## Policy Files
- `bac-model.rego`: Main policy implementation
- `bac-model_test.rego`: Test cases covering various scenarios

## Compliance
This policy ensures:
- Only approved models are used for specific use cases
- Users have appropriate security clearance
- Required approvals are obtained before operations
- Model Risk Management (MRM) oversight
- Continuous monitoring during inference
