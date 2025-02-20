import json
import os
from opa_client import evaluate_policy

def test_policy(input_file):
    # Read input data
    with open(input_file, 'r') as f:
        input_data = json.load(f)
    
    # Read policy content
    with open('policies/model_management.rego', 'r') as f:
        policy_content = f.read()
    
    print(f"\nTesting input from {os.path.basename(input_file)}:")
    print("Input:", json.dumps(input_data, indent=2))
    
    # Evaluate policy directly using opa_client
    result = evaluate_policy(policy_content, input_data)
    print("Result:", json.dumps(result, indent=2))
    print("-" * 80)

def main():
    test_cases = [
        'test_data/input_create_model.json',
        'test_data/input_deploy_model.json',
        'test_data/input_invalid_action.json'
    ]
    
    for test_case in test_cases:
        test_policy(test_case)

if __name__ == '__main__':
    main()
