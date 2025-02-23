import json
import os
from opa_client import evaluate_policy

def test_policy(input_file, policy_file='policies/model_management.rego'):
    # Read input data
    with open(input_file, 'r') as f:
        input_data = json.load(f)
    
    # Read policy content
    with open(policy_file, 'r') as f:
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

    test_cases = [
        'test_data/hello_world_input.json'
    ]
    
    for test_case in test_cases:
        test_policy(test_case, 'policies/hello_world.rego')

def direct_policy_evaluation():
    import requests
    import json

    url = "https://play.openpolicyagent.org/v1/data"

    payload = json.dumps({
    "rego_modules": {
        "policy.rego": "package model_management\n\n# Default to deny\ndefault allow := false\n\n# Input schema validation\nvalid_input if {\n\tinput.user\n\tinput.action\n\tinput.resource\n}\n\n# Rule to allow the user to perform the action on the resource\nallow if {\n\tvalid_input\n\tinput.user == \"world\"\n\tinput.action == \"world\"\n\tinput.resource == \"world\"\n}\n"
    },
    "input": {
        "user": "world",
        "action": "world",
        "resource": "world1"
    },
    "data": {},
    "strict": True,
    "rego_version": 1
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    print(response.text)    

if __name__ == '__main__':
    main()
    direct_policy_evaluation()
