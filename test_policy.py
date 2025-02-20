import requests
import json
import os

def test_policy(input_file):
    with open(input_file, 'r') as f:
        input_data = json.load(f)
    
    # Send request to local Flask server
    response = requests.post('http://localhost:5000/evaluate_policy', json={
        'policy_name': 'model_management',
        'input': input_data
    })
    
    print(f"\nTesting input from {os.path.basename(input_file)}:")
    print("Input:", json.dumps(input_data, indent=2))
    print("Result:", json.dumps(response.json(), indent=2))
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
