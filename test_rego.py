import json
import subprocess
import sys

def run_opa_test(test_case):
    # Write input to a temporary file
    with open('test_data/current_test.json', 'w') as f:
        json.dump({"input": test_case["input"]}, f, indent=2)
    
    # Run OPA evaluation
    cmd = [
        '.\\opa.exe', 'eval',
        '--format', 'json',
        '--data', 'policies/model_management.rego',
        '--input', 'test_data/current_test.json',
        'data.model_management'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Parse the result
    try:
        result_json = json.loads(result.stdout)
        if 'result' in result_json and result_json['result']:
            policy_result = result_json['result'][0]['expressions'][0]['value']
            # Extract only the relevant fields
            return {
                'allow': policy_result.get('allow', False),
                'deny': policy_result.get('deny', [])
            }
        else:
            return {"error": "No result found in OPA output"}
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        return {"error": f"Failed to parse OPA output: {str(e)}"}

def main():
    # Load test cases
    with open('test_data/test_cases.json', 'r') as f:
        test_cases = json.load(f)
    
    # Run each test case
    for test_case in test_cases:
        print(f"\nTesting: {test_case['name']}")
        print("Input:", json.dumps(test_case['input'], indent=2))
        
        result = run_opa_test(test_case)
        print("Result:", json.dumps(result, indent=2))
        print("-" * 80)

if __name__ == '__main__':
    main()
