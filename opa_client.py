import requests
import json

def evaluate_policy(policy_content, input_data):
    """
    Evaluate a Rego policy using OPA Playground API
    """
    endpoint = "https://play.openpolicyagent.org/v1/data"
    
    # Prepare payload to match working structure
    payload = {
        "rego_modules": {
            "policy.rego": policy_content
        },
        "input": input_data,
        "data": {},
        "strict": True,
        "rego_version": 1
    }
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        result = response.json()
        print("Debug - Response:", json.dumps(result, indent=2))  # Debug line
        return result
        
    except requests.RequestException as e:
        print("Debug - Error:", str(e))  # Debug line
        return {"error": f"API request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON response from OPA Playground"}

if __name__ == "__main__":
    # Test policy (matching the working example)
    policy = '''package play
default hello := false
hello if input.message == "world"'''
    
    input_data = {"message": "world"}
    
    result = evaluate_policy(policy, input_data)
    print("Evaluation Result:", json.dumps(result, indent=2))
