let editor, inputEditor;
let currentPolicyId = null;

// Initialize Monaco Editor
require(['vs/editor/editor.main'], function() {
    editor = monaco.editor.create(document.getElementById('editor'), {
        value: '# Write your Rego policy here\npackage example\n\ndefault allow = false\n\nallow {\n    input.user.role == "admin"\n}',
        language: 'ruby', // Using Ruby syntax highlighting for Rego
        theme: 'vs-dark',
        minimap: { enabled: false },
        readOnly: !document.getElementById('saveBtn')  // Read-only if save button doesn't exist (non-MRM user)
    });

    inputEditor = monaco.editor.create(document.getElementById('inputEditor'), {
        value: '{\n    "user": {\n        "role": "admin"\n    }\n}',
        language: 'json',
        theme: 'vs-dark',
        minimap: { enabled: false }
    });

    loadPolicies();
});

// Load policies from the server
async function loadPolicies() {
    try {
        const response = await fetch('/api/policies');
        const policies = await response.json();
        const policyList = document.getElementById('policyList');
        policyList.innerHTML = '';
        
        policies.forEach(policy => {
            const li = document.createElement('li');
            li.className = 'list-group-item policy-item';
            li.textContent = policy.name;
            li.onclick = () => loadPolicy(policy);
            policyList.appendChild(li);
        });
    } catch (error) {
        console.error('Error loading policies:', error);
    }
}

// Load a specific policy into the editor
function loadPolicy(policy) {
    currentPolicyId = policy.id;
    document.getElementById('policyName').value = policy.name;
    editor.setValue(policy.content);
    
    // Update active state in policy list
    document.querySelectorAll('.policy-item').forEach(item => {
        item.classList.remove('active');
        if (item.textContent === policy.name) {
            item.classList.add('active');
        }
    });
}

// Save the current policy
async function savePolicy() {
    const name = document.getElementById('policyName').value;
    const content = editor.getValue();
    
    if (!name) {
        alert('Please enter a policy name');
        return;
    }
    
    try {
        const url = currentPolicyId ? `/api/policies/${currentPolicyId}` : '/api/policies';
        const method = currentPolicyId ? 'PUT' : 'POST';
        
        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, content })
        });
        
        if (response.ok) {
            const policy = await response.json();
            currentPolicyId = policy.id;
            loadPolicies();
        }
    } catch (error) {
        console.error('Error saving policy:', error);
        alert('Error saving policy');
    }
}

// Evaluate the current policy
async function evaluatePolicy() {
    const resultElement = document.getElementById('evaluationResult');
    try {
        // Get the input JSON, handle empty or invalid JSON
        let inputJson = {};
        try {
            const inputText = inputEditor.getValue().trim();
            if (inputText) {
                inputJson = JSON.parse(inputText);
            }
        } catch (e) {
            resultElement.textContent = 'Error: Invalid input JSON';
            resultElement.style.color = 'red';
            return;
        }

        const response = await fetch('/api/evaluate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                policy: editor.getValue(),
                input: inputJson
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.result !== undefined) {
                resultElement.textContent = JSON.stringify(data.result, null, 2);
                resultElement.style.color = 'green';
            } else {
                resultElement.textContent = 'Evaluation completed, but no result returned';
                resultElement.style.color = 'orange';
            }
        } else {
            resultElement.textContent = `Error: ${data.error || 'Unknown error occurred'}`;
            resultElement.style.color = 'red';
        }
    } catch (error) {
        resultElement.textContent = `Error: ${error.message}`;
        resultElement.style.color = 'red';
    }
}

// Generate JWT token for the current policy
async function generateToken() {
    const resultElement = document.getElementById('jwtToken');
    const expiryElement = document.getElementById('tokenExpiry');
    
    try {
        const response = await fetch('/api/generate-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                policy: editor.getValue()
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            resultElement.value = data.token;
            expiryElement.textContent = `Expires: ${new Date(data.expires).toLocaleString()}`;
        } else {
            alert(`Error: ${data.error || 'Failed to generate token'}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// Copy token to clipboard
function copyToken() {
    const tokenInput = document.getElementById('jwtToken');
    tokenInput.select();
    document.execCommand('copy');
    
    // Visual feedback
    const copyBtn = document.getElementById('copyTokenBtn');
    const originalText = copyBtn.textContent;
    copyBtn.textContent = 'Copied!';
    setTimeout(() => {
        copyBtn.textContent = originalText;
    }, 2000);
}

// Event listeners
document.getElementById('newPolicyBtn').onclick = () => {
    currentPolicyId = null;
    document.getElementById('policyName').value = '';
    editor.setValue('# Write your Rego policy here\npackage example\n\ndefault allow = false\n\nallow {\n    input.user.role == "admin"\n}');
    document.querySelectorAll('.policy-item').forEach(item => item.classList.remove('active'));
};

document.getElementById('saveBtn').onclick = savePolicy;
document.getElementById('evaluateBtn').onclick = evaluatePolicy;
document.getElementById('generateTokenBtn').onclick = generateToken;
document.getElementById('copyTokenBtn').onclick = copyToken;
