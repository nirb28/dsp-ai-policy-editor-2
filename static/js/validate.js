document.addEventListener('DOMContentLoaded', function() {
    const validateBtn = document.getElementById('validateBtn');
    const tokenInput = document.getElementById('tokenInput');
    const validationStatus = document.getElementById('validationStatus');
    const tokenDetails = document.getElementById('tokenDetails');
    const issuedAt = document.getElementById('issuedAt');
    const expiresAt = document.getElementById('expiresAt');
    const signatureStatus = document.getElementById('signatureStatus');
    const policyContent = document.getElementById('policyContent');

    validateBtn.addEventListener('click', async function() {
        const token = tokenInput.value.trim();
        if (!token) {
            showError('Please enter a JWT token');
            return;
        }

        try {
            const response = await fetch('/api/validate-token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ token })
            });

            const data = await response.json();

            if (response.ok) {
                // Show success message
                validationStatus.className = 'alert alert-success';
                validationStatus.textContent = 'Token is valid!';
                validationStatus.style.display = 'block';

                // Display token details
                tokenDetails.style.display = 'block';
                issuedAt.textContent = new Date(data.issued_at).toLocaleString();
                expiresAt.textContent = new Date(data.expires_at).toLocaleString();
                signatureStatus.textContent = 'Valid ✓';
                signatureStatus.className = 'text-success';
                policyContent.textContent = data.policy;
            } else {
                showError(data.error || 'Token validation failed');
                tokenDetails.style.display = 'none';
            }
        } catch (error) {
            showError('Failed to validate token: ' + error.message);
            tokenDetails.style.display = 'none';
        }
    });

    function showError(message) {
        validationStatus.className = 'alert alert-danger';
        validationStatus.textContent = message;
        validationStatus.style.display = 'block';
    }
});
