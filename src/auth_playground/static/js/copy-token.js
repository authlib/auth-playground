/**
 * Copy token to clipboard functionality
 */
document.addEventListener('DOMContentLoaded', () => {
    const copyButtons = document.querySelectorAll('.copy-token-btn');

    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            const inputField = button.previousElementSibling;
            const token = inputField.value;

            navigator.clipboard.writeText(token).then(() => {
                // Store original button text
                const originalText = button.textContent;

                // Show success feedback
                button.textContent = 'Copied!';
                button.setAttribute('aria-busy', 'false');

                // Reset button text after 2 seconds
                setTimeout(() => {
                    button.textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy token:', err);
                button.textContent = 'Failed';

                setTimeout(() => {
                    button.textContent = 'Copy';
                }, 2000);
            });
        });
    });
});
