document.addEventListener('DOMContentLoaded', () => {
    const copyButtons = document.querySelectorAll('.copy-token-btn');

    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            const inputField = button.previousElementSibling;
            const token = inputField.value;

            navigator.clipboard.writeText(token).then(() => {
                const originalText = button.textContent;

                button.textContent = 'Copied!';
                button.setAttribute('aria-busy', 'false');

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
