// Listen on the document, so that the buttons htmx swaps in work too.
document.addEventListener('click', event => {
    const button = event.target.closest('.copy-token-btn');
    if (!button) {
        return;
    }

    const value = button.previousElementSibling.value;
    // Read the label once: a second click would read "Copied!".
    const originalText = button.dataset.label ??= button.textContent;

    navigator.clipboard.writeText(value).then(() => {
        button.textContent = 'Copied!';
        button.setAttribute('aria-busy', 'false');
    }).catch(err => {
        console.error('Failed to copy:', err);
        button.textContent = 'Failed';
    }).finally(() => {
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    });
});
