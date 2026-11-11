/* Apply the stored theme before first paint (docs/design-system.md). A file, not
   an inline script: the Content-Security-Policy allows scripts from 'self' only. */
(function () {
    try {
        var stored = localStorage.getItem('wr-theme');
        if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
    } catch (e) {}
})();
