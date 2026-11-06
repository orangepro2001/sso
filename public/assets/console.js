/*
 * The console's few behaviours, without a framework: every page works without
 * this file (forms post, links navigate); it only removes steps.
 */
(function () {
    'use strict';

    /* Theme: auto → light → dark → auto (docs/design-system.md). */
    var themeButton = document.querySelector('[data-theme-toggle]');
    if (themeButton) {
        var order = ['auto', 'light', 'dark'];
        var names = { auto: '테마: 시스템', light: '테마: 밝게', dark: '테마: 어둡게' };
        var current = function () {
            try { return localStorage.getItem('wr-theme') || 'auto'; } catch (e) { return 'auto'; }
        };
        var paint = function (theme) {
            themeButton.dataset.mode = theme;
            themeButton.title = names[theme];
            themeButton.setAttribute('aria-label', names[theme]);
        };
        paint(current());
        themeButton.addEventListener('click', function () {
            var next = order[(order.indexOf(current()) + 1) % order.length];
            try {
                if (next === 'auto') localStorage.removeItem('wr-theme'); else localStorage.setItem('wr-theme', next);
            } catch (e) {}
            if (next === 'auto') delete document.documentElement.dataset.theme;
            else document.documentElement.dataset.theme = next;
            paint(next);
        });
    }

    /* Whole table rows are links; inner links, buttons and forms keep their own click. */
    document.addEventListener('click', function (event) {
        var row = event.target.closest('tr[data-href]');
        if (!row || event.target.closest('a, button, input, select, textarea, label, form')) return;
        if (event.metaKey || event.ctrlKey) { window.open(row.dataset.href, '_blank'); return; }
        window.location.href = row.dataset.href;
    });

    /* Copy buttons: data-copy="#id" copies that element's text. */
    document.addEventListener('click', function (event) {
        var button = event.target.closest('[data-copy]');
        if (!button) return;
        var target = document.querySelector(button.dataset.copy);
        if (!target) return;
        var text = target.textContent.trim();
        var done = function () {
            var before = button.textContent;
            button.textContent = '복사됨';
            setTimeout(function () { button.textContent = before; }, 1600);
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(done);
        } else {
            var range = document.createRange();
            range.selectNodeContents(target);
            var selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            try { document.execCommand('copy'); done(); } catch (e) {}
        }
    });

    /* Forms that need a second thought: data-confirm="message". */
    document.addEventListener('submit', function (event) {
        var form = event.target;
        if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) event.preventDefault();
    }, true);

    /* Type-to-confirm: the submit button wakes up only when the input matches. */
    document.querySelectorAll('[data-match]').forEach(function (input) {
        var button = input.form && input.form.querySelector('button[type=submit]');
        if (!button) return;
        var sync = function () { button.disabled = input.value.trim() !== input.dataset.match; };
        input.addEventListener('input', sync);
        sync();
    });

    /* Show / hide a password field. */
    document.addEventListener('click', function (event) {
        var button = event.target.closest('[data-reveal]');
        if (!button) return;
        var input = document.querySelector(button.dataset.reveal);
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        button.textContent = input.type === 'password' ? '보기' : '숨기기';
    });

    /* Dialogs: data-open="id" opens, [data-close] closes, data-open-now opens on load. */
    document.addEventListener('click', function (event) {
        var opener = event.target.closest('[data-open]');
        if (opener) {
            var dialog = document.getElementById(opener.dataset.open);
            if (dialog && dialog.showModal) {
                dialog.showModal();
                var first = dialog.querySelector('input:not([type=hidden])');
                if (first) first.focus();
            }
        }
        if (event.target.closest('[data-close]')) {
            var parent = event.target.closest('dialog');
            if (parent) parent.close();
        }
    });
    document.querySelectorAll('dialog[data-open-now]').forEach(function (dialog) {
        if (dialog.showModal) dialog.showModal();
    });

    /* Filters that apply as soon as they change (inline handlers are blocked by the CSP). */
    document.addEventListener('change', function (event) {
        if (event.target.matches('[data-autosubmit]') && event.target.form) event.target.form.submit();
    });

    /* "/" jumps to the search box, as on most list pages people already know. */
    document.addEventListener('keydown', function (event) {
        if (event.key !== '/' || event.target.closest('input, textarea, select, [contenteditable]')) return;
        var search = document.querySelector('[data-search]');
        if (search) { event.preventDefault(); search.focus(); search.select(); }
    });

    /*
     * Avatar upload. The service has no image library (and should not need one):
     * the browser crops the picture to a centred square, scales it to 512 px and
     * re-encodes it, so a 6 MB phone photo arrives as ~60 KB and always fits.
     */
    var SIDE = 512;
    var LIMIT = 1000 * 1024;

    function encode(canvas, quality) {
        return new Promise(function (resolve) {
            canvas.toBlob(function (blob) {
                if (blob && blob.type === 'image/webp') return resolve(blob);
                canvas.toBlob(resolve, 'image/jpeg', quality);
            }, 'image/webp', quality);
        });
    }

    function shrink(file) {
        return new Promise(function (resolve, reject) {
            var url = URL.createObjectURL(file);
            var image = new Image();
            image.onload = function () {
                var side = Math.min(image.naturalWidth, image.naturalHeight);
                var out = Math.min(SIDE, side);
                var canvas = document.createElement('canvas');
                canvas.width = out;
                canvas.height = out;
                var context = canvas.getContext('2d');
                context.imageSmoothingQuality = 'high';
                context.drawImage(
                    image,
                    (image.naturalWidth - side) / 2, (image.naturalHeight - side) / 2, side, side,
                    0, 0, out, out
                );
                URL.revokeObjectURL(url);

                var attempt = function (quality) {
                    encode(canvas, quality).then(function (blob) {
                        if (!blob) return reject(new Error('encode'));
                        if (blob.size > LIMIT && quality > 0.5) return attempt(quality - 0.15);
                        var ext = blob.type === 'image/webp' ? 'webp' : 'jpg';
                        resolve(new File([blob], 'avatar.' + ext, { type: blob.type }));
                    });
                };
                attempt(0.9);
            };
            image.onerror = function () { URL.revokeObjectURL(url); reject(new Error('decode')); };
            image.src = url;
        });
    }

    document.querySelectorAll('[data-avatar-upload]').forEach(function (form) {
        var zone = form.querySelector('.dropzone');
        var input = form.querySelector('input[type=file]');
        var preview = form.querySelector('[data-avatar-preview]');
        var status = form.querySelector('[data-avatar-status]');
        if (!zone || !input) return;

        var say = function (text, bad) {
            if (!status) return;
            status.textContent = text;
            status.className = bad ? 'field-error' : 'hint';
        };

        var take = function (file) {
            if (!file) return;
            if (!/^image\//.test(file.type)) { say('이미지 파일을 골라 주세요.', true); return; }
            zone.classList.add('is-busy');
            say('사진을 줄이는 중…');
            shrink(file).then(function (small) {
                var transfer = new DataTransfer();
                transfer.items.add(small);
                input.files = transfer.files;
                if (preview) {
                    var src = URL.createObjectURL(small);
                    if (preview.tagName === 'IMG') { preview.src = src; }
                    else {
                        var img = document.createElement('img');
                        img.className = preview.className;
                        img.alt = '';
                        img.src = src;
                        img.setAttribute('data-avatar-preview', '');
                        preview.replaceWith(img);
                        preview = img;
                    }
                }
                say('올리는 중…');
                form.submit();
            }).catch(function () {
                zone.classList.remove('is-busy');
                say('이 사진을 읽지 못했습니다. JPG나 PNG로 다시 시도해 주세요.', true);
            });
        };

        input.addEventListener('change', function () { take(input.files[0]); });
        ['dragenter', 'dragover'].forEach(function (name) {
            zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.add('is-over'); });
        });
        ['dragleave', 'drop'].forEach(function (name) {
            zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.remove('is-over'); });
        });
        zone.addEventListener('drop', function (event) {
            take(event.dataTransfer.files && event.dataTransfer.files[0]);
        });
        // Pasting a screenshot works too.
        form.addEventListener('paste', function (event) {
            var item = Array.prototype.find.call(event.clipboardData.items || [], function (i) { return i.kind === 'file'; });
            if (item) take(item.getAsFile());
        });
    });
})();
