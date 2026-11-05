<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', 'SSO') — {{ config('app.name') }}</title>
    <meta name="color-scheme" content="light dark">

    {{-- Apply the stored theme before first paint: a dark preference must not flash
         white, and the same snippet exists in every app (docs/design-system.md). --}}
    <script>
        (function () {
            try {
                var stored = localStorage.getItem('wr-theme');
                if (stored === 'light' || stored === 'dark') {
                    document.documentElement.dataset.theme = stored;
                }
            } catch (e) {}
        })();
    </script>
    <link rel="stylesheet" href="{{ asset('assets/theme.css') }}">
    <link rel="stylesheet" href="{{ asset('assets/app.css') }}">
</head>
<body>
<header class="top">
    <span class="brand">SSO</span>
    <nav>
        @auth('admin')
            <a href="{{ route('admin.dashboard') }}" @class(['active' => request()->routeIs('admin.dashboard')])>Dashboard</a>
            <a href="{{ route('admin.users.index') }}" @class(['active' => request()->routeIs('admin.users.*')])>Users</a>
            <a href="{{ route('admin.invites.index') }}" @class(['active' => request()->routeIs('admin.invites.*')])>Invites</a>
            <a href="{{ route('admin.clients.index') }}" @class(['active' => request()->routeIs('admin.clients.*')])>Clients</a>
            <a href="{{ route('admin.devices.index') }}" @class(['active' => request()->routeIs('admin.devices.*')])>Guest devices</a>
            <a href="{{ route('admin.tokens.index') }}" @class(['active' => request()->routeIs('admin.tokens.*')])>Tokens</a>
            <a href="{{ route('admin.blacklist.index') }}" @class(['active' => request()->routeIs('admin.blacklist.*')])>Blacklist</a>
            <a href="{{ route('admin.audit.index') }}" @class(['active' => request()->routeIs('admin.audit.*')])>Audit</a>
        @endauth
    </nav>
    <span class="spacer"></span>

    {{-- auto → light → dark → auto; the OS preference is the default. --}}
    <button class="theme-toggle" type="button" data-theme-toggle
            title="Theme: auto / light / dark" aria-label="Toggle theme">◐</button>

    @auth('admin')
        <a class="muted small" href="{{ route('admin.account') }}" style="text-decoration:none">
            {{ auth('admin')->user()->email }}
        </a>
        <form method="post" action="{{ route('admin.logout') }}">
            @csrf
            <button class="link" type="submit">Sign out</button>
        </form>
    @endauth
    @auth('web')
        <span class="muted small">{{ auth('web')->user()->username }}</span>
        <form method="post" action="{{ route('logout') }}">
            @csrf
            <button class="link" type="submit">Sign out</button>
        </form>
    @endauth
</header>

<main class="@yield('main-class')">
    @if (session('status'))
        <div class="flash ok">{{ session('status') }}</div>
    @endif
    @if (session('reset_url'))
        <div class="flash key">
            <strong>Reset link — shown once, send it to the user yourself:</strong>
            <div class="mono" style="margin-top:6px;word-break:break-all">{{ session('reset_url') }}</div>
            <div class="small muted" style="margin-top:6px">
                Single use. Issuing another link for the same user makes this one invalid.
            </div>
        </div>
    @endif
    @if (session('generated_password'))
        <div class="flash key">
            <strong>Password set — shown once, copy it now:</strong>
            @foreach (session('generated_password') as $username => $plain)
                <div class="mono" style="margin-top:6px">{{ $username }} &nbsp;→&nbsp; <code>{{ $plain }}</code></div>
            @endforeach
        </div>
    @endif
    @if (session('client_secret'))
        <div class="flash key">
            <strong>Client secret (shown once):</strong><br>
            <code>{{ session('client_secret') }}</code>
        </div>
    @endif
    @if ($errors->any())
        <div class="flash bad">
            @foreach ($errors->all() as $error)
                <div>{{ $error }}</div>
            @endforeach
        </div>
    @endif

    @yield('content')
</main>
<script>
/* The toggle contract from docs/design-system.md: auto → light → dark → auto. */
(function () {
    var button = document.querySelector('[data-theme-toggle]');
    if (!button) return;

    var order = ['auto', 'light', 'dark'];
    var label = { auto: '◐', light: '☀', dark: '☾' };

    function current() {
        try { return localStorage.getItem('wr-theme') || 'auto'; } catch (e) { return 'auto'; }
    }

    function apply(theme) {
        if (theme === 'auto') {
            delete document.documentElement.dataset.theme;
            try { localStorage.removeItem('wr-theme'); } catch (e) {}
        } else {
            document.documentElement.dataset.theme = theme;
            try { localStorage.setItem('wr-theme', theme); } catch (e) {}
        }
        button.textContent = label[theme];
        button.title = 'Theme: ' + theme;
    }

    button.textContent = label[current()];
    button.addEventListener('click', function () {
        var next = order[(order.indexOf(current()) + 1) % order.length];
        apply(next);
    });
})();
</script>
</body>
</html>
