<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', 'SSO') — {{ config('app.name') }}</title>
    <link rel="stylesheet" href="{{ asset('assets/app.css') }}">
</head>
<body>
<header class="top">
    <span class="brand">SSO</span>
    <nav>
        @auth('admin')
            <a href="{{ route('admin.dashboard') }}" @class(['active' => request()->routeIs('admin.dashboard')])>Dashboard</a>
            <a href="{{ route('admin.users.index') }}" @class(['active' => request()->routeIs('admin.users.*')])>Users</a>
            <a href="{{ route('admin.clients.index') }}" @class(['active' => request()->routeIs('admin.clients.*')])>Clients</a>
            <a href="{{ route('admin.devices.index') }}" @class(['active' => request()->routeIs('admin.devices.*')])>Guest devices</a>
            <a href="{{ route('admin.tokens.index') }}" @class(['active' => request()->routeIs('admin.tokens.*')])>Tokens</a>
            <a href="{{ route('admin.blacklist.index') }}" @class(['active' => request()->routeIs('admin.blacklist.*')])>Blacklist</a>
            <a href="{{ route('admin.audit.index') }}" @class(['active' => request()->routeIs('admin.audit.*')])>Audit</a>
        @endauth
    </nav>
    <span class="spacer"></span>
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
</body>
</html>
