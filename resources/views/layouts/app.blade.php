<!doctype html>
<html lang="ko">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', '계정') — {{ config('app.name') }}</title>
    <meta name="color-scheme" content="light dark">
    <script src="{{ asset('assets/theme-init.js') }}"></script>
    <link rel="stylesheet" href="{{ asset('assets/theme.css') }}">
    <link rel="stylesheet" href="{{ asset('assets/app.css') }}?v={{ filemtime(public_path('assets/app.css')) }}">
    <script src="{{ asset('assets/console.js') }}?v={{ filemtime(public_path('assets/console.js')) }}" defer></script>
</head>
<body>
@php($me = auth('web')->user())
<header class="top">
    <a class="brand" href="{{ route('home') }}" style="text-decoration:none">계정 센터</a>
    <nav>
        @if ($me?->isSuperAdmin())
            <a href="{{ route('admin.users.index') }}" @class(['active' => request()->routeIs('admin.users.*')])>사용자</a>
            <a href="{{ route('admin.audit.index') }}" @class(['active' => request()->routeIs('admin.audit.*')])>활동 기록</a>
            <a href="{{ route('admin.clients.index') }}" @class(['active' => request()->routeIs('admin.clients.*')])>연결된 앱</a>
        @endif
        @if ($me)
            <a href="{{ route('account') }}" @class(['active' => request()->routeIs('account')])>내 계정</a>
        @endif
    </nav>
    <span class="spacer"></span>

    <button class="theme-toggle icon-btn" type="button" data-theme-toggle title="테마" aria-label="테마"></button>

    @if ($me)
        <a class="me" href="{{ route('account') }}">
            @include('partials.avatar', ['user' => $me, 'size' => 'sm'])
            <span class="me__name">{{ $me->name }}</span>
        </a>
        <form method="post" action="{{ route('logout') }}">
            @csrf
            <button class="link" type="submit">로그아웃</button>
        </form>
    @endif
</header>

<main class="@yield('main-class')">
    @if (session('status'))
        <div class="flash ok" role="status">{{ session('status') }}</div>
    @endif

    @if (session('generated_password'))
        <div class="flash key">
            <strong>새 비밀번호 — 지금 한 번만 보입니다. 복사해서 본인에게 전달하세요.</strong>
            @foreach (session('generated_password') as $username => $plain)
                <div class="secret">
                    <span class="mono">{{ $username }}</span>
                    <code id="secret-{{ $loop->index }}">{{ $plain }}</code>
                    <button type="button" data-copy="#secret-{{ $loop->index }}">복사</button>
                </div>
            @endforeach
        </div>
    @endif

    @if (session('reset_url'))
        <div class="flash key">
            <strong>비밀번호 재설정 링크 — 지금 한 번만 보입니다.</strong>
            <div class="secret">
                <code id="reset-url">{{ session('reset_url') }}</code>
                <button type="button" data-copy="#reset-url">복사</button>
            </div>
            <div class="small muted" style="margin-top:6px">
                메신저 등으로 본인에게 보내 주세요. 한 번만 쓸 수 있고 {{ session('reset_expires') ? session('reset_expires').'까지' : '24시간' }} 유효합니다.
                새 링크를 만들면 이 링크는 바로 무효가 됩니다.
            </div>
        </div>
    @endif

    @if (session('client_secret'))
        <div class="flash key">
            <strong>클라이언트 시크릿 — 지금 한 번만 보입니다.</strong>
            <div class="secret">
                <code id="client-secret">{{ session('client_secret') }}</code>
                <button type="button" data-copy="#client-secret">복사</button>
            </div>
        </div>
    @endif

    @if ($errors->any())
        <div class="flash bad" role="alert">
            @foreach ($errors->all() as $error)
                <div>{{ $error }}</div>
            @endforeach
        </div>
    @endif

    @yield('content')
</main>
</body>
</html>
