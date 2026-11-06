@extends('layouts.app')

@section('title', 'Sign in')

@section('content')
    <main class="narrow">
        <h1>Authorization center</h1>
        <p class="lead">One account for the internal tools.</p>

        <div class="card">
            @if ($user)
                <p style="margin-top:0">
                    Signed in as <strong>{{ $user->name }}</strong>
                    <span class="mono muted small">{{ $user->username }}</span>
                </p>
                <div class="row">
                    @if ($pending)
                        <a class="btn primary" href="{{ route('oauth.authorize', $pending) }}">Continue</a>
                    @else
                        <a class="btn primary" href="{{ route('home') }}">Continue</a>
                    @endif
                    <a class="btn" href="{{ route('account') }}">Your account</a>
                    @if ($user->isSuperAdmin())
                        <a class="btn" href="{{ route('admin.dashboard') }}">Console</a>
                    @endif
                    <form method="post" action="{{ route('logout') }}">
                        @csrf
                        <button class="link" type="submit">Sign out</button>
                    </form>
                </div>
            @else
                <div class="row">
                    <a class="btn primary" href="{{ route('login') }}">Sign in</a>
                    <a class="btn" href="{{ route('register') }}">Register</a>
                </div>
            @endif
        </div>

        @if ($user && $apps->isNotEmpty())
            <h2>Your applications</h2>
            <p class="tiny muted" style="margin-top:-6px">
                Curated by an administrator. Each one signs you in with this account — no separate password.
            </p>

            <div class="apps">
                @foreach ($apps as $app)
                    <a class="app" href="{{ $app->home_url }}">
                        <span class="app__name">{{ $app->name }}</span>
                        @if ($app->note)
                            <span class="app__note">{{ \Illuminate\Support\Str::limit($app->note, 90) }}</span>
                        @endif
                        <span class="app__go">Open →</span>
                    </a>
                @endforeach
            </div>
        @endif
    </main>
@endsection
