@extends('layouts.app')

@section('title', 'Sign in')

@section('content')
    <main class="narrow">
        <h1>Authorization center</h1>
        <p class="lead">One account for the internal tools. Administrators create accounts — or hand out an invite.</p>

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
                    <form method="post" action="{{ route('logout') }}">
                        @csrf
                        <button class="link" type="submit">Sign out</button>
                    </form>
                </div>
            @else
                <div class="row">
                    <a class="btn primary" href="{{ route('login') }}">Sign in</a>
                    <a class="btn" href="{{ route('admin.login') }}">Administrator console</a>
                </div>
                <p class="tiny muted" style="margin-bottom:0">
                    No account? Ask an administrator for an invite link — registration is closed otherwise.
                </p>
            @endif
        </div>
    </main>
@endsection
