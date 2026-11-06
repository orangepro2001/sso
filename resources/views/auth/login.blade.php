@extends('layouts.app')

@section('title', 'Sign in')

@section('main-class', 'narrow')

@section('content')
    <h1>Sign in</h1>

    @if ($requestingClient)
        {{-- The OAuth flow bounced here, so say so: an unexplained login form is
             what makes people type their console credentials into it. --}}
        <p class="lead">
            <strong>{{ $requestingClient }}</strong> wants to sign you in.
        </p>
    @else
        <p class="lead">One account for every internal tool, including the console.</p>
    @endif

    <form class="card" method="post" action="{{ route('login.store') }}@if (! empty($next))?next={{ urlencode($next) }}@endif">
        @csrf
        <label for="username">Username</label>
        <input id="username" type="text" name="username" value="{{ old('username') }}" required autofocus
               autocomplete="username" autocapitalize="none" spellcheck="false">

        <label for="password">Password</label>
        <input id="password" type="password" name="password" required autocomplete="current-password">

        <label class="row" style="margin-top:16px">
            <input type="checkbox" name="remember" value="1" style="width:auto">
            <span>Remember this browser</span>
        </label>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Sign in</button>
            <a class="btn" href="{{ $next ?: route('home') }}">Cancel</a>
        </div>
    </form>

    <p class="small muted">No account? <a href="{{ route('register') }}">Register</a>.</p>
@endsection
