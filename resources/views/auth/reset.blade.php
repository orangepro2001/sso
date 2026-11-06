@extends('layouts.app')

@section('title', 'Set a new password')

@section('main-class', 'narrow')

@section('content')
    @if ($invalid)
        <h1>This link cannot be used</h1>
        <p class="lead">
            The reset link is unknown, has expired, was already used, or was replaced by
            a newer one. Ask an administrator for a fresh link.
        </p>
        <div class="card">
            <div class="row">
                <a class="btn primary" href="{{ route('login') }}">Go to sign-in</a>
                <a class="btn" href="{{ route('home') }}">Home</a>
            </div>
        </div>
    @else
        <h1>Set a new password</h1>
        <p class="lead">
            For <strong class="mono">{{ $user->username }}</strong>. This link works once and
            then stops working.
        </p>

        <form class="card" method="post" action="{{ route('password.reset.update', ['token' => $token]) }}">
            @csrf

            <label for="password">New password</label>
            <input id="password" type="password" name="password" required autofocus
                   autocomplete="new-password">

            <label for="password_confirmation">Repeat the new password</label>
            <input id="password_confirmation" type="password" name="password_confirmation" required
                   autocomplete="new-password">

            <div class="row" style="margin-top:20px">
                <button class="primary" type="submit">Set password</button>
                <a class="btn" href="{{ route('login') }}">Cancel</a>
            </div>

            <p class="small muted" style="margin-bottom:0">
                Setting a password signs this account out everywhere: its access and
                refresh tokens are revoked.
            </p>
        </form>
    @endif
@endsection
