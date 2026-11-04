@extends('layouts.app')

@section('title', 'Sign in')

@section('main-class', 'narrow')

@section('content')
    <h1>Sign in</h1>
    <p class="lead">Use the credentials an administrator gave you.</p>

    <form class="card" method="post" action="{{ route('login.store') }}">
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
            <a class="btn" href="{{ route('home') }}">Cancel</a>
        </div>
    </form>

    {{-- Administrators are a separate identity space with their own sign-in page.
         Said unconditionally, so this hint cannot be used to enumerate admins. --}}
    <div class="card">
        <p class="small muted" style="margin:0">
            <strong>Administrator?</strong> The console has its own sign-in page:
            <a href="{{ route('admin.login') }}">console sign-in</a>.
            Administrator accounts do not work here, and user accounts do not work
            there.
        </p>
    </div>
@endsection
