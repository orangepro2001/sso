@extends('layouts.app')

@section('title', 'Register')

@section('main-class', 'narrow')

@section('content')
    <h1>Register</h1>

    <form class="card" method="post" action="{{ route('register.store') }}">
        @csrf

        <label for="name">Display name</label>
        <input id="name" type="text" name="name" value="{{ old('name') }}" required maxlength="120" autofocus
               placeholder="채길용 사원">

        <label for="username">Username</label>
        <input id="username" type="text" name="username" value="{{ old('username') }}" required
               minlength="3" maxlength="64" autocapitalize="off" autocomplete="username"
               placeholder="chae-gilyong">
        <p class="tiny muted">Lower-case letters, digits, dot, dash, underscore. This is what you sign in with.</p>

        <label for="password">Password</label>
        <input id="password" type="password" name="password" required autocomplete="new-password">

        <label for="password_confirmation">Password again</label>
        <input id="password_confirmation" type="password" name="password_confirmation" required
               autocomplete="new-password">

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Create account</button>
            <a class="btn" href="{{ route('login') }}">I have an account</a>
        </div>
    </form>
@endsection
