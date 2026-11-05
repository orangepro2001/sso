@extends('layouts.app')

@section('title', 'Register')

@section('content')
    <h1>Register</h1>

    @if ($invalid)
        <div class="flash bad">
            <strong>This registration code cannot be used.</strong>
            <p class="tiny">It may have expired, already been used, or been revoked. Ask an administrator for a new one.</p>
        </div>
    @else
        @if ($note)
            <p class="lead">{{ $note }}</p>
        @endif

        <form class="card" method="post" action="{{ route('register.store', $code) }}">
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
            <input id="password" type="password" name="password" required minlength="12" autocomplete="new-password">
            <p class="tiny muted">At least 12 characters.</p>

            <label for="password_confirmation">Password again</label>
            <input id="password_confirmation" type="password" name="password_confirmation" required
                   minlength="12" autocomplete="new-password">

            <button class="btn" type="submit">Create account</button>
        </form>
    @endif
@endsection
