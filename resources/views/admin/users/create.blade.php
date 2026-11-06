@extends('layouts.app')

@section('title', 'New user')

@section('content')
    <h1>New user</h1>
    <p class="lead">Hand these credentials over out of band. The password is stored hashed and cannot be read back.</p>

    <form class="card" method="post" action="{{ route('admin.users.store') }}">
        @csrf
        <label for="name">Display name</label>
        <input id="name" type="text" name="name" value="{{ old('name') }}" required autofocus>

        <label for="username">Username (used to sign in)</label>
        <input id="username" type="text" name="username" value="{{ old('username') }}" required
               autocomplete="off" autocapitalize="none" spellcheck="false"
               placeholder="e.g. yzy">
        <p class="small muted" style="margin:6px 0 0">
            3–64 characters, lower-case letters, digits, dot, dash or underscore.
            Stored lower-case; the sign-in form is case-insensitive.
        </p>

        <label for="password">Initial password — leave blank to generate one</label>
        <input id="password" type="password" name="password" value="{{ old('password') }}"
               autocomplete="new-password" placeholder="(blank: a 20-character password is generated)">
        <p class="small muted" style="margin:6px 0 0">
            Whatever is used is shown once on
            the next page — the form never pre-fills a password, so what you read here
            is never out of date.
        </p>

        <label for="role">Role</label>
        <select id="role" name="role">
            <option value="user" @selected(old('role', 'user') === 'user')>user — signs in to applications</option>
            <option value="super_admin" @selected(old('role', 'user') === 'super_admin')>super_admin — also runs this console</option>
        </select>

        <label for="note">Note (optional)</label>
        <textarea id="note" name="note">{{ old('note') }}</textarea>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Create user</button>
            <a class="btn" href="{{ route('admin.users.index') }}">Cancel</a>
        </div>
    </form>
@endsection
