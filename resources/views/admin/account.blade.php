@extends('layouts.app')

@section('title', 'Your account')

@section('content')
    <h1>Your account</h1>
    <p class="lead">{{ auth('admin')->user()->email }} · sign-in {{ auth('admin')->user()->last_login_at?->diffForHumans() ?? 'never' }} from {{ auth('admin')->user()->last_login_ip ?? '—' }}</p>

    <h2>Change password</h2>
    <form class="card" method="post" action="{{ route('admin.account.password') }}">
        @csrf
        @method('put')

        <label for="current_password">Current password</label>
        <input id="current_password" type="password" name="current_password" required autocomplete="current-password">

        <label for="password">New password (min. 12 characters)</label>
        <input id="password" type="password" name="password" required autocomplete="new-password">

        <label for="password_confirmation">Repeat the new password</label>
        <input id="password_confirmation" type="password" name="password_confirmation" required autocomplete="new-password">

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Change password</button>
        </div>
        <p class="small muted" style="margin-bottom:0">Your current session stays valid; other sessions keep their own cookies.</p>
    </form>

    <h2>Display name</h2>
    <form class="card" method="post" action="{{ route('admin.account.name') }}">
        @csrf
        @method('put')
        <label for="name">Name</label>
        <input id="name" type="text" name="name" value="{{ old('name', auth('admin')->user()->name) }}" required>
        <div class="row" style="margin-top:16px">
            <button type="submit">Save</button>
        </div>
    </form>
@endsection
