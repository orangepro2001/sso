@extends('layouts.app')

@section('title', 'Edit user')

@section('content')
    <h1>{{ $user->name }}</h1>
    <p class="lead mono">{{ $user->username }} · created {{ $user->created_at?->format('Y-m-d') }}</p>

    <form class="card" method="post" action="{{ route('admin.users.update', $user) }}">
        @csrf
        @method('put')

        <label for="name">Display name</label>
        <input id="name" type="text" name="name" value="{{ old('name', $user->name) }}" required>

        <label for="username">Username (used to sign in)</label>
        <input id="username" type="text" name="username" value="{{ old('username', $user->username) }}" required
               autocomplete="off" autocapitalize="none" spellcheck="false">
        <p class="small muted" style="margin:6px 0 0">
            Changing this changes what the user types at the sign-in prompt. Issued
            tokens stay valid; their <span class="mono">preferred_username</span> claim
            keeps the old value until they refresh.
        </p>

        <label for="status">Status</label>
        <select id="status" name="status">
            <option value="active" @selected(old('status', $user->status) === 'active')>active — can sign in and use tokens</option>
            <option value="disabled" @selected(old('status', $user->status) === 'disabled')>disabled — every token stops working</option>
        </select>

        <label for="role">Role</label>
        <select id="role" name="role">
            <option value="user" @selected(old('role', $user->role) === 'user')>user — signs in to applications</option>
            <option value="super_admin" @selected(old('role', $user->role) === 'super_admin')>super_admin — also runs this console</option>
        </select>

        <label for="note">Note</label>
        <textarea id="note" name="note">{{ old('note', $user->note) }}</textarea>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Save</button>
            <a class="btn" href="{{ route('admin.users.index') }}">Back</a>
        </div>
    </form>

    <h2>Replace password</h2>
    <form class="card" method="post" action="{{ route('admin.users.password', $user) }}">
        @csrf
        <label for="new-password">New password — leave blank to generate one</label>
        <input id="new-password" type="password" name="password" value=""
               autocomplete="new-password" placeholder="(blank: a 20-character password is generated)">
        <div class="row" style="margin-top:16px">
            <button type="submit">Replace password</button>
            <span class="small muted">Active sessions and issued tokens stay valid.</span>
        </div>
        <p class="small muted" style="margin-bottom:0">
            Only this button changes the password; <strong>Save</strong> above does not.
            The result is shown once on the next page. Changing the password revokes
            every token this user holds.
        </p>
    </form>

    <h2>Let the user choose their own password</h2>
    <form class="card" method="post" action="{{ route('admin.users.reset-link', $user) }}">
        @csrf
        <p class="small muted" style="margin-top:0">
            Creates a one-time link. There is no mail flow, so you deliver it yourself
            (chat, ticket, in person). The user opens it, sets a password, and the link
            dies. It expires after {{ intdiv((int) config('sso.reset_link_ttl'), 3600) }} hours.
        </p>
        <div class="row">
            <button type="submit">Create reset link</button>
            <span class="small muted">Issuing a link invalidates any earlier unused one.</span>
        </div>
    </form>

    <h2>Account facts</h2>
    <div class="card">
        <table>
            <tbody>
            <tr><th>ID</th><td class="mono">{{ $user->id }}</td></tr>
            <tr><th>Last login</th><td>{{ $user->last_login_at?->toDayDateTimeString() ?? 'never' }}</td></tr>
            <tr><th>Last login IP</th><td class="mono">{{ $user->last_login_ip ?? '—' }}</td></tr>
            <tr><th>Created by</th><td>{{ $user->creator?->username ?? '—' }}</td></tr>
            </tbody>
        </table>
    </div>
@endsection
