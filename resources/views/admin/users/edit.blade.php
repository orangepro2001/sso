@extends('layouts.app')

@section('title', 'Edit user')

@section('content')
    <h1>{{ $user->name }}</h1>
    <p class="lead mono">{{ $user->email }} · created {{ $user->created_at?->format('Y-m-d') }}</p>

    <form class="card" method="post" action="{{ route('admin.users.update', $user) }}">
        @csrf
        @method('put')

        <label for="name">Display name</label>
        <input id="name" type="text" name="name" value="{{ old('name', $user->name) }}" required>

        <label for="email">E-mail</label>
        <input id="email" type="email" name="email" value="{{ old('email', $user->email) }}" required>

        <label for="status">Status</label>
        <select id="status" name="status">
            <option value="active" @selected(old('status', $user->status) === 'active')>active — can sign in and use tokens</option>
            <option value="disabled" @selected(old('status', $user->status) === 'disabled')>disabled — every token stops working</option>
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
        <label for="new-password">New password (min. 12 characters)</label>
        <input id="new-password" type="text" name="password" value="{{ \Illuminate\Support\Str::password(16) }}" required>
        <div class="row" style="margin-top:16px">
            <button type="submit">Replace password</button>
            <span class="small muted">Active sessions and issued tokens stay valid.</span>
        </div>
    </form>

    <h2>Account facts</h2>
    <div class="card">
        <table>
            <tbody>
            <tr><th>ID</th><td class="mono">{{ $user->id }}</td></tr>
            <tr><th>Last login</th><td>{{ $user->last_login_at?->toDayDateTimeString() ?? 'never' }}</td></tr>
            <tr><th>Last login IP</th><td class="mono">{{ $user->last_login_ip ?? '—' }}</td></tr>
            <tr><th>Created by admin</th><td class="mono">{{ $user->created_by ?? '—' }}</td></tr>
            </tbody>
        </table>
    </div>
@endsection
