@extends('layouts.app')

@section('title', 'New client')

@section('content')
    <h1>New client</h1>
    <p class="lead">A <strong>public</strong> client has no secret and must use PKCE. A <strong>confidential</strong> client gets a secret shown once.</p>

    <form class="card" method="post" action="{{ route('admin.clients.store') }}">
        @csrf
        <label for="name">Name</label>
        <input id="name" type="text" name="name" value="{{ old('name') }}" required autofocus>

        <label for="type">Type</label>
        <select id="type" name="type">
            <option value="public" @selected(old('type') === 'public')>public — SPA / CLI / native, PKCE required</option>
            <option value="confidential" @selected(old('type') === 'confidential')>confidential — server side, client secret</option>
        </select>

        <label for="redirect_uris">Redirect URIs (one per line, exact match)</label>
        <textarea id="redirect_uris" name="redirect_uris" placeholder="https://example.internal/auth/callback">{{ old('redirect_uris') }}</textarea>

        <label>Allowed scopes</label>
        @foreach ($scopes as $scope)
            <label class="row" style="margin:4px 0">
                <input type="checkbox" name="allowed_scopes[]" value="{{ $scope }}" style="width:auto"
                       @checked(in_array($scope, old('allowed_scopes', ['openid', 'profile', 'email']), true))>
                <span class="mono small">{{ $scope }}</span>
            </label>
        @endforeach

        <label class="row" style="margin-top:14px">
            <input type="checkbox" name="active" value="1" style="width:auto" @checked(old('active', true))>
            <span>Active</span>
        </label>

        <label for="note">Note</label>
        <textarea id="note" name="note">{{ old('note') }}</textarea>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Register client</button>
            <a class="btn" href="{{ route('admin.clients.index') }}">Cancel</a>
        </div>
    </form>
@endsection
