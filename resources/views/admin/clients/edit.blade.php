@extends('layouts.app')

@section('title', 'Edit client')

@section('content')
    <h1>{{ $client->name }}</h1>
    <p class="lead mono">{{ $client->client_id }}</p>

    <form class="card" method="post" action="{{ route('admin.clients.update', $client) }}">
        @csrf
        @method('put')

        <label for="name">Name</label>
        <input id="name" type="text" name="name" value="{{ old('name', $client->name) }}" required>

        <label for="type">Type</label>
        <select id="type" name="type">
            <option value="public" @selected(old('type', $client->type) === 'public')>public — PKCE required</option>
            <option value="confidential" @selected(old('type', $client->type) === 'confidential')>confidential — client secret</option>
        </select>

        <label for="redirect_uris">Redirect URIs (one per line)</label>
        <textarea id="redirect_uris" name="redirect_uris">{{ old('redirect_uris', implode("\n", $client->redirect_uris ?? [])) }}</textarea>


        <label for="home_url">Home URL <span class="muted small">(where a person uses it; blank = machine only)</span></label>
        <input id="home_url" type="url" name="home_url" maxlength="500"
               value="{{ old('home_url', $client->home_url) }}" placeholder="https://521985.xyz/report">

        <label for="sort_order">Order in the launcher</label>
        <input id="sort_order" type="number" name="sort_order" min="0" max="999" value="{{ old('sort_order', $client->sort_order ?? 0) }}">

        <label class="row" style="margin-top:12px">
            <input type="checkbox" name="in_launcher" value="1" style="width:auto" @checked(old('in_launcher', $client->in_launcher ?? true))>
            <span>Show in the launcher</span>
        </label>

        <label>Allowed scopes</label>
        @foreach ($scopes as $scope)
            <label class="row" style="margin:4px 0">
                <input type="checkbox" name="allowed_scopes[]" value="{{ $scope }}" style="width:auto"
                       @checked(in_array($scope, old('allowed_scopes', $client->allowed_scopes ?? []), true))>
                <span class="mono small">{{ $scope }}</span>
            </label>
        @endforeach

        <label class="row" style="margin-top:14px">
            <input type="checkbox" name="active" value="1" style="width:auto" @checked(old('active', $client->active))>
            <span>Active</span>
        </label>

        <label class="row" style="margin-top:10px">
            <input type="checkbox" name="rotate_secret" value="1" style="width:auto">
            <span>Rotate the client secret (confidential clients only, shown once)</span>
        </label>

        <label for="note">Note</label>
        <textarea id="note" name="note">{{ old('note', $client->note) }}</textarea>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Save</button>
            <a class="btn" href="{{ route('admin.clients.index') }}">Back</a>
        </div>
    </form>

    <h2>Integration</h2>
    <div class="card">
        <pre>issuer        {{ rtrim(config('sso.issuer'), '/') }}
discovery     {{ rtrim(config('sso.issuer'), '/') }}/.well-known/openid-configuration
authorize     {{ rtrim(config('sso.issuer'), '/') }}/oauth/authorize
token         {{ rtrim(config('sso.issuer'), '/') }}/oauth/token
userinfo      {{ rtrim(config('sso.issuer'), '/') }}/oauth/userinfo
introspect    {{ rtrim(config('sso.issuer'), '/') }}/oauth/introspect
redirect_uri  {{ ($client->redirect_uris ?? [])[0] ?? '(none registered)' }}
scopes        {{ implode(' ', $client->allowed_scopes ?? []) }}</pre>
    </div>
@endsection
