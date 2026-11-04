@extends('layouts.app')

@section('title', 'Authorization center')

@section('content')
    <h1>Authorization center</h1>
    <p class="lead">OAuth 2.0 / OpenID Connect issuer for internal services. Accounts are created by administrators only.</p>

    <div class="grid">
        <div class="stat"><div class="n">{{ $keyCount }}</div><div class="k">Signing keys</div></div>
        <div class="stat"><div class="n">{{ $guestEnabled ? 'on' : 'off' }}</div><div class="k">Guest channel</div></div>
        <div class="stat"><div class="n mono" style="font-size:15px">{{ $guestAlgo }}</div><div class="k">Guest algorithm</div></div>
    </div>

    <h2>Endpoints</h2>
    <div class="card">
        <table>
            <tbody>
            <tr><th>Issuer</th><td class="mono">{{ $issuer }}</td></tr>
            <tr><th>Discovery</th><td class="mono">{{ $issuer }}/.well-known/openid-configuration</td></tr>
            <tr><th>Authorize</th><td class="mono">{{ $issuer }}/oauth/authorize</td></tr>
            <tr><th>Token</th><td class="mono">{{ $issuer }}/oauth/token</td></tr>
            <tr><th>Userinfo</th><td class="mono">{{ $issuer }}/oauth/userinfo</td></tr>
            <tr><th>Introspect</th><td class="mono">{{ $issuer }}/oauth/introspect</td></tr>
            <tr><th>Revoke</th><td class="mono">{{ $issuer }}/oauth/revoke</td></tr>
            <tr><th>Guest</th><td class="mono">{{ $issuer }}/oauth/guest</td></tr>
            <tr><th>JWKS</th><td class="mono">{{ $issuer }}/.well-known/jwks.json</td></tr>
            </tbody>
        </table>
    </div>

    <h2>Sign in</h2>
    <div class="card">
        <p class="small muted">There is no self-service registration. If you need an account, ask an administrator.</p>
        <div class="row">
            <a class="btn primary" href="{{ route('login') }}">User sign-in</a>
            <a class="btn" href="{{ route('admin.login') }}">Console</a>
        </div>
    </div>
@endsection
