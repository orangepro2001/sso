@extends('layouts.app')

@section('title', 'Guest device')

@section('content')
    <h1 class="mono" style="font-size:19px">{{ $device->device_id }}</h1>
    <p class="lead">
        @if ($device->isActive())
            <span class="badge ok">active</span>
        @else
            <span class="badge bad">blacklisted</span>
        @endif
        @if ($device->reviewed_at === null)
            <span class="badge warn">unreviewed</span>
        @else
            reviewed {{ $device->reviewed_at->diffForHumans() }} by admin #{{ $device->reviewed_by }}
        @endif
    </p>

    <div class="grid">
        <div class="stat"><div class="n">{{ $device->request_count }}</div><div class="k">Requests</div></div>
        <div class="stat"><div class="n" style="font-size:15px">{{ $device->first_seen_at?->format('Y-m-d H:i') }}</div><div class="k">First seen</div></div>
        <div class="stat"><div class="n" style="font-size:15px">{{ $device->last_seen_at?->format('Y-m-d H:i') }}</div><div class="k">Last seen</div></div>
        <div class="stat"><div class="n" style="font-size:15px" class="mono">{{ $device->first_seen_ip }}</div><div class="k">First IP</div></div>
        <div class="stat"><div class="n" style="font-size:15px">{{ $device->last_seen_ip }}</div><div class="k">Last IP</div></div>
    </div>

    <h2>Decide</h2>
    <div class="card">
        @if ($device->isActive())
            <form method="post" action="{{ route('admin.devices.block', $device) }}">
                @csrf
                <label for="reason">Blacklist reason (goes to the audit log)</label>
                <input id="reason" type="text" name="reason" placeholder="unknown machine, shared lab PC, ...">
                <div class="row" style="margin-top:16px">
                    <button class="danger" type="submit">Blacklist and revoke its tokens</button>
                </div>
                <p class="small muted" style="margin-bottom:0">
                    Effective immediately: the device is refused on the next <span class="mono">/oauth/guest</span> call and every
                    token it holds stops introspecting.
                </p>
            </form>
        @else
            <form method="post" action="{{ route('admin.devices.unblock', $device) }}">
                @csrf
                <button class="primary" type="submit">Reinstate device</button>
                <span class="small muted">Its tokens stay revoked; the next request mints a fresh one.</span>
            </form>
        @endif
    </div>

    <h2>Mark as reviewed</h2>
    <form class="card" method="post" action="{{ route('admin.devices.review', $device) }}">
        @csrf
        <input type="hidden" name="verdict" value="ok">
        <label for="note">Note</label>
        <textarea id="note" name="note">{{ $device->note }}</textarea>
        <div class="row" style="margin-top:14px">
            <button type="submit">Keep and mark reviewed</button>
        </div>
    </form>

    <h2>User agent</h2>
    <div class="card">
        <table>
            <tbody>
            <tr><th>First</th><td class="mono small">{{ $device->first_user_agent ?? '—' }}</td></tr>
            <tr><th>Last</th><td class="mono small">{{ $device->last_user_agent ?? '—' }}</td></tr>
            </tbody>
        </table>
    </div>

    <h2>Tokens</h2>
    <div class="card">
        @if ($tokens->isEmpty())
            <p class="empty">No tokens issued.</p>
        @else
            <table>
                <thead><tr><th>jti</th><th>Scopes</th><th>Expires</th><th>Revoked</th><th>Issued</th></tr></thead>
                <tbody>
                @foreach ($tokens as $token)
                    <tr>
                        <td class="mono small">{{ $token->jti }}</td>
                        <td class="mono small">{{ implode(' ', $token->scopes ?? []) }}</td>
                        <td class="small">{{ $token->expires_at?->format('Y-m-d H:i') ?? 'never' }}</td>
                        <td class="small">{{ $token->revoked_at?->format('Y-m-d H:i') ?? '—' }}</td>
                        <td class="small muted">{{ $token->created_at?->diffForHumans() }}</td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        @endif
    </div>

    <p><a href="{{ route('admin.devices.index') }}">← All guest devices</a></p>
@endsection
