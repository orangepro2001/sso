@extends('layouts.app')

@section('title', 'Dashboard')

@section('content')
    <h1>Dashboard</h1>
    <p class="lead">Everything below is live state from the database.</p>

    @unless ($guestSecretConfigured)
        <div class="flash bad">
            <strong>SSO_GUEST_SECRET is empty.</strong> The guest channel accepts every request without a signature.
            Set the secret in the container environment to make device signatures verifiable.
        </div>
    @endunless

    <div class="grid">
        <div class="stat"><div class="n">{{ $stats['users'] }}</div><div class="k">Users ({{ $stats['usersActive'] }} active)</div></div>
        <div class="stat"><div class="n">{{ $stats['clients'] }}</div><div class="k">Active clients</div></div>
        <div class="stat"><div class="n">{{ $stats['devices'] }}</div><div class="k">Guest devices</div></div>
        <div class="stat"><div class="n">{{ $stats['devicesBlacklisted'] }}</div><div class="k">Blacklisted devices</div></div>
        <div class="stat"><div class="n">{{ $stats['tokensLive'] }}</div><div class="k">Live access tokens</div></div>
        <div class="stat"><div class="n">{{ $stats['refreshFamilies'] }}</div><div class="k">Refresh families</div></div>
        <div class="stat"><div class="n">{{ $stats['blacklist'] }}</div><div class="k">Blacklist entries</div></div>
        <div class="stat"><div class="n">{{ $keyCount }}</div><div class="k">Signing keys</div></div>
    </div>

    <h2>Recently seen guest devices</h2>
    <div class="card">
        @if ($recentDevices->isEmpty())
            <p class="empty">No guest has enrolled yet.</p>
        @else
            <table>
                <thead>
                <tr><th>Device</th><th>Status</th><th>Calls</th><th>Last seen</th><th>From</th></tr>
                </thead>
                <tbody>
                @foreach ($recentDevices as $device)
                    <tr>
                        <td class="mono"><a href="{{ route('admin.devices.show', $device) }}">{{ $device->device_id }}</a></td>
                        <td>
                            @if ($device->status === 'active')
                                <span class="badge ok">active</span>
                            @else
                                <span class="badge bad">blacklisted</span>
                            @endif
                            @if ($device->reviewed_at === null)
                                <span class="badge warn">unreviewed</span>
                            @endif
                        </td>
                        <td>{{ $device->request_count }}</td>
                        <td class="small">{{ $device->last_seen_at?->diffForHumans() }}</td>
                        <td class="mono small">{{ $device->last_seen_ip }}</td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        @endif
    </div>

    <h2>Recent activity</h2>
    <div class="card">
        @if ($recentAudit->isEmpty())
            <p class="empty">Nothing logged yet.</p>
        @else
            <table>
                <thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Subject</th><th>IP</th></tr></thead>
                <tbody>
                @foreach ($recentAudit as $log)
                    <tr>
                        <td class="small muted">{{ $log->created_at?->format('m-d H:i:s') }}</td>
                        <td class="mono">{{ $log->event }}</td>
                        <td class="small">{{ $log->actor_type }}{{ $log->actor_id ? ':'.$log->actor_id : '' }}</td>
                        <td class="small mono">{{ $log->subject_id }}</td>
                        <td class="mono small">{{ $log->ip }}</td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        @endif
    </div>
@endsection
