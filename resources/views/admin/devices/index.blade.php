@extends('layouts.app')

@section('title', 'Guest devices')

@section('content')
    <h1>Guest devices</h1>
    <p class="lead">
        Every validly signed request is approved immediately and gets a usable token. This list is the
        after-the-fact review: blacklist what should not be there.
    </p>

    <div class="row" style="margin-bottom:16px">
        <a class="btn {{ $status === 'all' ? 'primary' : '' }}" href="{{ route('admin.devices.index') }}">All ({{ $counts['all'] }})</a>
        <a class="btn {{ $status === 'active' ? 'primary' : '' }}" href="{{ route('admin.devices.index', ['status' => 'active']) }}">Active ({{ $counts['active'] }})</a>
        <a class="btn {{ $status === 'blacklisted' ? 'primary' : '' }}" href="{{ route('admin.devices.index', ['status' => 'blacklisted']) }}">Blacklisted ({{ $counts['blacklisted'] }})</a>
        <span class="badge warn">{{ $counts['unreviewed'] }} unreviewed</span>
        <form method="get" action="{{ route('admin.devices.index') }}" class="row" style="margin-left:auto">
            <input type="hidden" name="status" value="{{ $status }}">
            <input type="text" name="q" value="{{ $search }}" placeholder="device_id" style="width:260px">
            <button type="submit">Search</button>
        </form>
    </div>

    <div class="card">
        @if ($devices->isEmpty())
            <p class="empty">No devices.</p>
        @else
            <table>
                <thead>
                <tr><th>Device</th><th>Status</th><th>Calls</th><th>First seen</th><th>Last seen</th><th>IP</th><th></th></tr>
                </thead>
                <tbody>
                @foreach ($devices as $device)
                    <tr>
                        <td class="mono small"><a href="{{ route('admin.devices.show', $device) }}">{{ $device->device_id }}</a></td>
                        <td>
                            @if ($device->isActive())
                                <span class="badge ok">active</span>
                            @else
                                <span class="badge bad">blacklisted</span>
                            @endif
                            @if ($device->reviewed_at === null)
                                <span class="badge warn">new</span>
                            @endif
                        </td>
                        <td>{{ $device->request_count }}</td>
                        <td class="small muted">{{ $device->first_seen_at?->format('Y-m-d H:i') }}</td>
                        <td class="small muted">{{ $device->last_seen_at?->diffForHumans() }}</td>
                        <td class="mono small">{{ $device->last_seen_ip }}</td>
                        <td class="small">
                            @if ($device->isActive())
                                <form class="inline-form" method="post" action="{{ route('admin.devices.block', $device) }}">
                                    @csrf
                                    <button class="link" type="submit">Blacklist</button>
                                </form>
                            @else
                                <form class="inline-form" method="post" action="{{ route('admin.devices.unblock', $device) }}">
                                    @csrf
                                    <button class="link" type="submit">Reinstate</button>
                                </form>
                            @endif
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $devices->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
