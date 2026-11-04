@extends('layouts.app')

@section('title', 'Tokens')

@section('content')
    <h1>Access tokens</h1>
    <p class="lead">What is live right now. Revoking here takes effect on the next introspection.</p>

    <div class="row" style="margin-bottom:16px">
        <a class="btn {{ $subject === 'all' ? 'primary' : '' }}" href="{{ route('admin.tokens.index') }}">All</a>
        <a class="btn {{ $subject === 'user' ? 'primary' : '' }}" href="{{ route('admin.tokens.index', ['subject' => 'user']) }}">Users</a>
        <a class="btn {{ $subject === 'guest' ? 'primary' : '' }}" href="{{ route('admin.tokens.index', ['subject' => 'guest']) }}">Guests</a>
        <a class="btn {{ $subject === 'client' ? 'primary' : '' }}" href="{{ route('admin.tokens.index', ['subject' => 'client']) }}">Clients</a>
    </div>

    <div class="card">
        @if ($tokens->isEmpty())
            <p class="empty">No tokens.</p>
        @else
            <table>
                <thead><tr><th>Subject</th><th>Kind</th><th>Client</th><th>Scopes</th><th>Expires</th><th>State</th><th></th></tr></thead>
                <tbody>
                @foreach ($tokens as $token)
                    <tr>
                        <td class="mono small">
                            @if ($token->guestDevice)
                                <a href="{{ route('admin.devices.show', $token->guestDevice) }}">{{ $token->guestDevice->device_id }}</a>
                            @elseif ($token->user)
                                {{ $token->user->username }}
                            @else
                                {{ $token->client_id }}
                            @endif
                        </td>
                        <td class="small">{{ $token->kind }}</td>
                        <td class="mono small">{{ $token->client_id ?? '—' }}</td>
                        <td class="mono small">{{ implode(' ', $token->scopes ?? []) }}</td>
                        <td class="small">{{ $token->expires_at?->format('Y-m-d H:i') ?? 'never' }}</td>
                        <td>
                            @if ($token->isActive())
                                <span class="badge ok">live</span>
                            @else
                                <span class="badge bad">dead</span>
                            @endif
                        </td>
                        <td>
                            @if ($token->revoked_at === null)
                                <form class="inline-form" method="post" action="{{ route('admin.tokens.revoke', $token) }}">
                                    @csrf
                                    <button class="link" type="submit">Revoke</button>
                                </form>
                            @endif
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $tokens->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
