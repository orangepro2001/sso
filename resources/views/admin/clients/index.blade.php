@extends('layouts.app')

@section('title', 'OAuth clients')

@section('content')
    <h1>OAuth clients</h1>
    <p class="lead">Registering a client here <em>is</em> the consent step: users never see a consent screen.</p>

    <div class="row" style="margin-bottom:16px">
        <a class="btn primary" href="{{ route('admin.clients.create') }}">New client</a>
    </div>

    <div class="card">
        @if ($clients->isEmpty())
            <p class="empty">No clients registered.</p>
        @else
            <table>
                <thead><tr><th>Name</th><th>Client ID</th><th>Type</th><th>Scopes</th><th>Active</th><th></th></tr></thead>
                <tbody>
                @foreach ($clients as $client)
                    <tr>
                        <td>{{ $client->name }}</td>
                        <td class="mono small">{{ $client->client_id }}</td>
                        <td><span class="badge">{{ $client->type }}</span></td>
                        <td class="small mono">{{ implode(' ', $client->allowed_scopes ?? []) }}</td>
                        <td>
                            @if ($client->active)
                                <span class="badge ok">yes</span>
                            @else
                                <span class="badge bad">no</span>
                            @endif
                        </td>
                        <td><a href="{{ route('admin.clients.edit', $client) }}">Edit</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $clients->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
