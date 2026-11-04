@extends('layouts.app')

@section('title', 'Blacklist')

@section('content')
    <h1>Blacklist</h1>
    <p class="lead">
        Checked on every introspection and on every token resolution. Guest tokens have no expiry, so this
        is the switch that actually turns them off.
    </p>

    <form class="card" method="post" action="{{ route('admin.blacklist.store') }}">
        @csrf
        <div class="grid">
            <div>
                <label for="kind">Kind</label>
                <select id="kind" name="kind">
                    <option value="device">device — guest device_id</option>
                    <option value="user">user — user id</option>
                    <option value="token">token — jti</option>
                    <option value="client">client — client_id</option>
                </select>
            </div>
            <div>
                <label for="value">Value</label>
                <input id="value" type="text" name="value" required placeholder="hostname, 42, uuid, sso_...">
            </div>
        </div>

        <label for="reason">Reason</label>
        <input id="reason" type="text" name="reason">

        <div class="row" style="margin-top:16px">
            <button class="primary" type="submit">Add entry</button>
        </div>
    </form>

    <div class="card">
        @if ($entries->isEmpty())
            <p class="empty">The blacklist is empty.</p>
        @else
            <table>
                <thead><tr><th>Kind</th><th>Value</th><th>Reason</th><th>Added</th><th>By</th><th></th></tr></thead>
                <tbody>
                @foreach ($entries as $entry)
                    <tr>
                        <td><span class="badge bad">{{ $entry->kind }}</span></td>
                        <td class="mono small">{{ $entry->value }}</td>
                        <td class="small">{{ $entry->reason }}</td>
                        <td class="small muted">{{ $entry->created_at?->format('Y-m-d H:i') }}</td>
                        <td class="small muted">{{ $entry->created_by ?? '—' }}</td>
                        <td>
                            <form class="inline-form" method="post" action="{{ route('admin.blacklist.destroy', $entry) }}">
                                @csrf
                                @method('delete')
                                <button class="link" type="submit">Remove</button>
                            </form>
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $entries->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
