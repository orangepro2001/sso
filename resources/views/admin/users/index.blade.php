@extends('layouts.app')

@section('title', 'Users')

@section('content')
    <h1>Users</h1>
    <p class="lead">Accounts exist only because an administrator created them. There is no registration endpoint.</p>

    <div class="row" style="margin-bottom:16px">
        <a class="btn primary" href="{{ route('admin.users.create') }}">New user</a>
        <form method="get" action="{{ route('admin.users.index') }}" class="row" style="margin-left:auto">
            <input type="text" name="q" value="{{ $search }}" placeholder="Search name or e-mail" style="width:260px">
            <button type="submit">Search</button>
        </form>
    </div>

    <div class="card">
        @if ($users->isEmpty())
            <p class="empty">No users yet.</p>
        @else
            <table>
                <thead><tr><th>Name</th><th>E-mail</th><th>Status</th><th>Last login</th><th>Created</th><th></th></tr></thead>
                <tbody>
                @foreach ($users as $user)
                    <tr>
                        <td>{{ $user->name }}</td>
                        <td class="mono small">{{ $user->email }}</td>
                        <td>
                            @if ($user->isActive())
                                <span class="badge ok">active</span>
                            @else
                                <span class="badge bad">disabled</span>
                            @endif
                        </td>
                        <td class="small muted">{{ $user->last_login_at?->diffForHumans() ?? 'never' }}</td>
                        <td class="small muted">{{ $user->created_at?->format('Y-m-d') }}</td>
                        <td><a href="{{ route('admin.users.edit', $user) }}">Edit</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $users->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
