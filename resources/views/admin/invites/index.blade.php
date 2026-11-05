@extends('layouts.app')

@section('title', 'Invites')

@section('content')
    <h1>Registration invites</h1>
    <p class="lead">One-time codes for people who need an account. Each code is single use, expires in 30 days, and can be revoked.</p>

    @if (session('invite_url'))
        <div class="flash ok">
            <strong>Hand this link over — it is shown once:</strong><br>
            <code class="mono">{{ session('invite_url') }}</code>
        </div>
    @endif

    <form class="card" method="post" action="{{ route('admin.invites.store') }}" style="margin-bottom:16px">
        @csrf
        <label for="note">Who is it for? (optional, shown on the form)</label>
        <div class="row">
            <input id="note" type="text" name="note" maxlength="120" placeholder="e.g. 채길용" style="flex:1">
            <button class="btn primary" type="submit">Create invite</button>
        </div>
    </form>

    <div class="card">
        @if ($invites->isEmpty())
            <p class="empty">No invites yet.</p>
        @else
            <table>
                <thead><tr><th>Note</th><th>State</th><th>Created</th><th>Expires</th><th>Used by</th><th></th></tr></thead>
                <tbody>
                @foreach ($invites as $invite)
                    <tr>
                        <td>{{ $invite->note ?: '—' }}</td>
                        <td>
                            @if ($invite->isUsable())
                                <span class="badge ok">unused</span>
                            @elseif ($invite->used_at)
                                <span class="badge">used</span>
                            @else
                                <span class="badge bad">{{ $invite->reason() }}</span>
                            @endif
                        </td>
                        <td class="small muted">{{ $invite->created_at?->format('Y-m-d') }}</td>
                        <td class="small muted">{{ $invite->expires_at?->format('Y-m-d') }}</td>
                        <td class="small muted">{{ $invite->user?->username ?? '—' }}</td>
                        <td>
                            @if ($invite->isUsable())
                                <form method="post" action="{{ route('admin.invites.destroy', $invite) }}">
                                    @csrf @method('DELETE')
                                    <button class="small" type="submit">Revoke</button>
                                </form>
                            @endif
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $invites->links() }}
        @endif
    </div>
@endsection
