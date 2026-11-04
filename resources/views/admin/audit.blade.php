@extends('layouts.app')

@section('title', 'Audit log')

@section('content')
    <h1>Audit log</h1>
    <p class="lead">Append-only trail of every security relevant event.</p>

    <form method="get" action="{{ route('admin.audit.index') }}" class="row" style="margin-bottom:16px">
        <input type="text" name="event" value="{{ $event }}" placeholder="prefix, e.g. guest. or admin." style="width:280px">
        <button type="submit">Filter</button>
        @if ($event !== '')
            <a class="btn" href="{{ route('admin.audit.index') }}">Clear</a>
        @endif
    </form>

    <div class="card">
        @if ($logs->isEmpty())
            <p class="empty">No entries.</p>
        @else
            <table>
                <thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Subject</th><th>IP</th><th>Meta</th></tr></thead>
                <tbody>
                @foreach ($logs as $log)
                    <tr>
                        <td class="small muted" style="white-space:nowrap">{{ $log->created_at?->format('m-d H:i:s') }}</td>
                        <td class="mono small">{{ $log->event }}</td>
                        <td class="small">{{ $log->actor_type }}{{ $log->actor_id ? ':'.$log->actor_id : '' }}</td>
                        <td class="small mono">{{ $log->subject_type }}{{ $log->subject_id ? ':'.$log->subject_id : '' }}</td>
                        <td class="mono small">{{ $log->ip }}</td>
                        <td class="mono small">{{ $log->meta ? json_encode($log->meta, JSON_UNESCAPED_SLASHES) : '' }}</td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $logs->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
