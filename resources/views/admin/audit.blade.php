@extends('layouts.app')
@use('App\Support\When')
@use('App\Support\AuditPresenter')

@section('title', '활동 기록')

@section('content')
    <div class="page-head">
        <div>
            <h1>활동 기록</h1>
            <p class="lead">
                @if ($person)
                    <a href="{{ route('admin.users.show', $person) }}">{{ $person->name }}</a> 님과 관련된 기록입니다.
                    <a class="small" href="{{ route('admin.audit.index', array_filter(['kind' => $kind ?: null])) }}">모든 사람 보기</a>
                @else
                    로그인, 계정 변경, 앱 토큰 — 보안에 관련된 일은 모두 여기에 남습니다.
                @endif
            </p>
        </div>
    </div>

    <div class="toolbar">
        <form method="get" action="{{ route('admin.audit.index') }}" class="row">
            @if ($kind)<input type="hidden" name="kind" value="{{ $kind }}">@endif
            <select name="user" data-autosubmit style="width:auto;min-width:200px" aria-label="사람">
                <option value="">모든 사람</option>
                @foreach ($everyone as $u)
                    <option value="{{ $u->id }}" @selected($person?->id === $u->id)>{{ $u->name }} ({{ $u->username }})</option>
                @endforeach
            </select>
            <noscript><button type="submit">보기</button></noscript>
        </form>
        <div class="chips">
            <a @class(['chip', 'active' => $kind === '']) href="{{ route('admin.audit.index', array_filter(['user' => $person?->id])) }}">전체</a>
            @foreach (AuditPresenter::CATEGORIES as $key => [$label])
                <a @class(['chip', 'active' => $kind === $key]) href="{{ route('admin.audit.index', array_filter(['kind' => $key, 'user' => $person?->id])) }}">{{ $label }}</a>
            @endforeach
        </div>
    </div>

    <div class="card" style="padding-top:8px">
        @if ($logs->isEmpty())
            <p class="empty">기록이 없습니다.</p>
        @else
            <table class="list">
                <thead><tr><th>언제</th><th>무슨 일</th><th>누가</th><th class="hide-sm">대상 / 내용</th><th class="hide-sm">IP</th></tr></thead>
                <tbody>
                @foreach ($logs as $log)
                    @php($tone = AuditPresenter::tone($log->event))
                    @php($subject = AuditPresenter::subject($log, $people, $clients))
                    @php($detail = AuditPresenter::detail($log, $clients))
                    <tr>
                        <td class="small" style="white-space:nowrap">
                            {{ When::at($log->created_at, 'm-d H:i') }}
                            <div class="sub">{{ When::ago($log->created_at) }}</div>
                        </td>
                        <td>
                            <span @class(['event', 'badge '.$tone => $tone !== ''])>{{ AuditPresenter::label($log->event) }}</span>
                            <details class="raw">
                                <summary>{{ $log->event }}</summary>
                                <pre>{{ json_encode(array_filter(['actor' => $log->actor_type.':'.$log->actor_id, 'subject' => $log->subject_type ? $log->subject_type.':'.$log->subject_id : null, 'meta' => $log->meta, 'agent' => $log->user_agent]), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
                            </details>
                        </td>
                        <td class="small">
                            @if (in_array($log->actor_type, ['user', 'admin'], true) && isset($people[$log->actor_id]))
                                <a href="{{ route('admin.audit.index', ['user' => $log->actor_id]) }}">{{ AuditPresenter::actor($log, $people) }}</a>
                            @else
                                {{ AuditPresenter::actor($log, $people) }}
                            @endif
                        </td>
                        <td class="small hide-sm">
                            @if ($subject){{ $subject }}@endif
                            @if ($detail !== '')<div class="sub">{{ $detail }}</div>@endif
                        </td>
                        <td class="mono small hide-sm">{{ $log->ip }}</td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $logs->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
