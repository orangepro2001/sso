@extends('layouts.app')

@section('title', '연결된 앱')

@section('content')
    <div class="page-head">
        <div>
            <h1>연결된 앱</h1>
            <p class="lead">이 계정으로 로그인하는 앱입니다. 여기 등록하는 것이 곧 허락이라, 사용자에게 따로 동의 화면이 뜨지 않습니다.</p>
        </div>
        <a class="btn primary" href="{{ route('admin.clients.create') }}">+ 앱 연결</a>
    </div>

    <div class="card" style="padding-top:8px">
        @if ($clients->isEmpty())
            <p class="empty">연결된 앱이 없습니다.</p>
        @else
            <table class="list">
                <thead><tr><th>앱</th><th class="hide-sm">클라이언트 ID</th><th>종류</th><th>상태</th><th></th></tr></thead>
                <tbody>
                @foreach ($clients as $client)
                    <tr data-href="{{ route('admin.clients.edit', $client) }}" @class(['is-off' => ! $client->active])>
                        <td>
                            <a href="{{ route('admin.clients.edit', $client) }}"><strong>{{ $client->name }}</strong></a>
                            @if ($client->home_url)<div class="sub">{{ $client->home_url }}</div>@endif
                        </td>
                        <td class="mono small hide-sm">{{ $client->client_id }}</td>
                        <td><span class="badge">{{ $client->type }}</span></td>
                        <td>
                            @if ($client->active)
                                <span class="badge ok dot">사용 중</span>
                            @else
                                <span class="badge bad dot">중지</span>
                            @endif
                        </td>
                        <td class="right"><span class="go" aria-hidden="true">›</span></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $clients->links('vendor.pagination.simple') }}
        @endif
    </div>
@endsection
