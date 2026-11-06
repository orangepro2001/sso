@extends('layouts.app')

@section('title', $client->name)

@section('content')
    <a class="back" href="{{ route('admin.clients.index') }}">‹ 연결된 앱</a>
    <h1>{{ $client->name }}</h1>
    <p class="lead mono">{{ $client->client_id }}</p>

    <form class="card" method="post" action="{{ route('admin.clients.update', $client) }}">
        @csrf
        @method('put')

        <label for="name">앱 이름</label>
        <input id="name" type="text" name="name" value="{{ old('name', $client->name) }}" required>

        <label for="type">종류</label>
        <select id="type" name="type">
            <option value="public" @selected(old('type', $client->type) === 'public')>public — PKCE 필수</option>
            <option value="confidential" @selected(old('type', $client->type) === 'confidential')>confidential — 시크릿 사용</option>
        </select>

        <label for="redirect_uris">리디렉션 URI <span class="muted small">(한 줄에 하나, 정확히 일치해야 함)</span></label>
        <textarea id="redirect_uris" name="redirect_uris">{{ old('redirect_uris', implode("\n", $client->redirect_uris ?? [])) }}</textarea>


        <label for="home_url">홈 주소 <span class="muted small">(사람이 여는 주소; 비우면 시작 화면에 안 보임)</span></label>
        <input id="home_url" type="url" name="home_url" maxlength="500"
               value="{{ old('home_url', $client->home_url) }}" placeholder="https://report.521985.xyz">

        <label for="sort_order">시작 화면 순서</label>
        <input id="sort_order" type="number" name="sort_order" min="0" max="999" value="{{ old('sort_order', $client->sort_order ?? 0) }}">

        <label class="row" style="margin-top:12px">
            <input type="checkbox" name="in_launcher" value="1" style="width:auto" @checked(old('in_launcher', $client->in_launcher ?? true))>
            <span>시작 화면에 표시</span>
        </label>

        <label>허용 범위 (scope)</label>
        @foreach ($scopes as $scope)
            <label class="row" style="margin:4px 0">
                <input type="checkbox" name="allowed_scopes[]" value="{{ $scope }}" style="width:auto"
                       @checked(in_array($scope, old('allowed_scopes', $client->allowed_scopes ?? []), true))>
                <span class="mono small">{{ $scope }}</span>
            </label>
        @endforeach

        <label class="row" style="margin-top:14px">
            <input type="checkbox" name="active" value="1" style="width:auto" @checked(old('active', $client->active))>
            <span>사용 중</span>
        </label>

        <label class="row" style="margin-top:10px">
            <input type="checkbox" name="rotate_secret" value="1" style="width:auto">
            <span>시크릿 새로 발급 (confidential 앱만, 한 번만 보임 — 앱 설정도 바꿔야 합니다)</span>
        </label>

        <label for="note">메모</label>
        <textarea id="note" name="note">{{ old('note', $client->note) }}</textarea>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">저장</button>
            <a class="btn" href="{{ route('admin.clients.index') }}">목록으로</a>
        </div>
    </form>

    <h2>연동 정보</h2>
    <div class="card">
        <pre>issuer        {{ rtrim(config('sso.issuer'), '/') }}
discovery     {{ rtrim(config('sso.issuer'), '/') }}/.well-known/openid-configuration
authorize     {{ rtrim(config('sso.issuer'), '/') }}/oauth/authorize
token         {{ rtrim(config('sso.issuer'), '/') }}/oauth/token
userinfo      {{ rtrim(config('sso.issuer'), '/') }}/oauth/userinfo
introspect    {{ rtrim(config('sso.issuer'), '/') }}/oauth/introspect
redirect_uri  {{ ($client->redirect_uris ?? [])[0] ?? '(등록 안 됨)' }}
scopes        {{ implode(' ', $client->allowed_scopes ?? []) }}</pre>
    </div>
@endsection
