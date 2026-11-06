@extends('layouts.app')

@section('title', '앱 연결')

@section('content')
    <a class="back" href="{{ route('admin.clients.index') }}">‹ 연결된 앱</a>
    <h1>앱 연결</h1>
    <p class="lead">이 계정으로 로그인할 앱을 등록합니다. 서버에서 도는 앱은 <strong>confidential</strong>(시크릿 발급), 브라우저·CLI 앱은 <strong>public</strong>(PKCE 필수)입니다.</p>

    <form class="card" method="post" action="{{ route('admin.clients.store') }}">
        @csrf
        <label for="name">앱 이름</label>
        <input id="name" type="text" name="name" value="{{ old('name') }}" required autofocus>

        <label for="type">종류</label>
        <select id="type" name="type">
            <option value="public" @selected(old('type') === 'public')>public — 브라우저 / CLI / 앱, PKCE 필수</option>
            <option value="confidential" @selected(old('type') === 'confidential')>confidential — 서버에서 도는 앱, 시크릿 발급</option>
        </select>

        <label for="redirect_uris">리디렉션 URI <span class="muted small">(한 줄에 하나, 정확히 일치해야 함)</span></label>
        <textarea id="redirect_uris" name="redirect_uris" placeholder="https://example.internal/auth/callback">{{ old('redirect_uris') }}</textarea>


        <label for="home_url">홈 주소 <span class="muted small">(사람이 여는 주소; 비우면 시작 화면에 안 보임)</span></label>
        <input id="home_url" type="url" name="home_url" maxlength="500"
               value="{{ old('home_url') }}" placeholder="https://report.521985.xyz">

        <label for="sort_order">시작 화면 순서</label>
        <input id="sort_order" type="number" name="sort_order" min="0" max="999" value="{{ old('sort_order', 0) }}">

        <label class="row" style="margin-top:12px">
            <input type="checkbox" name="in_launcher" value="1" style="width:auto" @checked(old('in_launcher', true))>
            <span>시작 화면에 표시</span>
        </label>

        <label>허용 범위 (scope)</label>
        @foreach ($scopes as $scope)
            <label class="row" style="margin:4px 0">
                <input type="checkbox" name="allowed_scopes[]" value="{{ $scope }}" style="width:auto"
                       @checked(in_array($scope, old('allowed_scopes', ['openid', 'profile', 'email']), true))>
                <span class="mono small">{{ $scope }}</span>
            </label>
        @endforeach

        <label class="row" style="margin-top:14px">
            <input type="checkbox" name="active" value="1" style="width:auto" @checked(old('active', true))>
            <span>사용 중</span>
        </label>

        <label for="note">메모</label>
        <textarea id="note" name="note">{{ old('note') }}</textarea>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">등록</button>
            <a class="btn" href="{{ route('admin.clients.index') }}">취소</a>
        </div>
    </form>
@endsection
