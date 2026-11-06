@extends('layouts.app')

@section('title', '계정 센터')

@section('main-class', $user ? '' : 'narrow')

@section('content')
    @if ($user)
        <div class="card">
            <div class="profile-head">
                @include('partials.avatar', ['user' => $user, 'size' => 'lg'])
                <div>
                    <h1>{{ $user->name }} 님, 안녕하세요</h1>
                    <div class="meta"><span class="mono">{{ $user->username }}</span>@if ($user->isSuperAdmin()) · <span class="badge admin">관리자</span>@endif</div>
                </div>
            </div>
            <div class="quick">
                @if ($pending)
                    <a class="btn primary" href="{{ route('oauth.authorize', $pending) }}">하던 로그인 계속하기</a>
                @endif
                <a class="btn" href="{{ route('account') }}">내 계정 (사진·비밀번호)</a>
                @if ($user->isSuperAdmin())
                    <a class="btn" href="{{ route('admin.users.index') }}">사용자 관리</a>
                @endif
            </div>
        </div>

        @if ($apps->isNotEmpty())
            <h2>내 앱</h2>
            <div class="apps">
                @foreach ($apps as $app)
                    <a class="app" href="{{ $app->home_url }}">
                        <span class="app__name">{{ $app->name }}</span>
                        @if ($app->note)
                            <span class="app__note">{{ \Illuminate\Support\Str::limit($app->note, 90) }}</span>
                        @endif
                        <span class="app__go">열기 →</span>
                    </a>
                @endforeach
            </div>
            <p class="hint">모두 이 계정으로 로그인합니다. 앱마다 비밀번호를 따로 만들 필요가 없습니다.</p>
        @endif
    @else
        <h1>계정 센터</h1>
        <p class="lead">하나의 계정으로 모든 사내 도구에 로그인합니다.</p>
        <div class="card">
            <div class="form-actions" style="margin-top:0">
                <a class="btn primary" href="{{ route('login') }}">로그인</a>
                <a class="btn" href="{{ route('register') }}">가입하기</a>
            </div>
        </div>
    @endif
@endsection
