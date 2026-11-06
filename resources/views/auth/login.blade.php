@extends('layouts.app')

@section('title', '로그인')

@section('main-class', 'narrow')

@section('content')
    <h1>로그인</h1>

    @if ($requestingClient)
        {{-- The OAuth flow bounced here, so say so: an unexplained login form is
             what makes people type their credentials into the wrong place. --}}
        <p class="lead"><strong>{{ $requestingClient }}</strong>에 로그인하려고 합니다.</p>
    @else
        <p class="lead">하나의 계정으로 모든 사내 도구에 로그인합니다.</p>
    @endif

    <form class="card" method="post" action="{{ route('login.store') }}@if (! empty($next))?next={{ urlencode($next) }}@endif">
        @csrf
        <label for="username">아이디</label>
        <input id="username" type="text" name="username" value="{{ old('username') }}" required autofocus
               autocomplete="username" autocapitalize="none" spellcheck="false">

        <label for="password">비밀번호</label>
        <input id="password" type="password" name="password" required autocomplete="current-password">

        <label class="row" style="margin-top:16px;font-weight:normal">
            <input type="checkbox" name="remember" value="1" style="width:auto" checked>
            <span>이 브라우저에서 로그인 유지</span>
        </label>

        <div class="form-actions" style="margin-top:20px">
            <button class="primary" type="submit" style="flex:1;justify-content:center">로그인</button>
        </div>
    </form>

    <p class="small muted" style="text-align:center">
        계정이 없나요? <a href="{{ route('register') }}">가입하기</a>
        · 비밀번호를 잊었다면 관리자에게 재설정 링크를 요청하세요.
    </p>
@endsection
