@extends('layouts.app')

@section('title', '가입')

@section('main-class', 'narrow')

@section('content')
    <h1>가입</h1>
    <p class="lead">만든 계정으로 바로 사내 도구에 로그인할 수 있습니다.</p>

    <form class="card" method="post" action="{{ route('register.store') }}">
        @csrf

        <label for="name">이름</label>
        <input id="name" type="text" name="name" value="{{ old('name') }}" required maxlength="120" autofocus
               placeholder="예: 채길용 사원">
        <div class="hint">앱에 표시되는 이름입니다. 직급을 붙여도 됩니다.</div>

        <label for="username">아이디</label>
        <input id="username" type="text" name="username" value="{{ old('username') }}" required
               minlength="3" maxlength="64" autocapitalize="none" spellcheck="false" autocomplete="username"
               placeholder="예: chae-gilyong">
        <div class="hint">로그인할 때 씁니다. 영문 소문자·숫자와 . _ - (3자 이상)</div>

        <label for="password">비밀번호</label>
        <input id="password" type="password" name="password" required autocomplete="new-password">

        <label for="password_confirmation">비밀번호 확인</label>
        <input id="password_confirmation" type="password" name="password_confirmation" required
               autocomplete="new-password">

        <div class="form-actions" style="margin-top:20px">
            <button class="primary" type="submit">가입하기</button>
            <a class="btn" href="{{ route('login') }}">이미 계정이 있어요</a>
        </div>
    </form>
@endsection
