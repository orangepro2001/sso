@extends('layouts.app')
@use('App\Support\When')

@section('title', '내 계정')

@section('content')
    <div class="page-head">
        <div>
            <h1>내 계정</h1>
            <p class="lead">여기서 바꾼 이름과 사진은 모든 앱에 반영됩니다 (앱에 다시 로그인하면 바로 보입니다).</p>
        </div>
    </div>

    <div class="split">
        <div class="stack">
            <form class="card" method="post" action="{{ route('account.update') }}">
                @csrf
                @method('put')
                <h2 class="card__title">프로필</h2>

                <label for="name">이름</label>
                <input id="name" type="text" name="name" value="{{ old('name', $user->name) }}" required maxlength="120">
                <div class="hint">앱에 표시되는 이름입니다. 직급을 붙여도 됩니다.</div>

                <label for="username">아이디</label>
                <input id="username" type="text" name="username" value="{{ old('username', $user->username) }}" required
                       autocapitalize="none" spellcheck="false" autocomplete="username">

                <label for="current_password_profile">현재 비밀번호 <span class="muted small">(아이디를 바꿀 때만)</span></label>
                <input id="current_password_profile" type="password" name="current_password" autocomplete="current-password">
                @error('current_password')<div class="field-error">{{ $message }}</div>@enderror

                <div class="form-actions">
                    <button class="primary" type="submit">저장</button>
                </div>
            </form>

            <form class="card" method="post" action="{{ route('account.password') }}">
                @csrf
                <h2 class="card__title">비밀번호 변경</h2>
                <p class="card__hint">바꾸면 이 브라우저를 뺀 모든 기기와 앱에서 로그아웃됩니다.</p>

                <label for="current_password">현재 비밀번호</label>
                <input id="current_password" type="password" name="current_password" required autocomplete="current-password">

                <label for="password">새 비밀번호</label>
                <input id="password" type="password" name="password" required autocomplete="new-password">

                <label for="password_confirmation">새 비밀번호 확인</label>
                <input id="password_confirmation" type="password" name="password_confirmation" required autocomplete="new-password">

                <div class="form-actions">
                    <button class="primary" type="submit">비밀번호 변경</button>
                </div>
            </form>
        </div>

        <div class="stack">
            <section class="card">
                <h2 class="card__title">프로필 사진</h2>
                <p class="card__hint">업무일보의 담당자 표시 등에 쓰입니다.</p>
                @include('partials.avatar-upload', [
                    'user' => $user,
                    'action' => route('account.avatar'),
                    'removeAction' => route('account.avatar.remove'),
                ])
            </section>

            <section class="card">
                <h2 class="card__title">로그인 중인 앱</h2>
                @if ($signedIn->isEmpty())
                    <p class="empty" style="padding-bottom:0">지금 로그인해 있는 앱이 없습니다.</p>
                @else
                    <ul class="rows">
                        @foreach ($signedIn as $token)
                            <li>
                                <div class="grow">
                                    <strong>{{ $token->client?->name ?? $token->client_id ?? '알 수 없는 앱' }}</strong>
                                    <div class="sub">{{ $token->issued_ip }} · {{ When::at($token->expires_at, 'm-d H:i') }}까지</div>
                                </div>
                                <div class="when">{{ When::ago($token->created_at) }}</div>
                            </li>
                        @endforeach
                    </ul>
                @endif
                <form method="post" action="{{ route('account.tokens') }}" style="margin-top:12px"
                      data-confirm="모든 앱과 다른 브라우저에서 로그아웃할까요? 이 브라우저는 유지됩니다.">
                    @csrf
                    @method('delete')
                    <button type="submit">모든 곳에서 로그아웃</button>
                </form>
                <p class="hint">모르는 기록이 있으면 비밀번호를 바꾸고 관리자에게 알려 주세요.</p>
            </section>

            <section class="card">
                <h2 class="card__title">최근 로그인</h2>
                <dl class="kv">
                    <dt>언제</dt><dd>{{ When::at($user->last_login_at) }}</dd>
                    <dt>어디서</dt><dd class="mono">{{ $user->last_login_ip ?? '—' }}</dd>
                    <dt>권한</dt><dd>{{ $user->isSuperAdmin() ? '관리자' : '일반' }}</dd>
                </dl>
            </section>
        </div>
    </div>
@endsection
