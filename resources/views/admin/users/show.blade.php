@extends('layouts.app')
@use('App\Support\When')
@use('App\Support\AuditPresenter')

@section('title', $user->name)

@section('content')
    <a class="back" href="{{ route('admin.users.index') }}">‹ 사용자 목록</a>

    {{-- Who this is, and the four things done most often: one click each. --}}
    <section class="card">
        <div class="profile-head">
            @include('partials.avatar', ['user' => $user, 'size' => 'lg'])
            <div style="min-width:0">
                <h1>
                    {{ $user->name }}
                    @if ($user->isSuperAdmin())<span class="badge admin">관리자</span>@endif
                    @if (! $user->isActive())<span class="badge bad dot">비활성</span>@endif
                    @if ($self)<span class="badge">나</span>@endif
                </h1>
                <div class="meta">
                    <span class="mono">{{ $user->username }}</span>
                    · 가입 {{ When::at($user->created_at, 'Y-m-d') }}
                    · 마지막 로그인 <span title="{{ When::at($user->last_login_at) }}">{{ When::ago($user->last_login_at, '없음') }}</span>
                    @if ($user->last_login_ip)<span class="mono">({{ $user->last_login_ip }})</span>@endif
                </div>
            </div>
        </div>

        <div class="quick">
            @if (! $self)
                <form method="post" action="{{ route('admin.users.role', $user) }}"
                      data-confirm="{{ $user->isSuperAdmin() ? $user->name.' 님의 관리자 권한을 내릴까요?' : $user->name.' 님을 관리자로 지정할까요? 이 콘솔에서 모든 계정을 바꿀 수 있게 됩니다.' }}">
                    @csrf
                    <input type="hidden" name="role" value="{{ $user->isSuperAdmin() ? 'user' : 'super_admin' }}">
                    <button type="submit">{{ $user->isSuperAdmin() ? '일반 사용자로 변경' : '관리자로 지정' }}</button>
                </form>

                <form method="post" action="{{ route('admin.users.status', $user) }}"
                      @if ($user->isActive()) data-confirm="{{ $user->name }} 님의 계정을 비활성화할까요? 모든 앱과 브라우저에서 즉시 로그아웃되고 다시 로그인할 수 없습니다." @endif>
                    @csrf
                    <input type="hidden" name="status" value="{{ $user->isActive() ? 'disabled' : 'active' }}">
                    @if ($user->isActive())
                        <button class="danger" type="submit">비활성화</button>
                    @else
                        <button class="primary" type="submit">다시 활성화</button>
                    @endif
                </form>
            @endif

            <a class="btn" href="#password">비밀번호 재설정</a>

            <form method="post" action="{{ route('admin.users.sign-out', $user) }}"
                  data-confirm="{{ $user->name }} 님을 모든 앱과 브라우저에서 로그아웃시킬까요?{{ $self ? ' (지금 이 브라우저는 유지됩니다)' : '' }}">
                @csrf
                <button type="submit">모든 곳에서 로그아웃</button>
            </form>

            <a class="btn" href="{{ route('admin.audit.index', ['user' => $user->id]) }}">활동 기록</a>
        </div>
    </section>

    <div class="split">
        <div class="stack">
            <form class="card" method="post" action="{{ route('admin.users.update', $user) }}">
                @csrf
                @method('put')
                <h2 class="card__title">기본 정보</h2>

                <label for="name">이름</label>
                <input id="name" type="text" name="name" value="{{ old('name', $user->name) }}" required maxlength="120">
                <div class="hint">앱에 표시되는 이름입니다. 직급을 붙여도 됩니다.</div>

                <label for="username">아이디</label>
                <input id="username" type="text" name="username" value="{{ old('username', $user->username) }}" required
                       autocapitalize="none" spellcheck="false" autocomplete="off">
                <div class="hint">로그인할 때 쓰는 이름입니다. 바꾸면 다음 로그인부터 새 아이디를 써야 합니다.</div>

                <label for="note">메모 <span class="muted small">(관리자만 봅니다)</span></label>
                <textarea id="note" name="note" rows="3" style="font-family:inherit;font-size:var(--text-md)">{{ old('note', $user->note) }}</textarea>

                <div class="form-actions">
                    <button class="primary" type="submit">저장</button>
                </div>
            </form>

            <section class="card" id="password">
                <h2 class="card__title">비밀번호</h2>
                <p class="card__hint">새 비밀번호를 정해서 알려 주거나, 링크를 보내 본인이 정하게 하세요. 어느 쪽이든 이 사람은 모든 앱에서 로그아웃됩니다.</p>

                <form method="post" action="{{ route('admin.users.password', $user) }}"
                      data-confirm="{{ $user->name }} 님의 비밀번호를 바꿀까요? 모든 앱에서 로그아웃됩니다.">
                    @csrf
                    <label for="new-password">새 비밀번호</label>
                    <div class="input-row">
                        <input id="new-password" type="password" name="password" autocomplete="new-password" placeholder="비워 두면 자동으로 만듭니다">
                        <button type="button" data-reveal="#new-password">보기</button>
                    </div>
                    <div class="form-actions">
                        <button class="primary" type="submit">비밀번호 설정</button>
                        <span class="hint" style="margin:0">설정한 비밀번호는 다음 화면 맨 위에 한 번 보입니다.</span>
                    </div>
                </form>

                <div class="or">또는</div>

                <form method="post" action="{{ route('admin.users.reset-link', $user) }}">
                    @csrf
                    <div class="form-actions" style="margin-top:0">
                        <button type="submit">재설정 링크 만들기</button>
                        <span class="hint" style="margin:0">한 번만 쓰는 링크, 24시간 유효. 메신저로 보내면 본인이 새 비밀번호를 정합니다.</span>
                    </div>
                </form>
            </section>

            @unless ($self)
                <form class="card danger-zone" method="post" action="{{ route('admin.users.destroy', $user) }}">
                    @csrf
                    @method('delete')
                    <h2 class="card__title">계정 삭제</h2>
                    <p class="card__hint">
                        되돌릴 수 없습니다. 보통은 <strong>비활성화</strong>로 충분합니다 — 로그인만 막고 기록은 남습니다.
                        삭제해도 각 앱에 남은 작성 기록은 지워지지 않습니다.
                    </p>
                    <label for="confirm">확인을 위해 아이디 <span class="mono">{{ $user->username }}</span> 를 입력하세요</label>
                    <input id="confirm" type="text" name="confirm" data-match="{{ $user->username }}" autocomplete="off" autocapitalize="none" spellcheck="false">
                    <div class="form-actions">
                        <button class="danger solid" type="submit">영구 삭제</button>
                    </div>
                </form>
            @endunless
        </div>

        <div class="stack">
            <section class="card">
                <h2 class="card__title">프로필 사진</h2>
                <p class="card__hint">앱의 담당자 표시 등에 쓰입니다.</p>
                @include('partials.avatar-upload', [
                    'user' => $user,
                    'action' => route('admin.users.avatar', $user),
                    'removeAction' => route('admin.users.avatar.remove', $user),
                ])
            </section>

            <section class="card">
                <h2 class="card__title">로그인 중인 앱</h2>
                @if ($tokens->isEmpty())
                    <p class="empty" style="padding-bottom:0">지금 로그인해 있는 앱이 없습니다.</p>
                @else
                    <ul class="rows">
                        @foreach ($tokens as $token)
                            <li>
                                <div class="grow">
                                    <div><strong>{{ $token->client?->name ?? $token->client_id ?? '알 수 없는 앱' }}</strong></div>
                                    <div class="sub">{{ $token->issued_ip ?? '' }} {{ \Illuminate\Support\Str::limit((string) $token->user_agent, 60) }}</div>
                                </div>
                                <div class="when" title="만료 {{ When::at($token->expires_at) }}">{{ When::ago($token->created_at) }}</div>
                            </li>
                        @endforeach
                    </ul>
                @endif
            </section>

            <section class="card">
                <div class="row" style="justify-content:space-between">
                    <h2 class="card__title">최근 활동</h2>
                    <a class="small" href="{{ route('admin.audit.index', ['user' => $user->id]) }}">전체 보기 ›</a>
                </div>
                @if ($activity->isEmpty())
                    <p class="empty" style="padding-bottom:0">기록이 없습니다.</p>
                @else
                    @php($clients = AuditPresenter::clients())
                    <ul class="rows">
                        @foreach ($activity as $log)
                            @php($tone = AuditPresenter::tone($log->event))
                            @php($subject = AuditPresenter::subject($log, $people, $clients))
                            @php($detail = AuditPresenter::detail($log, $clients))
                            <li>
                                <div class="grow">
                                    <div>
                                        <span @class(['event', 'badge '.$tone => $tone !== ''])>{{ AuditPresenter::label($log->event) }}</span>
                                        @if ($subject && (string) $log->actor_id === (string) $user->id)
                                            <span class="muted small">→ {{ $subject }}</span>
                                        @elseif ((string) $log->actor_id !== (string) $user->id && in_array($log->actor_type, ['user', 'admin'], true))
                                            <span class="muted small">by {{ AuditPresenter::actor($log, $people) }}</span>
                                        @endif
                                    </div>
                                    @if ($detail !== '')<div class="sub">{{ $detail }}</div>@endif
                                </div>
                                <div class="when" title="{{ When::at($log->created_at, 'Y-m-d H:i:s') }}">{{ When::ago($log->created_at) }}</div>
                            </li>
                        @endforeach
                    </ul>
                @endif
            </section>

            <section class="card">
                <h2 class="card__title">계정 정보</h2>
                <dl class="kv">
                    <dt>번호</dt><dd class="mono">{{ $user->id }}</dd>
                    <dt>만든 사람</dt><dd>{{ $user->creator?->name ?? ($user->note === 'self-registered' ? '본인 가입' : '—') }}</dd>
                    <dt>가입</dt><dd>{{ When::at($user->created_at) }}</dd>
                    <dt>마지막 로그인</dt><dd>{{ When::at($user->last_login_at) }}</dd>
                    <dt>사진 변경</dt><dd>{{ When::at($user->avatar_updated_at) }}</dd>
                </dl>
            </section>
        </div>
    </div>
@endsection
