@extends('layouts.app')
@use('App\Support\When')

@section('title', '사용자')

@section('content')
    <div class="page-head">
        <div>
            <h1>사용자</h1>
            <p class="lead">이 계정으로 모든 사내 도구에 로그인합니다. 사람을 눌러 권한·비밀번호·사진을 관리하세요.</p>
        </div>
        <button class="primary" type="button" data-open="new-user">+ 새 사용자</button>
    </div>

    <div class="toolbar">
        <form class="search" method="get" action="{{ route('admin.users.index') }}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
            <input type="text" name="q" value="{{ $search }}" placeholder="이름이나 아이디로 찾기  ( / )" data-search autocomplete="off">
            @if ($filter !== 'all')<input type="hidden" name="filter" value="{{ $filter }}">@endif
        </form>
        <div class="chips">
            @foreach (['all' => '전체', 'admin' => '관리자', 'user' => '일반', 'disabled' => '비활성'] as $key => $label)
                <a @class(['chip', 'active' => $filter === $key])
                   href="{{ route('admin.users.index', array_filter(['filter' => $key === 'all' ? null : $key, 'q' => $search ?: null])) }}">
                    {{ $label }} <span class="n">{{ $counts[$key] }}</span>
                </a>
            @endforeach
        </div>
    </div>

    <div class="card" style="padding-top:8px">
        @if ($users->isEmpty())
            <p class="empty">
                @if ($search !== '')
                    ‘{{ $search }}’에 맞는 사람이 없습니다. <a href="{{ route('admin.users.index') }}">검색 지우기</a>
                @else
                    아직 아무도 없습니다.
                @endif
            </p>
        @else
            <table class="list">
                <thead>
                <tr>
                    <th>사람</th>
                    <th>권한</th>
                    <th>상태</th>
                    <th class="hide-sm">마지막 로그인</th>
                    <th class="hide-sm">가입</th>
                    <th></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($users as $user)
                    <tr data-href="{{ route('admin.users.show', $user) }}" @class(['is-off' => ! $user->isActive()])>
                        <td>
                            <a class="who" href="{{ route('admin.users.show', $user) }}" style="text-decoration:none">
                                @include('partials.avatar', ['user' => $user])
                                <span class="who__text">
                                    <span class="who__name">{{ $user->name }}</span>
                                    <span class="who__sub">{{ $user->username }}</span>
                                </span>
                            </a>
                        </td>
                        <td>
                            @if ($user->isSuperAdmin())
                                <span class="badge admin">관리자</span>
                            @else
                                <span class="small muted">일반</span>
                            @endif
                        </td>
                        <td>
                            @if ($user->isActive())
                                <span class="badge ok dot">활성</span>
                            @else
                                <span class="badge bad dot">비활성</span>
                            @endif
                        </td>
                        <td class="small muted hide-sm" title="{{ When::at($user->last_login_at) }}">{{ When::ago($user->last_login_at, '로그인 기록 없음') }}</td>
                        <td class="small muted hide-sm">{{ When::at($user->created_at, 'Y-m-d') }}</td>
                        <td class="right"><span class="go" aria-hidden="true">›</span></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
            {{ $users->links('vendor.pagination.simple') }}
        @endif
    </div>

    @php($create = $errors->getBag('create'))
    <dialog class="modal" id="new-user" @if ($create->any() || request()->boolean('new')) data-open-now @endif>
        <form method="post" action="{{ route('admin.users.store') }}">
            @csrf
            <h2>새 사용자</h2>
            <p class="card__hint">만든 뒤 아이디와 비밀번호를 본인에게 전달하세요. 본인이 로그인해서 비밀번호를 바꿀 수 있습니다.</p>

            <label for="new-name">이름</label>
            <input id="new-name" type="text" name="name" value="{{ old('name') }}" required maxlength="120" placeholder="예: 홍길동 대리">
            @if ($create->has('name'))<div class="field-error">{{ $create->first('name') }}</div>@endif

            <label for="new-username">아이디</label>
            <input id="new-username" type="text" name="username" value="{{ old('username') }}" required
                   autocapitalize="none" spellcheck="false" autocomplete="off" placeholder="예: gildong">
            @if ($create->has('username'))
                <div class="field-error">{{ $create->first('username') }}</div>
            @else
                <div class="hint">로그인할 때 쓰는 이름입니다. 영문 소문자·숫자와 . _ - (3자 이상)</div>
            @endif

            <label for="new-password">비밀번호</label>
            <div class="input-row">
                <input id="new-password" type="password" name="password" autocomplete="new-password" placeholder="비워 두면 자동으로 만듭니다">
                <button type="button" data-reveal="#new-password">보기</button>
            </div>
            <div class="hint">자동으로 만든 비밀번호는 다음 화면에 한 번만 보입니다.</div>

            <label for="new-role">권한</label>
            <select id="new-role" name="role">
                <option value="user" @selected(old('role', 'user') === 'user')>일반 — 앱에 로그인</option>
                <option value="super_admin" @selected(old('role') === 'super_admin')>관리자 — 이 콘솔도 사용</option>
            </select>

            <div class="form-actions">
                <button class="primary" type="submit">만들기</button>
                <button type="button" data-close>취소</button>
            </div>
        </form>
    </dialog>
@endsection
