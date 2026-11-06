{{-- A person's picture, or the first letter of their name. --}}
@php($sizeClass = isset($size) ? 'avatar--'.$size : '')
@if ($user->hasAvatar())
    <img class="avatar {{ $sizeClass }}" src="{{ $user->avatarUrl() }}" alt="" loading="lazy" @isset($preview) data-avatar-preview @endisset>
@else
    <span class="avatar {{ $sizeClass }}" aria-hidden="true" @isset($preview) data-avatar-preview @endisset>{{ mb_substr(trim($user->name) ?: $user->username, 0, 1) }}</span>
@endif
