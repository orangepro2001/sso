@extends('layouts.app')

@section('title', 'Account')

@section('content')
    <h1>Your account</h1>
    <p class="lead">Signed in as <span class="mono">{{ $user->username }}</span>.</p>

    @if ($errors->any())
        <div class="flash bad">
            @foreach ($errors->all() as $error)
                <div>{{ $error }}</div>
            @endforeach
        </div>
    @endif

    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr));align-items:start">

        <div class="card">
            <h2 style="margin-top:0">Picture</h2>
            <div class="row" style="align-items:center;gap:16px">
                @if ($user->hasAvatar())
                    <img src="{{ $user->avatarUrl() }}" alt="" width="72" height="72"
                         style="border-radius:50%;object-fit:cover;border:1px solid var(--hair)">
                @else
                    <span style="width:72px;height:72px;border-radius:50%;display:grid;place-items:center;
                                 background:var(--blue-050);color:var(--blue);font-weight:700;font-size:26px">
                        {{ mb_substr($user->name, 0, 1) }}
                    </span>
                @endif

                <form method="post" action="{{ route('account.avatar') }}" enctype="multipart/form-data" class="row">
                    @csrf
                    <input type="file" name="avatar" accept="image/png,image/jpeg,image/webp,image/gif" required>
                    <button class="btn primary" type="submit">Upload</button>
                </form>

                @if ($user->hasAvatar())
                    <form method="post" action="{{ route('account.avatar.remove') }}">
                        @csrf @method('DELETE')
                        <button class="btn danger" type="submit">Remove</button>
                    </form>
                @endif
            </div>
            <p class="tiny muted">PNG, JPEG, WebP or GIF, up to 512 KB. Stored on this host — nothing is sent to an avatar service.</p>
        </div>

        <div class="card">
            <h2 style="margin-top:0">Profile</h2>
            <form method="post" action="{{ route('account.update') }}">
                @csrf
                @method('PUT')

                <label for="name">Display name</label>
                <input id="name" type="text" name="name" value="{{ old('name', $user->name) }}" required maxlength="120">
                <p class="tiny muted">Shown inside the applications.</p>

                <label for="username">Username</label>
                <input id="username" type="text" name="username" value="{{ old('username', $user->username) }}"
                       required minlength="3" maxlength="64" autocapitalize="off">
                <p class="tiny muted">
                    What you sign in with. Changing it needs your current password below, and other applications
                    that copied the name — rather than the account id — will see the new one.
                </p>

                <label for="confirm_password">Current password <span class="muted">(only needed to change the username)</span></label>
                <input id="confirm_password" type="password" name="current_password" autocomplete="current-password">

                <div class="row" style="margin-top:16px">
                    <button class="btn primary" type="submit">Save profile</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2 style="margin-top:0">Password</h2>
            <form method="post" action="{{ route('account.password') }}">
                @csrf

                <label for="current_password">Current password</label>
                <input id="current_password" type="password" name="current_password" required autocomplete="current-password">

                <label for="password">New password</label>
                <input id="password" type="password" name="password" required autocomplete="new-password">
                <p class="tiny muted">Every other device is signed out once it changes.</p>

                <label for="password_confirmation">New password again</label>
                <input id="password_confirmation" type="password" name="password_confirmation" required autocomplete="new-password">

                <div class="row" style="margin-top:16px">
                    <button class="btn primary" type="submit">Change password</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2 style="margin-top:0">Where you are signed in</h2>
            @if ($signedIn->isEmpty())
                <p class="empty">No application holds a token for you right now.</p>
            @else
                <table>
                    <thead><tr><th>Application</th><th>Signed in</th><th>From</th><th>Expires</th></tr></thead>
                    <tbody>
                    @foreach ($signedIn as $token)
                        <tr>
                            <td class="mono">{{ $token->client_id ?: 'web session' }}</td>
                            <td class="small muted">{{ $token->created_at?->format('Y-m-d H:i') }}</td>
                            <td class="mono small">{{ $token->issued_ip ?? '—' }}</td>
                            <td class="small muted">{{ $token->expires_at?->format('Y-m-d') ?? 'no expiry' }}</td>
                        </tr>
                    @endforeach
                    </tbody>
                </table>
                <form method="post" action="{{ route('account.tokens') }}" style="margin-top:12px">
                    @csrf @method('DELETE')
                    <button class="btn danger" type="submit">Sign out of every application</button>
                </form>
            @endif
        </div>

        <div class="card">
            <h2 style="margin-top:0">Recent sign-in</h2>
            <table>
                <tbody>
                <tr><th>Last sign-in</th><td class="small muted">{{ $user->last_login_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
                <tr><th>From</th><td class="mono">{{ $user->last_login_ip ?? '—' }}</td></tr>
                <tr><th>Status</th><td><span class="badge {{ $user->isActive() ? 'ok' : 'bad' }}">{{ $user->status }}</span></td></tr>
                </tbody>
            </table>
            <p class="tiny muted">Something here you do not recognise? Change your password and tell an administrator.</p>
        </div>
    </div>
@endsection
