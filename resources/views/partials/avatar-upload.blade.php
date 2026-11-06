{{-- Picture uploader: click, drop or paste. console.js crops to a square and
     shrinks it before the form is sent; without JavaScript the plain file input
     and the button still work. --}}
<form method="post" action="{{ $action }}" enctype="multipart/form-data" data-avatar-upload>
    @csrf
    <label class="dropzone" style="margin:0;cursor:pointer;font-weight:normal">
        @include('partials.avatar', ['user' => $user, 'size' => 'xl', 'preview' => true])
        <input type="file" name="avatar" accept="image/*">
        <span class="btn">사진 고르기</span>
        <p class="hint" data-avatar-status>클릭하거나 사진을 끌어다 놓으세요. 붙여넣기(Ctrl+V)도 됩니다.<br>정사각형으로 잘라 자동으로 줄여서 올립니다.</p>
    </label>
    <noscript><div class="form-actions"><button type="submit">올리기</button></div></noscript>
</form>
@if ($user->hasAvatar())
    <form method="post" action="{{ $removeAction }}" data-confirm="프로필 사진을 지울까요?" style="margin-top:8px;text-align:center">
        @csrf
        @method('delete')
        <button class="link" type="submit" style="color:var(--muted)">사진 지우기</button>
    </form>
@endif
