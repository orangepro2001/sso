<?php

// Only the rules this service uses. Anything missing falls back to English
// (fallback_locale), which is readable, just not friendly.
return [
    'required' => ':attribute 항목을 입력하세요.',
    'string' => ':attribute 항목은 글자여야 합니다.',
    'integer' => ':attribute 항목은 숫자여야 합니다.',
    'min' => ['string' => ':attribute 항목은 :min자 이상이어야 합니다.', 'numeric' => ':attribute 항목은 :min 이상이어야 합니다.'],
    'max' => ['string' => ':attribute 항목은 :max자 이하여야 합니다.', 'numeric' => ':attribute 항목은 :max 이하여야 합니다.', 'file' => ':attribute 파일은 :max KB 이하여야 합니다.'],
    'unique' => '이미 쓰이고 있는 :attribute 입니다.',
    'regex' => ':attribute 형식이 맞지 않습니다.',
    'confirmed' => ':attribute 확인이 일치하지 않습니다.',
    'different' => ':attribute 항목은 :other 항목과 달라야 합니다.',
    'in' => '선택한 :attribute 값이 올바르지 않습니다.',
    'file' => ':attribute 항목은 파일이어야 합니다.',
    'uploaded' => ':attribute 파일을 올리지 못했습니다.',
    'mimetypes' => ':attribute 파일은 :values 형식이어야 합니다.',
    'url' => ':attribute 항목은 올바른 주소여야 합니다.',
    'array' => ':attribute 항목은 목록이어야 합니다.',
    'boolean' => ':attribute 항목은 참/거짓이어야 합니다.',

    'custom' => [
        'username' => [
            'regex' => '아이디는 영문 소문자·숫자로 시작하고 끝나며, 중간에 . _ - 를 쓸 수 있습니다 (3~64자).',
        ],
    ],

    'attributes' => [
        'name' => '이름',
        'username' => '아이디',
        'password' => '비밀번호',
        'current_password' => '현재 비밀번호',
        'avatar' => '사진',
        'role' => '권한',
        'status' => '상태',
        'note' => '메모',
        'confirm' => '확인',
        'redirect_uris' => '리디렉션 URI',
        'home_url' => '홈 주소',
    ],
];
