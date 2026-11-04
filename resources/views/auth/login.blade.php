@extends('layouts.app')

@section('title', 'Sign in')

@section('main-class', 'narrow')

@section('content')
    <h1>Sign in</h1>
    <p class="lead">Use the credentials an administrator gave you.</p>

    <form class="card" method="post" action="{{ route('login.store') }}">
        @csrf
        <label for="email">E-mail</label>
        <input id="email" type="email" name="email" value="{{ old('email') }}" required autofocus autocomplete="username">

        <label for="password">Password</label>
        <input id="password" type="password" name="password" required autocomplete="current-password">

        <label class="row" style="margin-top:16px">
            <input type="checkbox" name="remember" value="1" style="width:auto">
            <span>Remember this browser</span>
        </label>

        <div class="row" style="margin-top:20px">
            <button class="primary" type="submit">Sign in</button>
            <a class="btn" href="{{ route('home') }}">Cancel</a>
        </div>
    </form>
@endsection
