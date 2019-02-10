<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;

class ResetPasswordSuccessController extends Controller
{

    public function __construct(){

    }

    public function index(){
      return view('auth.passwords.resetsuccess');
    }


}
