<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
}); // get user info from token

Route::post('register', 'UserController@register');  // register
Route::post('login', 'UserController@authenticate'); // login

Route::get('open', 'DataController@open'); // sample method: open data

Route::group(['middleware' => ['jwt.verify']], function() {
    Route::get('user', 'UserController@getAuthenticatedUser'); // /api/user get user via token
    Route::get('closed', 'DataController@closed'); // sample method: secured data
    Route::post('logout', 'UserController@logout'); // invalidate token
});