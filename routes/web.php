<?php
use Illuminate\Http\Request;
use App\Events\TeacheBroadcastNewData;
use App\Events\SpeedChange;
/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
    // return redirect('/sefm');
});

Route::post('/broadcast/{classroom}', function ($classroom, Request $request){
    $data = $request->input('data');
    event(new TeacheBroadcastNewData($classroom, $data));
    return response('OK');
});


Route::post('/broadcast/{classroom}/speed', function ($classroom, Request $request){
    $speed = $request->input('speed');
    event(new SpeedChange($classroom, $speed));
    return response('OK');
});

Auth::routes();
Route::get('/web', 'HomeController@index')->name('home');

Route::namespace('Auth')->group(function () {
    Route::post('/password/email', 'ForgotPasswordController@sendResetLinkEmail')->name('password.email');
    Route::get('/password/reset', 'ForgotPasswordController@showLinkRequestForm')->name('password.request');
    Route::post('/password/reset', 'ResetPasswordController@reset');
    Route::get('/password/reset/{token}', 'ResetPasswordController@showResetForm')->name('password.reset');
    Route::get('/password/resetsuccess', 'ResetPasswordSuccessController@index')->name('password.reset.success');

    Route::get('/sefm', function () {
	    // return "Welcome to SEFM APP!";
	    return File::get(public_path() . '/app/index.html');
	    // return view('app.spa');
	})->middleware('auth');
});
