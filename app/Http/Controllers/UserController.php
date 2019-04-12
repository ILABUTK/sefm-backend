<?php

    namespace App\Http\Controllers;

    use App\User;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Hash;
    use Illuminate\Support\Facades\Validator;
    use JWTAuth;
    use Tymon\JWTAuth\Exceptions\JWTException;
    use Illuminate\Support\Facades\Log;

    use Illuminate\Support\Carbon;
    use Illuminate\Auth\Events\Login;
    use Yadahan\AuthenticationLog\AuthenticationLog;
    use Yadahan\AuthenticationLog\Notifications\NewDevice;

    class UserController extends Controller
    {

         /**
         * Handle the event.
         *
         * @param  
         * @return void
         */
        public function log_jwt_login(Request $request)
        {
            $user = JWTAuth::user();
            $ip = $request->ip();
            $userAgent = $request->userAgent();
            $known = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->first();

            $authenticationLog = new AuthenticationLog([
                'ip_address' => $ip,
                'user_agent' => $userAgent,
                'login_at' => Carbon::now(),
            ]);

            $user->authentications()->save($authenticationLog);

            if (! $known && config('authentication-log.notify')) {
                $user->notify(new NewDevice($authenticationLog));
            }
        }
        public function authenticate(Request $request)
        {
            $credentials = $request->only('email', 'password');

            try {
                \Log::debug('Tried to login here via UserController:: authenticate ...' .time());

                if (! $token = JWTAuth::attempt($credentials)) {
                    return response()->json(['error' => 'invalid_credentials'], 400);
                }
                // success
                $this->log_jwt_login($request);

            } catch (JWTException $e) {
                return response()->json(['error' => 'could_not_create_token'], 500);
            }

            return response()->json(compact('token'));
        }

        public function register(Request $request)
        {
            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:6|confirmed',
            ]); ## password_confirmation

            if($validator->fails()){
                    return response()->json($validator->errors()->toJson(), 400);
            }

            $user = User::create([
                'name' => $request->get('name'),
                'email' => $request->get('email'),
                'password' => Hash::make($request->get('password')),
            ]);

            $token = JWTAuth::fromUser($user);

            return response()->json(compact('user','token'),201);
        }

        /**
         * Handle the event.
         *
         * @param  
         * @return void
         */
        public function log_jwt_logout(Request $request)
        {
            if (JWTAuth::user()) {
                $user = JWTAuth::user();
                $ip = $request->ip();
                $userAgent = $request->userAgent();
                $authenticationLog = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->first();

                if (! $authenticationLog) {
                    $authenticationLog = new AuthenticationLog([
                        'ip_address' => $ip,
                        'user_agent' => $userAgent,
                    ]);
                }

                $authenticationLog->logout_at = Carbon::now();

                $user->authentications()->save($authenticationLog);
            }
        }
        public function logout(Request $request)
        {
            try {
                $this->log_jwt_logout($request); //log

                JWTAuth::invalidate(JWTAuth::parseToken());                
            } catch (JWTException $e) {
                return response()->json(['error' => 'logout encountered error'], 400);
            }     

            return response()->json(['status' => 'success!'], 200);      
        }

        public function getAuthenticatedUser()
            {
                try {

                        if (! $user = JWTAuth::parseToken()->authenticate()) {
                                return response()->json(['user_not_found'], 404);
                        }

                } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

                        return response()->json(['token_expired'], $e->getStatusCode());

                } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

                        return response()->json(['token_invalid'], $e->getStatusCode());

                } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

                        return response()->json(['token_absent'], $e->getStatusCode());

                }

                return response()->json(compact('user'));
            }
    }