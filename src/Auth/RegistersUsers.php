<?php

namespace Wellola\PALaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Auth\Events\Registered;
use Wellola\PALaravelCognitoAuth\PACognitoClient;
use Wellola\PALaravelCognitoAuth\Exceptions\InvalidUserFieldException;
use Illuminate\Foundation\Auth\RegistersUsers as BaseSendsRegistersUsers;

trait RegistersUsers
{
    use BaseSendsRegistersUsers;

    /**
     * Handle a registration request for the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     * @throws InvalidUserFieldException
     */
    public function register(Request $request)
    {
        $this->validator($request->all())->validate();

        $attributes = [];

        $userFields = config('cognito.sso_user_fields');

        foreach ($userFields as $userField) {
            if ($request->filled($userField)) {
                $attributes[$userField] = $request->get($userField);
            } else {
                throw new InvalidUserFieldException("The configured user field {$userField} is not provided in the request.");
            }
        }

        app()->make(PACognitoClient::class)->register($request->email, $request->password, $attributes);

        event(new Registered($user = $this->create($request->all())));

        return $this->registered($request, $user) ?: redirect($this->redirectPath());
    }
}
