<?php

namespace Wellola\PALaravelCognitoAuth\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Wellola\PALaravelCognitoAuth\PACognitoClient;
use Illuminate\Foundation\Auth\SendsPasswordResetEmails as BaseSendsPasswordResetEmails;

trait PASendsPasswordResetEmails
{
    use BaseSendsPasswordResetEmails;

    /**
     * Send a reset link to the given user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function sendResetLinkEmail(Request $request)
    {
        $this->validateEmail($request);

        $response = app()->make(PACognitoClient::class)->sendResetLink($request->email);

        if ($response == Password::RESET_LINK_SENT) {
            return redirect(route('cognito.password-reset'));
        }

        return $this->sendResetLinkFailedResponse($request, $response);
    }
}
