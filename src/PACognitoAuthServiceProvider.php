<?php

namespace Wellola\PALaravelCognitoAuth;

use Illuminate\Support\Arr;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Wellola\PALaravelCognitoAuth\Auth\PACognitoGuard;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class PACognitoAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/cognito.php' => config_path('cognito.php'),
        ], 'config');

        $this->publishes([
            __DIR__.'/Resources/views' => resource_path('views/vendor/black-bits/laravel-cognito-auth'),
        ], 'views');

        $this->publishes([
            __DIR__.'/Resources/lang' => resource_path('lang/vendor/black-bits/laravel-cognito-auth'),
        ], 'lang');

        $this->app->singleton(PACognitoClient::class, function (Application $app) {
            $config = [
                'region'      => config('cognito.pa.region'),
                'version'     => config('cognito.pa.version'),
            ];

            $credentials = config('cognito.pa.credentials');

            if (! empty($credentials['key']) && ! empty($credentials['secret'])) {
                $config['credentials'] = Arr::only($credentials, ['key', 'secret', 'token']);
            }

            return new PACognitoClient(
                new CognitoIdentityProviderClient($config),
                config('cognito.pa.app_client_id'),
                config('cognito.pa.app_client_secret'),
                config('cognito.pa.user_pool_id')
            );
        });

        $this->app['auth']->extend('cognito', function (Application $app, $name, array $config) {
            $guard = new PACognitoGuard(
                $name,
                $client = $app->make(PACognitoClient::class),
                $app['auth']->createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );

            $guard->setCookieJar($this->app['cookie']);
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });

//        $this->loadRoutesFrom(__DIR__.'/routes.php');
//        $this->loadViewsFrom(__DIR__.'/Resources/views', 'black-bits/laravel-cognito-auth');
//        $this->loadTranslationsFrom(__DIR__.'/Resources/lang', 'black-bits/laravel-cognito-auth');
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/cognito.php', 'cognito');
    }
}
