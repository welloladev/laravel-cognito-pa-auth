<?php

return [
    // AWS Settings
    'credentials'       => [
        'key'    => env('PA_AWS_COGNITO_KEY', ''),
        'secret' => env('PA_AWS_COGNITO_SECRET', ''),
    ],
    'region'            => env('PA_AWS_COGNITO_REGION', 'eu-west-1'),
    'version'           => env('PA_AWS_COGNITO_VERSION', 'latest'),
    'app_client_id'     => env('PA_AWS_COGNITO_CLIENT_ID', ''),
    'app_client_secret' => env('PA_AWS_COGNITO_CLIENT_SECRET', ''),
    'user_pool_id'      => env('PA_AWS_COGNITO_USER_POOL_ID', ''),

    // package configuration
    'use_sso'           => env('USE_SSO', false),
    'sso_user_fields'   => [
        'name',
        'email',
    ],
    'sso_user_model'        => 'App\User',
    'delete_user'           => env('PA_AWS_COGNITO_DELETE_USER', false),
];
