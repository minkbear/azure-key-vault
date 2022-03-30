<?php

namespace InsitesConsulting\AzureKeyVault;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class Vault
{
//    protected string $tenant_id;
//    private $client_id;
//    private $client_secret;
//    private $vault;
//
//    public function __construct(
//        string $tenant_id = '',
//        string $client_id = '',
//        string $client_secret = '',
//        string $vault = ''
//    ) {
//        $this->tenant_id = $tenant_id;
//        $this->client_id = $client_id;
//        $this->client_secret = $client_secret;
//        $this->vault = $vault;
//    }

    private static function authToken(): string
    {
        if (Cache::has('keyvault_token')) {
            return Cache::get('keyvault_token');
        }

        $tenant_id = config('vault.tenant_id');
        $client_id = config('vault.client_id');
        $client_secret = config('vault.client_secret');

        $response = Http::asForm()
        ->post(
            "https://login.microsoftonline.com/{$tenant_id}/oauth2/token",
            [
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'resource' => 'https://vault.azure.net',
                'grant_type' => 'client_credentials',
            ]
        )->json();

        $token = $response['access_token'];
        $expiry = now()->addSeconds((int)$response['expires_in']);

        Cache::put('keyvault_token', $token, $expiry);
        return $token;
    }

    private static function vaultUrl(): string
    {
        $vault = config('vault.vault');

        return "https://{$vault}.vault.azure.net/";
    }

    public static function secret(string $name, ?string $default = null): ?string
    {
        $response = Http::withToken(self::authToken())
            ->accept('application/json')
            ->get(
                self::vaultUrl() . "secrets/$name",
                [
                    "api-version" => "7.1"
                ]
            );
        if ($response->successful()) {
            return $response->json()['value'];
        } elseif ($response->status() == 404) {
            return $default;
        } else {
            throw new AzureKeyVaultException(
                $response->json()['error']['message'],
                $response->status()
            );
        }
    }

    public function setVault(?string $vault = null): void
    {
        $this->vault = $vault ?? config('vault.vault');
    }

    public static function certificate($name) {
        $response = Http::withToken(self::authToken())
            ->accept('application/json')
            ->get(
                self::vaultUrl() . "certificates/$name",
                [
                    "api-version" => "7.2"
                ]
            );

        if ($response->successful()) {
            $result = $response->json();

            $cert = new Certificate(
                $response['id'],
                $response['cer'],
                $response['attributes']['enabled'],
                $response['attributes']['created'],
                $response['attributes']['updated'],
                $response['attributes']['exp']
            );

            return $cert;
        } elseif ($response->status() == 404) {
            return $default;
        } else {
            throw new AzureKeyVaultException(
                $response->json()['error']['message'],
                $response->status()
            );
        }
    }

    public static function uploadcert($name, $content_base64, $pwd) {
        $response = Http::withToken(self::authToken())
            ->accept('application/json')
            ->post(
                self::vaultUrl() . "certificates/$name/import?api-version=7.2",
                [
                    'value' => $content_base64,
                    'pwd' => $pwd,
                    'policy' => [
                        'key_props' => [
                            'exportable' => true,
                            'kty' => 'RSA',
                            'key_size' => 2048,
                            'reuse_key' => false
                        ],
                        'secret_props' => [
                            'contentType' => 'application/x-pkcs12'
                        ]
                    ]
                ]
            );

        if ($response->successful()) {
            $result = $response->json();

//            $cert = new Certificate(
//                $response['id'],
//                $response['cer'],
//                $response['attributes']['enabled'],
//                $response['attributes']['created'],
//                $response['attributes']['updated'],
//                $response['attributes']['exp']
//            );

            return $result;
        } elseif ($response->status() == 404) {
            return $default;
        } else {
            throw new AzureKeyVaultException(
                $response->json()['error']['message'],
                $response->status()
            );
        }
    }
}
