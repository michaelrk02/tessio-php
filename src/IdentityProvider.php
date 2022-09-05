<?php

namespace Michaelrk02\Tessio;

/**
 * IdentityProvider class
 *
 * SSO identity provider
 */
class IdentityProvider
{
    /**
     * @var string $name
     */
    protected $name;

    /**
     * @var IdpProxyInterface $proxy
     */
    protected $proxy;

    /**
     * @var int $loginTimeout
     */
    protected $loginTimeout;

    /**
     * Construct new IdentityProvider object
     *
     * @param string $name Name to uniquely identify this provider
     * @param IdpProxyInterface $proxy Proxy object used for this provider
     * @param int $loginTimeout SSO login timeout (in minutes)
     */
    public function __construct($name, $proxy, $loginTimeout)
    {
        $this->name = $name;
        $this->proxy = $proxy;
        $this->loginTimeout = $loginTimeout;
    }

    /**
     * Check if there's a SSO request
     *
     * Returns SSO request parameters that consists of:
     *
     * - `idp` (string) : Identity provider name
     * - `sp` (string) : Service provider name
     * - `redir` (string) : Redirection URL to handle SSO response
     * - `iat` (int) : SSO request timestamp
     * - `scope` (array) : User account request scopes
     * - `sig` (string) : SHA256 hash (sp + iat) using service provider's secret key
     *
     * @param bool $checkTimeout Whether to check for SSO request timeout
     *
     * @return array|null SSO request parameters
     */
    public function checkRequest($checkTimeout = true)
    {
        $request = @$_GET['sso-request-token'];
        if (!empty($request)) {
            $request = @json_decode(@base64_decode($request), true);
            if (!isset($request)) {
                throw new \Exception('Invalid SSO request token format');
            }

            $idp = @$request['idp'];
            $sp = @$request['sp'];
            $redir = @$request['redir'];
            $iat = (int)@$request['iat'];
            $scope = @$request['scope'];
            $sig = @$request['sig'];

            if (!(is_string($idp) && is_string($sp) && is_string($redir) && ($iat !== 0) && is_array($scope) && is_string($sig))) {
                throw new \Exception('Incomplete SSO request parameters');
            }

            if (!$this->verifyRequest($sp, $iat, $sig)) {
                throw new \Exception('SSO request parameters cannot be correctly validated');
            }

            if (!($idp === $this->name)) {
                throw new \Exception('Invalid identity provider specified');
            }

            if (!(!$checkTimeout || (time() <= $iat + $this->loginTimeout * 60))) {
                throw new \Exception('SSO request timed out. Please try again');
            }

            return [
                'idp' => $idp,
                'sp' => $sp,
                'redir' => $redir,
                'iat' => $iat,
                'scope' => $scope,
                'sig' => $sig
            ];
        }
        return null;
    }

    /**
     * Verify SSO request authenticity
     *
     * @param string $serviceProvider Service provider name
     * @param int $issueTime SSO request timestamp
     * @param string $signature SHA256 signature to verify
     *
     * @return bool True if signatures match
     */
    public function verifyRequest($serviceProvider, $issueTime, $signature)
    {
        return $signature === hash_hmac('sha256', $serviceProvider.$issueTime, $this->proxy->getServiceProviderSecret($serviceProvider));
    }

    /**
     * Handle incoming SSO request
     *
     * Put this on your application's login handler, especially before displaying a view
     * May be called via GET/POST request.
     *
     * @return array|null SSO request parameters
     */
    public function handleRequest()
    {
        $request = $this->checkRequest();
        if (isset($request)) {
            $credentials = $this->proxy->getLoginCredentials($request['scope']);
            if (is_array($credentials)) {
                $idp = $this->name;
                $sp = $request['sp'];
                $uid = @$credentials['uid'];
                $iat = time();
                $scope = base64_encode(json_encode(@$credentials['scope']));
                $sig = hash_hmac('sha256', $idp.$sp.$uid.$iat.$scope, $this->proxy->getServiceProviderSecret($request['sp']));

                if (!(isset($uid) && is_string($scope))) {
                    throw new \Exception('Invalid SSO credentials returned');
                }

                http_response_code(200);
                header('Content-Type: text/html');
                echo '<html>';
                echo ' <head>';
                echo '  <title>SSO Response</title>';
                echo '  <script>';
                echo '   document.addEventListener("load", function() { document.getElementById("sso").submit(); })';
                echo '  </script>';
                echo ' </head>';
                echo ' <body>';
                echo '  <p>SSO login successful. Sending credentials ...</p>';
                echo '  <form id="sso" method="post" action="'.esc($request['redir']).'">';
                echo '   <input type="hidden" name="idp" value="'.esc($idp).'">';
                echo '   <input type="hidden" name="sp" value="'.esc($sp).'">';
                echo '   <input type="hidden" name="uid" value="'.esc($uid).'">';
                echo '   <input type="hidden" name="iat" value="'.esc($iat).'">';
                echo '   <input type="hidden" name="scope" value="'.esc($scope).'">';
                echo '   <input type="hidden" name="sig" value="'.esc($sig).'">';
                echo '  </form>';
                echo ' </body>';
                echo '</html>';
                exit;
            }
        }
        return $request;
    }

    /**
     * Reconstruct a SSO token
     *
     * @param array $request SSO request parameters
     *
     * @return string SSO request token
     */
    public function reconstructToken($request)
    {
        return base64_encode(json_encode([
            'idp' => $request['idp'],
            'sp' => $request['sp'],
            'redir' => $request['redir'],
            'iat' => $request['iat'],
            'scope' => $request['scope'],
            'sig' => $request['sig']
        ]));
    }
}
