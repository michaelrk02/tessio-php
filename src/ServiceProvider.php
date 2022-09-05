<?php

namespace Michaelrk02\Tessio;

/**
 * ServiceProvider class
 *
 * SSO service provider
 */
class ServiceProvider
{
    /**
     * @var string $name
     */
    protected $name;

    /**
     * @var string $idpName
     */
    protected $idpName;

    /**
     * @var string $idpLoginUrl
     */
    protected $idpLoginUrl;

    /**
     * @var string $redirectUrl
     */
    protected $redirectUrl;

    /**
     * @var string $secret
     */
    protected $secret;

    /**
     * @var int $responseTimeout
     */
    protected $responseTimeout;

    /**
     * Construct new ServiceProvider object
     *
     * @param string $name Name to uniquely identify this provider
     * @param string $idpName Identity provider name
     * @param string $idpLoginUrl Login URL from identity provider
     * @param string $redirectUrl URL in this service to redirect user when logged in
     * @param string $secret Service provider secret key
     * @param int $responseTimeout SSO response timeout (in seconds)
     */
    public function __construct($name, $idpName, $idpLoginUrl, $redirectUrl, $secret, $responseTimeout = 5)
    {
        $this->name = $name;
        $this->idpName = $idpName;
        $this->redirectUrl = $redirectUrl;
        $this->secret = $secret;
        $this->responseTimeout = $responseTimeout;
    }

    /**
     * Send SSO login request
     *
     * This will redirect the user's browser to the identity provider website
     *
     * @param array $scope User account scopes (array of strings)
     * @param string|null $overrideRedirectUrl Redirect URL to override
     *
     * @return void
     */
    public function requestLogin($scope = [], $overrideRedirectUrl = null)
    {
        $token = $this->createRequestToken($overrideRedirectUrl ?? $this->redirectUrl, $scope);
        $loginUrl = $this->idpLoginUrl.'?sso-request-token='.urlencode($token);

        http_response_code(301);
        header('Location: '.$loginUrl);
        exit;
    }

    /**
     * Handle incoming SSO response
     *
     * Put this on a dedicated route on your website.
     *
     * This will return an array that consists of keys:
     *
     * - `uid` (string|int) : Associated user ID
     * - `scope` (array) : Scope key/value pairs
     *
     * @return array SSO user credentials
     */
    public function handleResponse()
    {
        $parameters = ['idp', 'uid', 'iat', 'scope', 'sig'];
        foreach ($parameters as $parameter) {
            if (!array_key_exists($parameter, $_POST)) {
                throw new \Exception('Incomplete SSO response parameters');
            }
        }

        $idp = $_POST['idp'];
        $sp = $_POST['sp'];
        $uid = $_POST['uid'];
        $iat = (int)$_POST['iat'];
        $scope = $_POST['scope'];
        $sig = $_POST['sig'];

        if (!$this->verifyResponse($idp, $sp, $uid, $iat, $scope, $sig)) {
            throw new \Exception('SSO response parameters cannot be correctly validated');
        }

        if (!($sp === $this->name)) {
            throw new \Exception('Invalid service provider specified');
        }

        if (!(time() <= $iat + $this->responseTimeout)) {
            throw new \Exception('SSO response timed out. Please try again');
        }

        $scope = @json_decode(@base64_decode($scope), true);
        if (!is_array($scope)) {
            throw new \Exception('Invalid user account scope returned');
        }

        return [
            'uid' => $uid,
            'scope' => $scope
        ];
    }

    /**
     * Create SSO request token
     *
     * @param string $redirectUrl Redirection URL if user is logged in
     * @param array $scope User account scope
     *
     * @return string SSO request token
     */
    public function createRequestToken($redirectUrl, $scope)
    {
        $request = [];
        $request['idp'] = $this->idpName;
        $request['sp'] = $this->name;
        $request['redir'] = $this->redirectUrl;
        $request['iat'] = time();
        $request['scope'] = $scope;
        $request['sig'] = hash_hmac('sha256', $request['sp'].$request['iat'], $this->secret);

        return base64_encode(json_encode($request));
    }

    /**
     * Verify SSO response authenticity
     *
     * @param string $identityProvider Identity provider name
     * @param string $serviceProvider Service provider name
     * @param string $userId Associated user ID
     * @param string $issueTime SSO response timestamp
     * @param string $scopeToken User account scope (JSON -> Base64 encoded)
     * @param string $signature SHA256 signature to verify
     *
     * @return bool True if signatures match
     */
    public function verifyResponse($identityProvider, $serviceProvider, $userId, $issueTime, $scopeToken, $signature)
    {
        return $signature === hash_hmac('sha256', $identityProvider.$serviceProvider.$userId.$issueTime.$scopeToken, $this->secret);
    }
}
