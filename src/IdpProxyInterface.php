<?php

namespace Michaelrk02\Tessio;

/**
 * IdpProxy interface
 *
 * Identity provider callbacks
 */
interface IdpProxyInterface
{
    /**
     * Get a service provider's secret key
     *
     * @param string $serviceProvider Service provider name
     *
     * @return string Secret key
     */
    public function getServiceProviderSecret($serviceProvider);

    /**
     * Get user login credentials
     *
     * This must return an array with keys:
     *
     * - `uid` (string|int) : Associated user ID
     * - `scope` (array) : Scope key/value pairs
     *
     * @param array $scope Requested user account scopes
     *
     * @return array|null Login credentials, `null` if not logged in
     */
    public function getLoginCredentials($scope);
}
