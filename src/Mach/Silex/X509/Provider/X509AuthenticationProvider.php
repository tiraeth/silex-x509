<?php

/*
 * This file is part of the mach/silex-x509 package.
 *
 * (c) Marcin Chwedziak <marcin@chwedziak.pl>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mach\Silex\X509\Provider;

use Mach\Silex\X509\EntryPoint\X509AuthenticationEntryPoint;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Symfony\Component\Security\Core\Authentication\Provider\PreAuthenticatedAuthenticationProvider;
use Symfony\Component\Security\Http\Firewall\X509AuthenticationListener;

/**
 * X.509 Authentication Security Provider
 *
 * @author Marcin Chwedziak <marcin@chwedziak.pl>
 */
class X509AuthenticationProvider implements ServiceProviderInterface
{
    public function register(Container $app)
    {
        $app['security.x509.client_key'] = 'SSL_CLIENT_S_DN_Email';
        $app['security.x509.credentials_key'] = 'SSL_CLIENT_S_DN';

        $app['security.authentication_listener.factory.x509'] = $app->protect(function($name, $options) use ($app) {
            if (!isset($app['security.entry_point.'.$name.'.x509'])) {
                $app['security.entry_point.'.$name.'.x509'] = $app['security.entry_point.x509._proto']($name, $options);
            }

            if (!isset($app['security.authentication_listener.'.$name.'.x509'])) {
                $app['security.authentication_listener.'.$name.'.x509'] = $app['security.authentication_listener.x509._proto']($name, $options);
            }

            if (!isset($app['security.authentication_provider.'.$name.'.x509'])) {
                $app['security.authentication_provider.'.$name.'.x509'] = $app['security.authentication_provider.x509._proto']($name);
            }

            return array(
                'security.authentication_provider.'.$name.'.x509',
                'security.authentication_listener.'.$name.'.x509',
                'security.entry_point.'.$name.'.x509',
                'pre_auth'
            );
        });

        $app['security.authentication_listener.x509._proto'] = $app->protect(function ($providerKey, $options) use ($app) {
            return function () use ($app, $providerKey, $options) {
                return new X509AuthenticationListener(
                    $app['security.token_storage'],
                    $app['security.authentication_manager'],
                    $providerKey,
                    $app['security.x509.client_key'],
                    $app['security.x509.credentials_key'],
                    $app['logger'],
                    $app['dispatcher']
                );
            };
        });

        $app['security.authentication_provider.x509._proto'] = $app->protect(function ($name) use ($app) {
            return function () use ($app, $name) {
                return new PreAuthenticatedAuthenticationProvider(
                    $app['security.user_provider.'.$name],
                    $app['security.user_checker'],
                    $name
                );
            };
        });

        $app['security.entry_point.x509._proto'] = $app->protect(function ($name, array $options) use ($app) {
            return function () use ($app, $name, $options) {
                return new X509AuthenticationEntryPoint();
            };
        });
    }
}