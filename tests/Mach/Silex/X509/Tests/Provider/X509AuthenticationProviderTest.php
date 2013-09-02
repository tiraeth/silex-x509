<?php

/*
 * This file is part of the mach/silex-x509 package.
 *
 * (c) Marcin Chwedziak <marcin@chwedziak.pl>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mach\Silex\X509\Tests\Provider;

use Mach\Silex\X509\Provider\X509AuthenticationProvider;
use Silex\Application;
use Silex\WebTestCase;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\HttpFoundation\Request;

/**
 * X509AuthenticationProvider
 *
 * @author Marcin Chwedziak <marcin@chwedziak.pl>
 */
class X509AuthenticationProviderTest extends WebTestCase
{
    public function testX509Authentication()
    {
        $app = $this->createApplication();

        $client = new Client($app);

        $client->request('get', '/');
        $this->assertEquals(403, $client->getResponse()->getStatusCode());

        $client->request('get', '/', array(), array(), array('TestClientKey' => 'dennis@example.com', 'TestCredentialsKey' => 'foo'));
        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        $this->assertEquals('dennis@example.comAUTHENTICATED', $client->getResponse()->getContent());
        
        $client->request('get', '/admin', array(), array(), array('TestClientKey' => 'dennis@example.com', 'TestCredentialsKey' => 'foo'));
        $this->assertEquals(403, $client->getResponse()->getStatusCode());

        $client->restart();

        $client->request('get', '/', array(), array(), array('TestClientKey' => 'admin@example.com', 'TestCredentialsKey' => 'foo'));
        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        $this->assertEquals('admin@example.comAUTHENTICATEDADMIN', $client->getResponse()->getContent());
        
        $client->request('get', '/admin', array(), array(), array('TestClientKey' => 'admin@example.com', 'TestCredentialsKey' => 'foo'));
        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        $this->assertEquals('admin', $client->getResponse()->getContent());
    }

    public function createApplication()
    {
        $app = new Application();
        $app->register(new SessionServiceProvider());

        $app->register(new SecurityServiceProvider(), array(
            'security.firewalls' => array(
                'x509_cert' => array(
                    'pattern' => '^.*$',
                    'x509' => true,
                    'users' => array(
                        'dennis@example.com' => array('ROLE_USER', null),
                        'admin@example.com'  => array('ROLE_ADMIN', null),
                    ),
                ),
            ),
            'security.access_rules' => array(
                array('^/admin', 'ROLE_ADMIN'),
            ),
            'security.role_hierarchy' => array(
                'ROLE_ADMIN' => array('ROLE_USER'),
            ),
        ));

        $app->register(new X509AuthenticationProvider(), array(
            'security.x509.client_key' => 'TestClientKey',
            'secruity.x509.credentials_key' => 'TestCredentialsKey',
        ));

        $app->get('/', function() use ($app) {
            $user = $app['security']->getToken()->getUser();

            $content = is_object($user) ? $user->getUsername() : 'ANONYMOUS';

            if ($app['security']->isGranted('IS_AUTHENTICATED_FULLY')) {
                $content .= 'AUTHENTICATED';
            }

            if ($app['security']->isGranted('ROLE_ADMIN')) {
                $content .= 'ADMIN';
            }

            return $content;
        });

        $app->get('/admin', function() use ($app) {
            return 'admin';
        });

        $app['session.test'] = true;

        return $app;
    }
}