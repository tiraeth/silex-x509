X.509 Authentication Security Provider
=============================

The X509AuthenticationProvider provides a X.509 Authentication Listener and bootstraps it so you can easily implement X.509 Certificate authentication in your Silex application.

Parameters
----------

* silex.x509.client_key: (optional) Header key with Client ID (default: SSL_CLIENT_S_DN)
* silex.x509.credentials_key: (optional) Header key with Credentials (default: SSL_CLIENT_S_DN_Email)

Registering
-----------

    use Silex\Application;
    use Silex\Provider\SecurityServiceProvider;
    use Mach\Silex\X509\Provider\X509AuthenticationProvider;

    $app = new Application();
    
    $app->register(new SecurityServiceProvider(), [...]);

    $app->register(new X509AuthenticationProvider());

Example firewall configuration
------------------------------

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
