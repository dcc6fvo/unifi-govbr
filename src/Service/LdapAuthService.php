<?php

namespace App\Service;

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class LdapAuthService
{
    public function __construct(
        private ParameterBagInterface $params,
        private LoggerInterface $logger,
        private LoggerInterface $authLogger
    ) {}

    public function authenticate(string $username, string $password): array
    {
        if (!\function_exists('ldap_connect')) {
            $this->logger->critical('Extensão PHP LDAP não está habilitada (função ldap_connect ausente).');
            return [ 'success' => false, 'message' => 'Extensão PHP LDAP não habilitada no servidor' ];
        }

        $host = $this->params->get('app.ldap.host');
        $port = (int) $this->params->get('app.ldap.port');
        $encryption = strtolower((string) $this->params->get('app.ldap.encryption'));
        $baseDn = (string) $this->params->get('app.ldap.base_dn');
        $bindTemplate = (string) $this->params->get('app.ldap.bind_dn_template');

        if (empty($host) || empty($bindTemplate)) {
            $this->logger->error('Configuração LDAP ausente: host ou bind_dn_template.');
            return [ 'success' => false, 'message' => 'Configuração LDAP inválida' ];
        }

        $ldapUri = $encryption === 'ssl' ? 'ldaps://' . $host : 'ldap://' . $host;

        $connection = @\ldap_connect($ldapUri, $port ?: null);
        if ($connection === false) {
            $this->logger->error('Falha ao conectar no servidor LDAP.');
            return [ 'success' => false, 'message' => 'Falha ao conectar no servidor LDAP' ];
        }

        \ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        \ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);

        if ($encryption === 'tls') {
            if (!@\ldap_start_tls($connection)) {
                $this->logger->error('Falha ao iniciar StartTLS no LDAP.');
                @\ldap_unbind($connection);
                return [ 'success' => false, 'message' => 'Falha ao iniciar TLS no LDAP' ];
            }
        }

        $bindDn = str_replace(['{username}', '{base_dn}'], [$username, $baseDn], $bindTemplate);

        $bind = @\ldap_bind($connection, $bindDn, $password);
        if ($bind === false) {
            $error = \ldap_error($connection);
            $this->logger->warning('Autenticação LDAP falhou para usuário ' . $username . ': ' . $error);
            @\ldap_unbind($connection);
            return [ 'success' => false, 'message' => 'Usuário ou senha inválidos' ];
        }

        $displayName = $username;
        if (!empty($baseDn)) {
            $filter = sprintf('(uid=%s)', \ldap_escape($username, '', LDAP_ESCAPE_FILTER));
            $attributes = ['cn', 'displayName', 'sAMAccountName'];
            $search = @\ldap_search($connection, $baseDn, $filter, $attributes) ?: null;
            if ($search) {
                $entries = \ldap_get_entries($connection, $search);
                if ($entries && $entries['count'] > 0) {
                    $entry = $entries[0];
                    $displayName = $entry['displayname'][0] ?? ($entry['cn'][0] ?? ($entry['samaccountname'][0] ?? $username));
                }
            }
        }

        @\ldap_unbind($connection);
        return [ 'success' => true, 'display_name' => $displayName ];
    }
}
