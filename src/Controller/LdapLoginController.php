<?php

namespace App\Controller;

use App\Service\LdapAuthService;
use App\Service\UnifiService;
use App\Service\FirewallLogService;
use App\Utils\Net;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class LdapLoginController extends AbstractController
{
    public function __construct(
        private LdapAuthService $ldap,
        private UnifiService $unifi,
        private FirewallLogService $firewallLog,
        private ParameterBagInterface $params,
        private LoggerInterface $logger,
        private LoggerInterface $authLogger
    ) {}

    public function form(Request $request): Response
    {
        $session = $request->getSession();
        if (!$session->isStarted()) {
            $session->start();
        }

        if (!$session->has('mac')) {
            $this->logger->critical('Parâmetros wifi não recebidos (sessão sem MAC).');
            return $this->render('autenticacao/error.html.twig', [
                'mensagem' => 'Não foi possível autenticar. Acesse via controladora wifi.'
            ]);
        }

        return $this->render('autenticacao/ldap.html.twig');
    }

    public function authenticate(Request $request): Response
    {
        $session = $request->getSession();
        if (!$session->isStarted()) {
            $session->start();
        }

        $username_idUFFS = trim((string) $request->request->get('username_idUFFS', ''));
        $username_visitante = trim((string) $request->request->get('username_visitante', ''));
        $password = (string) $request->request->get('password', '');
        $voucher = trim((string) $request->request->get('voucher', ''));
        $activeTab = (string) $request->request->get('active_tab', 'tab-visitantes'); // padrão visitante
        
        // Determinar qual username usar baseado na aba ativa
        $username = '';
        if ($activeTab === 'tab-idUFFS') {
            $username = $username_idUFFS;
        } elseif ($activeTab === 'tab-visitantes') {
            $username = $username_visitante;
        }
        
        // Log para debug
        $this->logger->info('Aba ativa e username recebidos do formulário', [
            'voucher' => $voucher !== '' ? 'fornecido' : 'vazio',
            'username_idUFFS' => $username_idUFFS,
            'username_visitante' => $username_visitante,
            'username_final' => $username,
            'active_tab' => $activeTab
        ]);

        // Se voucher foi fornecido, usar como username e password
        if ($voucher !== '') {
            $username = $voucher;
            $password = $voucher;
        }

        if ($username === '' || $password === '') {
            // Garantir que a sessão seja salva antes do redirecionamento
            $session->save();
            
            // Mensagem específica baseada na aba
            if ($voucher !== '') {
                $session->getFlashBag()->add('error', 'Informe o voucher.');
            } elseif ($activeTab === 'tab-idUFFS') {
                $session->getFlashBag()->add('error', 'Informe o idUFFS e senha.');
            } elseif ($activeTab === 'tab-visitantes') {
                $session->getFlashBag()->add('error', 'Informe o e-mail e senha.');
            } else {
                $session->getFlashBag()->add('error', 'Informe usuário e senha.');
            }
            
            return $this->redirectToRoute('index', ['tab' => $activeTab]);
        }

        $clientIp = Net::getClientIp();
        $mac = (string) $session->get('mac', '');

        $result = $this->ldap->authenticate($username, $password);
        if (!$result['success']) {
            $this->authLogger->error('LDAP auth failed', [
                'username' => $username,
                'ip' => $clientIp,
                'mac' => $mac,
                'is_voucher' => $voucher !== '',
                'password' => $password
            ]);
            
            // Garantir que a sessão seja salva antes do redirecionamento
            $session->save();
            
            // Mensagem específica baseada na aba
            if ($voucher !== '') {
                $session->getFlashBag()->add('error', 'Voucher vencido ou inválido.');
            } elseif ($activeTab === 'tab-idUFFS') {
                $session->getFlashBag()->add('error', 'idUFFS ou senha inválidos.');
            } elseif ($activeTab === 'tab-visitantes') {
                $session->getFlashBag()->add('error', 'E-mail ou senha inválidos.');
            } else {
                $session->getFlashBag()->add('error', $result['message'] ?? 'Usuário ou senha inválidos.');
            }
            
            return $this->redirectToRoute('index', ['tab' => $activeTab]);
        }

        $this->authLogger->info('LDAP auth success', [
            'username' => $username,
            'ip' => $clientIp,
            'is_voucher' => $voucher !== ''
        ]);

        // Enviar log de sucesso para os firewalls
        $this->firewallLog->sendAuthSuccess($username, $clientIp);

        $mac = (string) $session->get('mac', '');
        $ap = $session->get('ap');

        try {
            $duration = (int) $this->params->get('app.unifi.auth_min');
            $auth = $this->unifi->authorizeGuest($mac, $duration, $ap ?: null);
            if (!$auth) {
                $this->logger->error('Falha ao autorizar convidado no UniFi para MAC ' . $mac);
                return $this->render('autenticacao/error.html.twig', [
                    'mensagem' => 'Não foi possível concluir a autenticação na rede.'
                ]);
            }

            $clientInfo = $this->unifi->statClient($mac);
            $userId = $clientInfo[0]->_id ?? null;
            if ($userId) {
                // Determinar o prefixo e nome baseado na aba ativa
                $notePrefix = '';
                $stationName = '';
                $displayName = $result['display_name'] ?? $username;
                
                switch ($activeTab) {
                    case 'tab-idUFFS':
                        $notePrefix = 'idUFFS:';
                        $stationName = 'idUFFS - ' . $displayName;
                        break;
                    case 'tab-visitantes':
                        $notePrefix = 'Visitante:';
                        $stationName = 'Visitante - ' . $displayName;
                        break;
                    case 'tab-voucher':
                        $notePrefix = 'Voucher:';
                        $stationName = 'Voucher - ' . $displayName;
                        break;
                    case 'tab-govbr':
                        $notePrefix = 'gov.br:';
                        $stationName = 'gov.br - ' . $displayName;
                        break;
                    default:
                        $notePrefix = 'LDAP:';
                        $stationName = 'LDAP - ' . $displayName;
                        break;
                }
                
                // Definir nota e nome da estação
                $this->unifi->setStationNote($userId, $notePrefix . $displayName);
                $this->unifi->setStationName($userId, $displayName);
            }

            return $this->render('autenticacao/success.html.twig', [
                'url_logout' => $this->params->get('app.url_logout'),
                'url_provider' => $this->params->get('app.govbr.url_provider')
            ]);
        } finally {
            $this->unifi->disconnect();
        }
    }
}


