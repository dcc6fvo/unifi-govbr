<?php

namespace App\Controller;

use App\Utils\Govbr;
use App\Utils\Net;

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class IndexController extends AbstractController
{

    public function __construct(private ParameterBagInterface $params,
                                private LoggerInterface $logger) {}

    public function index(Request $request): Response{

        $session = $request->getSession();
        if (!$session->isStarted()) {
            $session->start();
        }

        // Verificar se já temos MAC na sessão (redirecionamento após erro de auth)
        if ($session->has('mac')) {
            $mac = $session->get('mac');
        } elseif (null !== $request->query->get('id')) {
            // Primeira vez - parâmetros da controladora wifi
            $mac = htmlspecialchars($request->query->get('id'));
            $session->set('mac', $mac);
        } else {
            $this->logger->critical('Erro: Parâmetros wifi não recebidos. Acesse via controladora wifi. ');
            return $this->render('autenticacao/error.html.twig', [
               'mensagem' => 'Não foi possível autenticar. Parâmetros wifi não recebidos. Acesse via controladora wifi.'
            ]);
        }

        // Só definir outros parâmetros se não existirem na sessão (primeira vez)
        if (!$session->has('ap')) {
            $session->set('ap', $request->query->get('ap') ?? '');
        }
        if (!$session->has('t')) {
            $session->set('t', $request->query->get('t') ?? '');
        }
        if (!$session->has('url')) {
            $session->set('url', $request->query->get('url') ?? '');
        }

        // Gerar o Code Verifier e armazenar na sessão
        $codeVerifier = Govbr::generateCodeVerifier();
        $session->set('code_verifier', $codeVerifier);

        // Gerar o Code Challenge
        $codeChallenge = Govbr::generateCodeChallenge($codeVerifier);
        $session->set('code_challenge', $codeChallenge);

        // Determinar qual aba deve estar ativa
        $activeTab = $request->query->get('tab', 'tab-visitantes'); // padrão visitante
        
        return $this->render('autenticacao/login.html.twig', [
                'url_login' => $this->params->get('app.url_login'),
                'active_tab' => $activeTab
        ]);

    }

}

