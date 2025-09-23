<?php

namespace App\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class DevMockController extends AbstractController
{
    public function __construct(private ParameterBagInterface $params, private LoggerInterface $logger) {}

    public function mock(Request $request): Response
    {
        $env = $this->params->get('kernel.environment');
        if ($env !== 'dev') {
            throw $this->createNotFoundException();
        }

        $session = $request->getSession();
        if (!$session->isStarted()) {
            $session->start();
        }

        $mac = $request->query->get('id', '00:11:22:33:44:55');
        $ap  = $request->query->get('ap', 'AA:BB:CC:DD:EE:FF');
        $t   = $request->query->get('t', (string) time());
        $url = $request->query->get('url', 'http://example.org');

        $session->set('mac', $mac);
        $session->set('ap', $ap);
        $session->set('t', $t);
        $session->set('url', $url);

        $this->logger->info('Sessão de teste populada (mock captive portal).', [ 'mac' => $mac, 'ap' => $ap ]);

        return $this->redirectToRoute('index');
    }
}


