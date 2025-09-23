<?php

namespace App\Controller;

use App\Service\UnifiService;

use App\Utils\Govbr;
use App\Utils\Net;

use Psr\Log\LoggerInterface;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

use UniFi_API\Client;

class LogoutController extends AbstractController
{

    private UnifiService $conn;

    public function __construct(private UnifiService $unifiService,
                                private ParameterBagInterface $params,
                                private LoggerInterface $logger) {
       
        $this->conn=$unifiService;
    }

    public function index(Request $request): Response {

        $session = $request->getSession();
        if (!$session->isStarted()) {
            $session->start();
        }

        if (!$session->has('code_verifier') && !$session->has('mac')) {
            $this->logger->error('Erro: Code Verifier e/ou mac não encontrado na sessão');
            return $this->render('autenticacao/error.html.twig', [
                'mensagem' => 'Erro: Code Verifier e/ou mac não encontrado na sessão.'
            ]);
        }

        try {

            $unauthorize = $this->conn->unauthorizeGuest($session->get('mac'));

            if ($unauthorize) {

                $session->invalidate();   

                $this->logger->info('Cliente desconectado com sucesso.');
                    return $this->render('autenticacao/logout.html.twig');

            }else{
                $this->logger->error('Não foi possível desautorizar o usuario na controladora unifi: ');
                    return [
                    'success' => false,
                    'message' => 'Não foi possível desautorizar o usuario na controladora unifi:  '
                    ]; 

            }

        }catch (Exception $e) {

            $this->logger->error('General Exception in logout: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'General Exception in logout: ' . $e->getMessage()
            ]; 
        }

        finally {
            $this->conn->disconnect();
        } 
    }
}



