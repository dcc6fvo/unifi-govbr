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

    public function index(): Response {

        session_start();

        if (!isset($_SESSION['code_verifier']) && !isset($_SESSION['mac'])) {
            $this->logger->error('Erro: Code Verifier e/ou mac não encontrado na sessão ' . $e->getMessage());
            return $this->render('unifi/error.html.twig', [
                'mensagem' => 'Erro: Code Verifier e/ou mac não encontrado na sessão.'
            ]);
        }

        try {

            $unauthorize = $this->conn->unauthorizeGuest($_SESSION['mac']);

            if ($unauthorize) {

                session_destroy();   

                $this->logger->info('Cliente desconectado com sucesso.');
                    return $this->render('unifi/logout.html.twig');

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



