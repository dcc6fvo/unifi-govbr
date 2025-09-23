<?php

namespace App\Controller;

use App\Service\UnifiService;
use App\Service\FirewallLogService;
use App\Utils\Net;
use Psr\Log\LoggerInterface;

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

use UniFi_API\Client;
use UniFi_API\Exceptions\CurlGeneralErrorException;
use UniFi_API\Exceptions\CurlExtensionNotLoadedException;
use UniFi_API\Exceptions\CurlTimeoutException;
use UniFi_API\Exceptions\EmailInvalidException;
use UniFi_API\Exceptions\InvalidBaseUrlException;
use UniFi_API\Exceptions\InvalidCurlMethodException;
use UniFi_API\Exceptions\InvalidSiteNameException;
use UniFi_API\Exceptions\JsonDecodeException;
use UniFi_API\Exceptions\LoginFailedException;
use UniFi_API\Exceptions\LoginRequiredException;
use UniFi_API\Exceptions\MethodDeprecatedException;
use UniFi_API\Exceptions\NotAUnifiOsConsoleException;

use Exception;

class ReturnCallbackController extends AbstractController
{

    private UnifiService $conn;

    public function __construct(private UnifiService $unifiService,
                                private FirewallLogService $firewallLog,
                                private ParameterBagInterface $params,
                                private LoggerInterface $logger) {

        $this->conn=$unifiService;
    }

    public function index(Request $request): Response {

        $session = $request->getSession();
        if (!$session->isStarted()) {
            $session->start();
        }

        if ($session->has('code_verifier')) {
            $codeVerifier = $session->get('code_verifier');
            // Use o $codeVerifier na requisição para o endpoint /token
        } else {
            $this->logger->error('Erro: Code Verifier não encontrado na sessão ');
            return $this->render('autenticacao/error.html.twig', [
                'mensagem' => 'Erro: Code Verifier não encontrado na sessão.'
            ]);
        }

        if (isset($_GET['code'])) {
            $code = $_GET['code'];

            // URL do endpoint de token
            $tokenUrl = $this->params->get('app.govbr.url_provider').'/token';

            $REDIRECT_URI=$this->params->get('app.govbr.redirect_uri');
            $SCOPES=$this->params->get('app.govbr.scopes');
            $CLIENT_ID=$this->params->get('app.govbr.client_id'); 
            $SECRET=$this->params->get('app.govbr.secret');

            // Dados para o POST
            $postData = [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $REDIRECT_URI,
                'client_id' =>  $CLIENT_ID,
                'code_verifier' => $codeVerifier,
                'client_secret' => $SECRET,
            ];

            // Inicializa o cURL
            $ch = curl_init();

            // Configurações do cURL
            curl_setopt($ch, CURLOPT_URL, $tokenUrl);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

            // Executa a requisição
            $response = curl_exec($ch);

            // Verifica erros
            if (curl_errno($ch)) {
                $this->logger->error('Erro na requisição ' . curl_error($ch));
                return $this->render('autenticacao/error.html.twig', [
                    'mensagem' => "Erro na requisição: " . curl_error($ch)
                ]);
                
            } else {
                // Decodifica a resposta JSON
                $responseData = json_decode($response, true);
                //echo "<p>Resposta do servidor:</p>";
                //echo "<pre>" . htmlspecialchars(print_r($responseData, true)) . "</pre>";

                // Verifica se o access_token foi recebido
                if (isset($responseData['id_token'])) {
                    $idToken = $responseData['id_token'];
                    $idTokenParts = explode('.', $idToken);
                    if (count($idTokenParts) === 3) {
                        $payload = base64_decode($idTokenParts[1]);
                        $payloadData = json_decode($payload, true);

                        if (isset($payloadData['picture'])) {
                            $pictureUrl = $payloadData['picture'];
                            $accessToken = $responseData['access_token'];
                            $ch = curl_init();
                            curl_setopt($ch, CURLOPT_URL, $pictureUrl);
                            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                                "Authorization: Bearer $accessToken"
                            ]);
                        
                            $pictureResponse = curl_exec($ch);
                        
                            if (curl_errno($ch)) {
                                $this->logger->error('Erro ao obter a foto: '.curl_error($ch));
                                return $this->render('autenticacao/error.html.twig', [
                                    'mensagem' => 'Erro ao obter a foto: '.curl_error($ch)
                                ]);

                            } else {
                                // Exibe a foto
                                /*$base64Image = base64_encode($pictureResponse);
                                echo "<p>Foto:</p>";
                                echo "<img style='height: 60px;' src='data:image/jpeg;base64,$base64Image' alt='Foto do usuário' />";*/
                            }
                        
                            curl_close($ch);
                        }
                        // Acessa atributos específicos
                        if (isset($payloadData['name'])) {

                            // Outros dados recuperaveis:
                            /*{
                                "sub": "11111111111", //cpf
                                "name": "NAME",
                                "social_name": "SOCIAL NAME",
                                "profile": "https://servicos.staging.acesso.gov.br/",
                                "picture": "https://sso.staging.acesso.gov.br/userinfo/picture",
                                "email": "email@acesso.gov.br",
                                "email_verified": true,
                                "phone_number": "61999999999",
                                "phone_number_verified": true
                            }*/

                            $macSessao = $session->get('mac');
                            $macRetorno = $_GET['state'];

                            if ($macSessao === $macRetorno) {
                               
                                $arr = $this->doAuth($session->get('ap'), $macSessao, 'gov.br:' . $payloadData['sub']);

                                if( $arr['success']){

                                    $this->logger->info('Cliente '.$payloadData['sub'].' conectado.');
                                    
                                    // Enviar log de sucesso para os firewalls
                                    $clientIp = Net::getClientIp();
                                    $this->firewallLog->sendAuthSuccess($payloadData['sub'], $clientIp);
                                    
                                    return $this->render('autenticacao/success.html.twig', [
                                        'url_logout' => $this->params->get('app.url_logout'),
                                        'url_provider' => $this->params->get('app.govbr.url_provider')
                                    ]);
                                    
                                }else{
                                    
                                    $this->logger->error('Erro: ' . $arr['message']);
                                    return $this->render('autenticacao/error.html.twig', [
                                        'mensagem' => $arr['message']
                                    ]);
                                }
                                
                            }

                        }
                    }
                }

                // Verifica se o access_token foi recebido
                if (isset($responseData['access_token'])) {
                    $accessToken = $responseData['access_token'];
                    $tokenParts = explode('.', $accessToken);
                    if (count($tokenParts) === 3) {
                        $payload = base64_decode($tokenParts[1]);
                        $payloadData = json_decode($payload, true);
                
                        // Acessa atributos específicos
                        if (isset($payloadData['sub'])) {

                            $apiUrl = "https://api.staging.acesso.gov.br/confiabilidades/v3/contas/" . $payloadData['sub'] . "/niveis?response-type=ids" ;
                            $ch = curl_init();
                            curl_setopt($ch, CURLOPT_URL, $apiUrl);
                            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                                "Authorization: Bearer $accessToken"
                            ]);
            
                            // Executa a requisição GET
                            $apiResponse = curl_exec($ch);
            
                            if (curl_errno($ch)) {
                                $this->logger->error('Erro na requisição a API ' . $e->getMessage());
                                return $this->render('autenticacao/error.html.twig', [
                                    'mensagem' => 'Erro na requisição à API: '.curl_error($ch)
                                ]);
                        
                            } else {
                                $apiData = json_decode($apiResponse, true);
                                /*echo "<p>Níveis de confiabilidade: (3 - ouro, 2 - prata, 1 - bronze):</p>";
                                echo "<pre>" . htmlspecialchars(print_r($apiData, true)) . "</pre>";*/
                            }
            
                            // Fecha o cURL
                            curl_close($ch);
                        }
                        
                    } else {
                        $this->logger->error('Erro: o access token não é um JWT válido ');
                        return $this->render('autenticacao/error.html.twig', [
                             'mensagem' => 'O Access Token não é um JWT válido.'
                        ]);
            
                    }
                } else {
                    $this->logger->error('Erro: access token não foi recebido ');
                    return $this->render('autenticacao/error.html.twig', [
                        'mensagem' => 'Access Token não foi recebido'
                    ]);
                }
            }

            // Fecha o cURL
            curl_close($ch);
        } else {
            $this->logger->error('Erro: nenhum código foi recebido. ' );
            return $this->render('autenticacao/error.html.twig', [
                'mensagem' => 'Erro: Nenhum código foi recebido.'
            ]);
        }

    }

    public function doAuth(string $ap, string $mac, string $note ): array
    {
        try {
            //$this->params->resolve();
            
            //Autoriza o dispositivo pelo tempo solicitado
            $duration = $this->params->get('app.unifi.auth_min');
            $auth_result = $this->conn->authorizeGuest($mac, $duration, $ap);
            $getid_result = $this->conn->statClient($mac);
            $user_id      = $getid_result[0]->_id;
            // Extrair o nome do usuário (remover o prefixo "gov.br:")
            $userName = str_replace('gov.br:', '', $note);
            $note_result  = $this->conn->setStationNote($user_id, $note);
            $this->conn->setStationName($user_id, $userName);

            return [
                    'success' => true,
                    'message' => 'Usuário autenticado com sucesso'
            ];

        } catch (CurlExtensionNotLoadedException $e) {

            $this->logger->error('CurlExtensionNotLoadedException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'CurlExtensionNotLoadedException: '.$e->getMessage()
            ];

        } catch (InvalidBaseUrlException $e) {
            
            $this->logger->error('InvalidBaseUrlException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'InvalidBaseUrlException: ' . $e->getMessage()
            ];      

        } catch (InvalidSiteNameException $e) {

            $this->logger->error('InvalidSiteNameException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'InvalidSiteNameException: ' . $e->getMessage()
            ]; 

        } catch (JsonDecodeException $e) {

            $this->logger->error('JsonDecodeException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'JsonDecodeException: ' . $e->getMessage()
            ]; 

        } catch (LoginRequiredException $e) {

            $this->logger->error('LoginRequiredException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'LoginRequiredException: ' . $e->getMessage()
            ]; 

        } catch (CurlGeneralErrorException $e) {

            $this->logger->error('CurlGeneralErrorException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'CurlGeneralErrorException: ' . $e->getMessage()
            ]; 

        } catch (CurlTimeoutException $e) {

            $this->logger->error('CurlTimeoutException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'CurlTimeoutException: ' . $e->getMessage()
            ]; 

        } catch (LoginFailedException $e) {

            $this->logger->error('LoginFailedException: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'LoginFailedException: ' . $e->getMessage()
            ]; 

        } catch (Exception $e) {

            $this->logger->error('General Exception: ' . $e->getMessage());
            return [
                    'success' => false,
                    'message' => 'General Exception: ' . $e->getMessage()
            ]; 

        }
        finally {
            $this->conn->disconnect();
        } 
    }

}
