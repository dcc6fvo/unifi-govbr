<?php

namespace App\Service;

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class FirewallLogService
{
    public function __construct(
        private ParameterBagInterface $params,
        private LoggerInterface $logger
    ) {}

    public function sendAuthSuccess(string $username, string $ip): void
    {
        try {
            $paloAddr = $this->params->get('app.firewall.palo_addr');
            $paloPort = (int) $this->params->get('app.firewall.palo_port');

            if (empty($paloAddr) || empty($paloPort)) {
                $this->logger->warning('Configurações de firewall não definidas, pulando envio de log');
                return;
            }

            $message = '<47> Authentication success User:' . $username . ' Source:' . $ip;

            $this->sendSyslogMessage($message, $paloAddr, $paloPort);

            $this->logger->info('Log de autenticação enviado para firewall', [
                'username' => $username,
                'ip' => $ip,
                'address' => $paloAddr
            ]);

        } catch (\Exception $e) {
            $this->logger->error('Erro ao enviar log para firewall', [
                'username' => $username,
                'ip' => $ip,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function sendSyslogMessage(string $message, string $address, int $port): void
    {
        // Usar file_get_contents com stream context para UDP
        $context = stream_context_create([
            'socket' => [
                'bindto' => '0:0',
            ],
        ]);

        $socket = stream_socket_client(
            "udp://{$address}:{$port}",
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            throw new \RuntimeException("Falha ao conectar via UDP para {$address}:{$port} - {$errstr} ({$errno})");
        }

        $result = fwrite($socket, $message);
        fclose($socket);

        if ($result === false) {
            throw new \RuntimeException("Falha ao enviar mensagem para {$address}:{$port}");
        }
    }
}
