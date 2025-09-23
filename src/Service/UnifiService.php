<?php

namespace App\Service;

use UniFi_API\Client;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class UnifiService
{
    private Client $unifi;

    public function __construct(
        private ParameterBagInterface $params,
        private LoggerInterface $logger
    ) {
        $this->initializeClient();
    }

    private function initializeClient(): void
    {
        $client = new Client(
            $this->params->get('app.unifi.unifi_user'),
            $this->params->get('app.unifi.unifi_pass'),
            $this->params->get('app.unifi.controller_url'),
            $this->params->get('app.unifi.site_identifier'),
            $this->params->get('app.unifi.controller_version'),
            false
        );

        if($this->params->get('app.unifi.debug')=='true')
            $client->set_debug(true);

        if (!$client->login()) {
            $this->logger->error('Falha ao conectar no controlador UniFi.');
            throw new \RuntimeException('Não foi possível conectar ao controlador UniFi.');
        }

        $this->unifi = $client;
        $this->logger->info('Conexão com o controlador UniFi estabelecida com sucesso.');
    }

    public function unauthorizeGuest(string $mac): bool{
        
        return $this->unifi->unauthorize_guest($mac);
    }

    public function authorizeGuest(string $mac, int $duration, ?string $ap = null): bool{
        
        return $this->unifi->authorize_guest($mac, $duration, null, null, null, $ap);
    }

    public function statClient(string $mac): array{

        return $this->unifi->stat_client($mac);
    }
    
    public function setStationNote(string $user_id, string $note): bool {

        return $this->unifi->set_sta_note($user_id,$note);
    }

    public function setStationName(string $user_id, string $name): bool {

        return $this->unifi->set_sta_name($user_id, $name);
    }

    public function getClients(): array{

        return $this->unifi->list_clients() ?? [];
    }

    public function getDevice(string $mac): ?array{

        $device = $this->unifi->stat_device($mac);
        return $device[0] ?? null;
    }

    public function disconnect(): void{

        $this->unifi->logout();
        $this->logger->info('Desconexão do controlador UniFi realizada.');
    }
}
