# Etapa 1: Build
FROM php:8.4.8-fpm-alpine AS build

# Instala extensões PHP necessárias para Symfony + JSON + cURL
RUN apk add --no-cache --virtual .build-deps \
        $PHPIZE_DEPS \
        icu-dev \
        libxml2-dev \
        oniguruma-dev \
        libzip-dev \
        curl-dev \
        openldap-dev \
        git \
    && docker-php-ext-configure ldap \
    && docker-php-ext-install intl mbstring opcache xml zip curl ldap \
    && apk del .build-deps

# Instala Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Diretório de trabalho da build
WORKDIR /app

# Copia o código da aplicação
COPY . .

# Instala dependências PHP (produção)
RUN composer install --no-dev --optimize-autoloader --no-scripts

# Compila cache do Symfony
RUN php bin/console cache:clear --env=prod --no-debug \
    && php bin/console cache:warmup --env=prod --no-debug

# Etapa 2: Runtime final
FROM php:8.4.8-fpm-alpine

# Instala apenas as bibliotecas de runtime necessárias
RUN apk add --no-cache icu libxml2 oniguruma libzip curl openldap

# Copia os binários PHP (extensões já compiladas, etc) da etapa build
COPY --from=build /usr/local/ /usr/local/

# Copia o app para o diretório de produção
WORKDIR /var/www/html
COPY --from=build /app /var/www/html

RUN chmod 777 var/cache

# Gerando imagem ascii
COPY scripts/ascii.sh /ascii.sh
COPY banner banner
RUN chmod +x /ascii.sh
ENTRYPOINT ["/ascii.sh"]

# Expondo porta FPM
EXPOSE 9000

# Entrada padrão
CMD ["php-fpm"]
