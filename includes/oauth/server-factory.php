<?php

// SPDX-FileCopyrightText: 2026 Elementor MCP <dev@elementormcp.com>
// SPDX-License-Identifier: GPL-2.0-or-later

declare(strict_types=1);

namespace ElementorMCP\OAuth\ServerFactory;

use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use ElementorMCP\OAuth\ClientValidation;
use ElementorMCP\OAuth\Keys;
use ElementorMCP\OAuth\Repositories\AccessTokenRepository;
use ElementorMCP\OAuth\Repositories\AuthCodeRepository;
use ElementorMCP\OAuth\Repositories\ClientRepository;
use ElementorMCP\OAuth\Repositories\RefreshTokenRepository;
use ElementorMCP\OAuth\Repositories\ScopeRepository;
use Psr\Http\Message\ServerRequestInterface;

if (!defined('ABSPATH')) {
    exit();
}

/**
 * Accepts an ephemeral port on a registered http://localhost redirect at the consent and token
 * steps, matching what the authorize endpoint already allowed through.
 */
// @mago-expect lint:file-name
final class LoopbackAuthCodeGrant extends AuthCodeGrant
{
    protected function validateRedirectUri(
        string $redirectUri,
        ClientEntityInterface $client,
        ServerRequestInterface $request,
    ): void {
        if (ClientValidation\localhost_redirect_matches((array) $client->getRedirectUri(), $redirectUri)) {
            return;
        }

        parent::validateRedirectUri($redirectUri, $client, $request);
    }
}

function build_authorization_server(): AuthorizationServer
{
    $keys = Keys\get();
    $server = new AuthorizationServer(
        new ClientRepository(),
        new AccessTokenRepository(),
        new ScopeRepository(),
        $keys['private'],
        $keys['encryption'],
    );

    $authCodeGrant = new LoopbackAuthCodeGrant(
        new AuthCodeRepository(),
        new RefreshTokenRepository(),
        new DateInterval('PT1M'),
    );
    $authCodeGrant->setRefreshTokenTTL(new DateInterval('P14D'));
    // PKCE is required by default for public clients in league v9 — no explicit call needed.

    $server->enableGrantType($authCodeGrant, new DateInterval('PT1H'));

    $refreshGrant = new RefreshTokenGrant(new RefreshTokenRepository());
    $refreshGrant->setRefreshTokenTTL(new DateInterval('P14D'));
    $server->enableGrantType($refreshGrant, new DateInterval('PT1H'));

    return $server;
}

function build_resource_server(): ResourceServer
{
    return new ResourceServer(new AccessTokenRepository(), Keys\get()['public']);
}
