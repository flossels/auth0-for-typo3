<?php

declare(strict_types=1);

/*
 * This file is part of the "Auth0" extension for TYPO3 CMS.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * Florian Wessels <f.wessels@Leuchtfeuer.com>, Leuchtfeuer Digital Marketing
 */

namespace Bitmotion\Auth0\Utility;

use Auth0\SDK\Auth0;
use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Contract\API\Management\UsersInterface;
use Auth0\SDK\Exception\ConfigurationException;
use Auth0\SDK\Store\SessionStore;
use Bitmotion\Auth0\Domain\Model\Application;
use Bitmotion\Auth0\Domain\Repository\ApplicationRepository;
use Bitmotion\Auth0\Exception\ApiNotEnabledException;
use Bitmotion\Auth0\Middleware\CallbackMiddleware;
use Bitmotion\Auth0\Scope;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\ApplicationType;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class ApiUtility implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    protected array $scope = ['openid', 'profile', 'email'];

    protected Application $application;

    protected Auth0 $auth0;

    public function __construct(int $application)
    {
        $this->application = GeneralUtility::makeInstance(ApplicationRepository::class)->findByUid($application);

        if ($this->application->hasApi()) {
            $this->scope[] = 'read:current_user';
        }
    }

    /**
     * @throws ConfigurationException
     */
    public function getAuth0(string $redirectUri = ''): Auth0
    {
        return new Auth0($this->getSdkConfiguration($redirectUri));
    }

    protected function setScope(array $scopes): void
    {
        if (!empty($scopes)) {
            $reflection = new \ReflectionClass(Scope::class);
            $allowedScopes = $reflection->getConstants();
            $targetScopes = $this->getTargetScopes($scopes, $allowedScopes);

            if (!empty($targetScopes)) {
                $this->scope = $targetScopes;
            }
        }
    }

    /**
     * @throws ConfigurationException
     */
    protected function getSdkConfiguration(string $redirectUri): SdkConfiguration
    {
        $storageId = sprintf('auth0_typo3_%s', $this->getContext());
        $redirectUri = !empty($redirectUri) ? $redirectUri : $this->getCallbackUri();

        $sdkConfiguration = new SdkConfiguration([
            'cookieSecret' => $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'],
            'domain' => $this->application->getDomain(),
            'audience' => [ $this->application->getAudience(true) ],
            'clientId' => $this->application->getClientId(),
            'redirectUri' => $redirectUri,
            'scope' => $this->scope,
            'persistIdToken' => true,
            'persistAccessToken' => true,
            'persistRefreshToken' => true,
            'clientSecret' => $this->application->getClientSecret(),
            'tokenAlgorithm' => $this->application->getSignatureAlgorithm(),
            'sessionStorageId' => $storageId,
            'transientStorageId' => $storageId,
            'cookieExpires' => 60 * 60 * 24
        ]);

        $sessionStore = new SessionStore($sdkConfiguration);
        $sdkConfiguration->setSessionStorage($sessionStore);

        return $sdkConfiguration;
    }

    protected function getCallbackUri(): string
    {
        return GeneralUtility::getIndpEnv('TYPO3_REQUEST_HOST') . CallbackMiddleware::PATH;
    }

    protected function getContext(): string
    {
        if (($GLOBALS['TYPO3_REQUEST'] ?? null) instanceof ServerRequest) {
            return ApplicationType::fromRequest($GLOBALS['TYPO3_REQUEST'])->isFrontend() ? (string)SystemEnvironmentBuilder::REQUESTTYPE_FE : (string)SystemEnvironmentBuilder::REQUESTTYPE_BE;
        }

        return (string)SystemEnvironmentBuilder::REQUESTTYPE_FE;
    }

    protected function getTargetScopes(array $scopes, array $allowedScopes): array
    {
        $targetScopes = [];

        foreach ($scopes as $scope) {
            if (!in_array($scope, $allowedScopes)) {
                $this->logger->warning(sprintf('Scope %s is not allowed.', $scope));
                continue;
            }

            $targetScopes[] = $scope;
        }

        return $targetScopes;
    }

    /**
     * @throws ApiNotEnabledException
     * @throws ConfigurationException
     */
    public function getUserApi(string ...$scopes): UsersInterface
    {
        if (!$this->application->hasApi()) {
            throw new ApiNotEnabledException('Management API is not enabled in Auth0 Application');
        }

        $this->setScope($scopes);

        return $this->getAuth0()->management()->users();
    }
}
