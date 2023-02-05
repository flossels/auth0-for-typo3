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

namespace Bitmotion\Auth0\Service;

use Auth0\SDK\Auth0;
use Auth0\SDK\Exception\Auth0Exception;
use Bitmotion\Auth0\Domain\Transfer\EmAuth0Configuration;
use Bitmotion\Auth0\Exception\ApiNotEnabledException;
use Bitmotion\Auth0\Exception\TokenException;
use Bitmotion\Auth0\LoginProvider\Auth0Provider;
use Bitmotion\Auth0\Middleware\CallbackMiddleware;
use Bitmotion\Auth0\Scope;
use Bitmotion\Auth0\Utility\ApiUtility;
use Bitmotion\Auth0\Utility\Database\UpdateUtility;
use Bitmotion\Auth0\Utility\TokenUtility;
use Bitmotion\Auth0\Utility\UserUtility;
use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Driver\Exception;
use GuzzleHttp\Utils;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Authentication\AuthenticationService as BasicAuthenticationService;
use TYPO3\CMS\Core\Crypto\PasswordHashing\InvalidPasswordHashException;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class AuthenticationService extends BasicAuthenticationService
{
    protected array $user = [];

    protected array $userInfo = [];

    protected string $tableName = 'fe_users';

    protected array $auth0User;

    protected Auth0 $auth0;

    protected int $application = 0;

    protected string $userIdentifier = '';

    /**
     * @throws InvalidPasswordHashException
     * @throws DBALException
     * @throws Exception
     */
    public function initAuth($mode, $loginData, $authInfo, $pObj): void
    {
        if ($this->isResponsible($authInfo['loginType']) === false || $this->login['responsible'] === false) {
            $this->logger->debug('Auth0 authentication is not responsible for this request.');
            return;
        }

        if ($this->initApplication($authInfo['loginType']) === false) {
            $this->logger->debug('Initialization of Auth0 application failed.');
            return;
        }

        // Set default values
        $this->setDefaults($authInfo, $mode, $loginData, $pObj);

        if ($this->initializeAuth0Connections()) {
            $this->handleLogin();
        }
    }

    protected function isResponsible(string $loginType): bool
    {
        $responsible = true;

        // Service is not responsible when environment is in backend mode and the given loginProvider does not match the expected one.
        if ($loginType === 'BE' && (int)GeneralUtility::_GP('loginProvider') !== Auth0Provider::LOGIN_PROVIDER) {
            $this->logger->debug('Not an Auth0 backend login. Skip.');
            $responsible = false;
        }

        // Check whether there was an error during Auth0 calls
        $auth0ErrorCode = GeneralUtility::_GET('error') ?? '';

        if ($auth0ErrorCode) {
            $this->logger->notice('Access denied. Skip. Error: ' . $auth0ErrorCode);
            $responsible = false;
        }

        return $responsible;
    }

    protected function initApplication(string $loginType): bool
    {
        $extensionConfiguration = GeneralUtility::makeInstance(EmAuth0Configuration::class);
        $this->userIdentifier = $extensionConfiguration->getUserIdentifier();

        switch ($loginType) {
            case 'FE':
                $this->logger->info('Handle frontend login.');
                $this->application = $this->retrieveApplicationFromUrlQuery();
                $this->tableName = 'fe_users';
                break;

            case 'BE':
                $this->logger->info('Handle backend login.');
                $this->application = $extensionConfiguration->getBackendConnection();
                $this->tableName = 'be_users';
                break;

            default:
                $this->logger->error('Environment is neither in frontend nor in backend mode.');
        }

        if ($this->application === 0) {
            $this->logger->error('No Auth0 application UID given.');

            return false;
        }

        return true;
    }

    protected function retrieveApplicationFromUrlQuery(): int
    {
        $application = (int)GeneralUtility::_GET('application');

        if ($application !== 0) {
            return $application;
        }

        $tokenUtility = GeneralUtility::makeInstance(TokenUtility::class);

        if (!$tokenUtility->verifyToken((string)GeneralUtility::_GET(CallbackMiddleware::TOKEN_PARAMETER))) {
            return 0;
        }

        try {
            $token = $tokenUtility->getToken();
        } catch (TokenException $exception) {
            return 0;
        }

        return (int)$token->claims()->get('application');
    }

    protected function setDefaults(array $authInfo, string $mode, array $loginData, AbstractUserAuthentication $pObj): void
    {
        $authInfo['db_user']['check_pid_clause'] = false;
        $loginData['responsible'] = false;

        $this->db_user = $authInfo['db_user'];
        $this->authInfo = $authInfo;
        $this->mode = $mode;
        $this->login = $loginData;
        $this->pObj = $pObj;
    }

    /**
     * @throws InvalidPasswordHashException
     * @throws DBALException
     * @throws Exception
     */
    protected function handleLogin(): void
    {
        if ($this->login['responsible'] === true) {
            switch ($this->mode) {
                case 'getUserFE':
                case 'getUserBE':
                    $this->insertOrUpdateUser();
                    break;
                case 'authUserFE':
                case 'authUserBE':
                    $this->logger->debug(sprintf('Skip auth mode "%s".', $this->mode));
                    break;
                default:
                    $this->logger->notice(sprintf('Undefined mode "%s". Skip.', $this->mode));
            }
        }
    }

    protected function getAuth0User(): bool
    {
        try {
            $apiUtility = GeneralUtility::makeInstance(ApiUtility::class, $this->application);
            $userApi = $apiUtility->getUserApi(Scope::CURRENT_USER_READ);
            $this->auth0User = Utils::jsonDecode($userApi->get($this->userInfo[$this->userIdentifier])->getBody()->__toString(), true);
        } catch (ApiNotEnabledException $exception) {
            // Do nothing since API is disabled
        } catch (Auth0Exception $apiException) {
            $this->logger->error('No Auth0 user found.');

            return false;
        }

        return true;
    }

    /**
     * @throws InvalidPasswordHashException
     * @throws DBALException
     * @throws Exception
     */
    protected function insertOrUpdateUser(): void
    {
        $userUtility = GeneralUtility::makeInstance(UserUtility::class);
        $this->user = $userUtility->checkIfUserExists($this->tableName, $this->userInfo[$this->userIdentifier]);

        // Insert a new user into database
        if (empty($this->user)) {
            $this->logger->notice('Insert new user.');
            $userUtility->insertUser($this->tableName, $this->auth0User ?? $this->userInfo);
        }

        $updateUtility = GeneralUtility::makeInstance(UpdateUtility::class, $this->tableName, $this->auth0User ?? $this->userInfo);
        $updateUtility->updateGroups();

        // Update existing user on every login when we are in BE context (since TypoScript is loaded).
        if ($this->authInfo['loginType'] === 'BE') {
            $updateUtility->updateUser();
        } else {
            // Update last used application (no TypoScript loaded in Frontend Requests)
            $userUtility->setLastUsedApplication($this->userInfo[$this->userIdentifier], $this->application);
        }
    }

    /**
     * Initializes the connection to the Auth0 server
     */
    protected function initializeAuth0Connections(): bool
    {
        try {
            $this->auth0 = GeneralUtility::makeInstance(ApiUtility::class, $this->application)->getAuth0();
            $userInfo = $this->auth0->getUser() ?? [];

            if (!$userInfo && $this->auth0->getExchangeParameters()) {
                $this->auth0->exchange();
                $userInfo = $this->auth0->getUser() ?? [];
            }

            $this->userInfo = $userInfo;

            if (!isset($this->userInfo[$this->userIdentifier]) || $this->getAuth0User() === false) {
                return false;
            }

            $this->login['responsible'] = true;
            $this->logger->notice(sprintf('Found user with Auth0 identifier "%s".', $this->userInfo[$this->userIdentifier]));

            return true;
        } catch (\Exception $exception) {
            $this->logger->emergency(sprintf('Error %s: %s', $exception->getCode(), $exception->getMessage()));
        }

        return false;
    }

    /**
     * @return bool|mixed
     */
    public function getUser()
    {
        if ($this->login['status'] !== 'login' || $this->login['responsible'] === false || !isset($this->userInfo[$this->userIdentifier])) {
            return false;
        }

        $user = $this->fetchUserRecord($this->login['uname'], 'auth0_user_id = "' . $this->userInfo[$this->userIdentifier] . '"');

        if (!is_array($user)) {
            $this->auth0->clear();
            $this->writelog(255, 3, 3, 2, 'Login-attempt from ###IP###, username \'%s\' not found!!', [$this->login['uname']]);
            $this->logger->info(
                sprintf('Login-attempt from username "%s" not found!', $this->login['uname']),
                [
                    'REMOTE_ADDR' => $this->authInfo['REMOTE_ADDR'],
                ]
            );
        }

        return $user;
    }

    public function authUser(array $user): int
    {
        if ($this->login['responsible'] === false) {
            // Service is not responsible. Check other services.
            return 100;
        }

        if (empty($user['auth0_user_id']) || $user['auth0_user_id'] !== $this->userInfo[$this->userIdentifier]) {
            // Verification failed as identifier does not match. Maybe other services can handle this login.
            return 100;
        }

        // Do not log in if email address is not verified (only available if API is enabled)
        if ($this->userInfo && !$this->userInfo['email_verified']) {
            $this->logger->warning('Email not verified. Do not login user.');

            // Responsible, authentication failed, do NOT check other services
            return 0;
        }

        // Success
        $this->logger->notice(sprintf('Auth0 User %s (UID: %s) successfully logged in.', $user['auth0_user_id'], $user['uid']));
        return 200;
    }
}
