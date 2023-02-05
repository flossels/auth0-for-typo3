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

namespace Bitmotion\Auth0\Middleware;

use Auth0\SDK\Exception\ArgumentException;
use Auth0\SDK\Exception\ConfigurationException;
use Auth0\SDK\Exception\NetworkException;
use Bitmotion\Auth0\Domain\Repository\ApplicationRepository;
use Bitmotion\Auth0\Domain\Transfer\EmAuth0Configuration;
use Bitmotion\Auth0\ErrorCode;
use Bitmotion\Auth0\Exception\ApiNotEnabledException;
use Bitmotion\Auth0\Exception\TokenException;
use Bitmotion\Auth0\Exception\UnknownErrorCodeException;
use Bitmotion\Auth0\LoginProvider\Auth0Provider;
use Bitmotion\Auth0\Scope;
use Bitmotion\Auth0\Service\RedirectService;
use Bitmotion\Auth0\Utility\ApiUtility;
use Bitmotion\Auth0\Utility\Database\UpdateUtility;
use Bitmotion\Auth0\Utility\TokenUtility;
use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Driver\Exception;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Backend\Utility\BackendUtility;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Context\Exception\AspectNotFoundException;
use TYPO3\CMS\Core\Exception\SiteNotFoundException;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Http\Response;
use TYPO3\CMS\Core\Http\Uri;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class CallbackMiddleware implements MiddlewareInterface
{
    const PATH = '/auth0/callback';

    const TOKEN_PARAMETER = 'token';

    const BACKEND_URI = '%s/typo3/?loginProvider=%d&code=%s&state=%s';

    /**
     * @throws NotFoundExceptionInterface
     * @throws DBALException
     * @throws Exception
     * @throws NetworkException
     * @throws ContainerExceptionInterface
     * @throws UnknownErrorCodeException
     * @throws ConfigurationException
     * @throws SiteNotFoundException
     * @throws ArgumentException
     * @throws ApiNotEnabledException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (strpos($request->getUri()->getPath(), self::PATH) === false) {
            // Middleware is not responsible for given request
            return $handler->handle($request);
        }

        $tokenUtility = GeneralUtility::makeInstance(TokenUtility::class);

        if (!$tokenUtility->verifyToken((string)GeneralUtility::_GET(self::TOKEN_PARAMETER))) {
            return new Response('php://temp', 400);
        }

        try {
            $token = $tokenUtility->getToken();
        } catch (TokenException $exception) {
            return new Response('php://temp', 400);
        }

        if ($token->claims()->get('environment') === TokenUtility::ENVIRONMENT_BACKEND) {
            return $this->handleBackendCallback($request, $tokenUtility);
        }

        return $this->handleFrontendCallback($token);
    }

    protected function handleBackendCallback(ServerRequestInterface $request, TokenUtility $tokenUtility): RedirectResponse
    {
        $queryParams = $request->getQueryParams();

        $redirectUri = sprintf(
            self::BACKEND_URI,
            $tokenUtility->getIssuer(),
            Auth0Provider::LOGIN_PROVIDER,
            $queryParams['code'],
            $queryParams['state']
        );

        // Add error parameters to backend uri if exists
        if (!empty(GeneralUtility::_GET('error')) && !empty(GeneralUtility::_GET('error_description'))) {
            $redirectUri .= sprintf(
                '&error=%s&error_description=%',
                GeneralUtility::_GET('error'),
                GeneralUtility::_GET('error_description')
            );
        }

        return new RedirectResponse($redirectUri, 302);
    }

    /**
     * @throws DBALException
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws ConfigurationException
     * @throws ApiNotEnabledException
     * @throws NotFoundExceptionInterface
     * @throws NetworkException
     * @throws UnknownErrorCodeException
     * @throws SiteNotFoundException
     * @throws ArgumentException
     */
    protected function handleFrontendCallback(Plain $token): RedirectResponse
    {
        $errorCode = (string)GeneralUtility::_GET('error');
        $claims = $token->claims();

        if (!empty($errorCode)) {
            return $this->enrichReferrerByErrorCode($errorCode, $claims);
        }

        $referrer = $claims->get('referrer');

        if ($this->isUserLoggedIn()) {
            $loginType = GeneralUtility::_GET('logintype');
            $application = $claims->get('application');
            $userInfo = GeneralUtility::makeInstance(ApiUtility::class, $application)->getAuth0()->getUser();

            // Redirect when user just logged in (and update him)
            if ($loginType === 'login' && !empty($userInfo)) {
                $this->updateTypo3User($application, $userInfo);

                if ((bool)$claims->get('redirectDisable') === false) {
                    $allowedMethods = ['groupLogin', 'userLogin', 'login', 'getpost', 'referrer'];
                    $this->performRedirectFromPluginConfiguration($claims, $allowedMethods, $referrer);
                } else {
                    return new RedirectResponse($referrer);
                }
            } elseif ($loginType === 'logout') {
                // User was logged out prior to this method. That's why there is no valid TYPO3 frontend user anymore.
                $this->performRedirectFromPluginConfiguration($claims, ['logout', 'referrer'], $referrer);
            }
        }

        // Redirect back to log out page if no redirect was executed before
        return new RedirectResponse($referrer);
    }

    /**
     * @throws UnknownErrorCodeException
     */
    protected function enrichReferrerByErrorCode(string $errorCode, DataSet $claims): RedirectResponse
    {
        if (in_array($errorCode, (new \ReflectionClass(ErrorCode::class))->getConstants())) {
            $referrer = new Uri($claims->get('referrer'));

            $errorQuery = sprintf(
                'error=%s&error_description=%s',
                $errorCode,
                GeneralUtility::_GET('error_description')
            );

            $query = $referrer->getQuery() . (!empty($referrer->getQuery()) ? '&' : '') . $errorQuery;

            return new RedirectResponse($referrer->withQuery($query));
        }

        throw new UnknownErrorCodeException(sprintf('Error %s is unknown.', $errorCode), 1586000737);
    }

    protected function isUserLoggedIn(): bool
    {
        $context = GeneralUtility::makeInstance(Context::class);

        try {
            return (bool)$context->getPropertyFromAspect('frontend.user', 'isLoggedIn');
        } catch (AspectNotFoundException $exception) {
            return false;
        }
    }

    /**
     * @throws ArgumentException
     * @throws Exception
     * @throws DBALException
     * @throws NetworkException
     * @throws ApiNotEnabledException
     * @throws ConfigurationException
     */
    protected function updateTypo3User(int $application, array $user): void
    {
        // Get user
        $application = BackendUtility::getRecord(ApplicationRepository::TABLE_NAME, $application, 'api, uid');

        if ((bool)$application['api'] === true) {
            $userApi = GeneralUtility::makeInstance(ApiUtility::class, $application['uid'])->getUserApi(Scope::USER_READ);
            $user = $userApi->get($user[GeneralUtility::makeInstance(EmAuth0Configuration::class)->getUserIdentifier()]);
        }

        // Update user
        $updateUtility = GeneralUtility::makeInstance(UpdateUtility::class, 'fe_users', $user);
        $updateUtility->updateUser();
        $updateUtility->updateGroups();
    }

    /**
     * @throws NotFoundExceptionInterface
     * @throws SiteNotFoundException
     * @throws Exception
     * @throws DBALException
     * @throws ContainerExceptionInterface
     */
    protected function performRedirectFromPluginConfiguration(DataSet $claims, array $allowedMethods, ?string $referrer = null): void
    {
        $redirectService = new RedirectService([
            'redirectDisable' => false,
            'redirectMode' => $claims->get('redirectMode'),
            'redirectFirstMethod' => $claims->get('redirectFirstMethod'),
            'redirectPageLogin' => $claims->get('redirectPageLogin'),
            'redirectPageLoginError' => $claims->get('redirectPageLoginError'),
            'redirectPageLogout' => $claims->get('redirectPageLogout')
        ]);

        $redirectService->setReferrer($referrer);
        $redirectService->handleRedirect($allowedMethods);
    }
}
