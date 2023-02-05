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

namespace Bitmotion\Auth0\Controller;

use Auth0\SDK\Auth0;
use Auth0\SDK\Exception\ConfigurationException;
use Bitmotion\Auth0\Domain\Repository\ApplicationRepository;
use Bitmotion\Auth0\Domain\Transfer\EmAuth0Configuration;
use Bitmotion\Auth0\Middleware\CallbackMiddleware;
use Bitmotion\Auth0\Utility\ApiUtility;
use Bitmotion\Auth0\Utility\ParametersUtility;
use Bitmotion\Auth0\Utility\RoutingUtility;
use Bitmotion\Auth0\Utility\TokenUtility;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Context\Exception\AspectNotFoundException;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Extbase\Mvc\Exception\StopActionException;

class LoginController extends ActionController implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    protected string $error = '';

    protected string $errorDescription = '';

    protected Auth0 $auth0;

    protected int $application = 0;

    protected EmAuth0Configuration $extensionConfiguration;

    /**
     * @throws ConfigurationException
     */
    public function initializeAction(): void
    {
        if (!empty(GeneralUtility::_GET('error'))) {
            $this->error = htmlspecialchars((string)GeneralUtility::_GET('error'));
        }

        if (!empty(GeneralUtility::_GET('error_description'))) {
            $this->errorDescription = htmlspecialchars((string)GeneralUtility::_GET('error_description'));
        }

        $this->application = (int)($this->settings['application'] ?? GeneralUtility::_GET('application'));
        $this->auth0 = GeneralUtility::makeInstance(ApiUtility::class, $this->application)->getAuth0($this->getCallback());
        $this->extensionConfiguration = new EmAuth0Configuration();
    }

    /**
     * @throws AspectNotFoundException
     */
    public function formAction(): void
    {
        $context = GeneralUtility::makeInstance(Context::class);

        if ($context->getPropertyFromAspect('frontend.user', 'isLoggedIn')) {
            $userInfo = $this->auth0->getUser();
        }

        $this->view->assignMultiple([
            'userInfo' => $userInfo ?? [],
            'referrer' => GeneralUtility::_GET('referrer') ?? GeneralUtility::_GET('return_url') ?? '',
            'auth0Error' => $this->error,
            'auth0ErrorDescription' => $this->errorDescription,
        ]);
    }

    /**
     * @throws AspectNotFoundException
     * @throws StopActionException
     * @throws ConfigurationException
     */
    public function loginAction(string $rawAdditionalAuthorizeParameters = ''): void
    {
        $context = GeneralUtility::makeInstance(Context::class);
        $userInfo = $this->auth0->getUser();

        // Log in user to auth0 when there is neither a TYPO3 frontend user nor an Auth0 user
        if (!$context->getPropertyFromAspect('frontend.user', 'isLoggedIn') || empty($userInfo)) {
            if (!empty($rawAdditionalAuthorizeParameters)) {
                $additionalAuthorizeParameters = ParametersUtility::transformUrlParameters($rawAdditionalAuthorizeParameters);
            } else {
                $additionalAuthorizeParameters = $this->settings['frontend']['login']['additionalAuthorizeParameters'] ?? [];
            }

            $this->logger->notice('Try to login user.');
            header('Location: ' . $this->auth0->login(null, $additionalAuthorizeParameters));
            exit;
        }

        $this->redirect('form');
    }

    /**
     * @throws StopActionException
     * @throws ConfigurationException
     */
    public function logoutAction(): void
    {
        $application = GeneralUtility::makeInstance(ApplicationRepository::class)->findByUid($this->application);
        $singleLogOut = isset($this->settings['softLogout']) ? !$this->settings['softLogout'] : $application->isSingleLogOut();

        if ($singleLogOut === false) {
            $routingUtility = GeneralUtility::makeInstance(RoutingUtility::class);
            $routingUtility->addArgument('logintype', 'logout');

            if (strpos($this->settings['redirectMode'], 'logout') !== false && (bool)$this->settings['redirectDisable'] === false) {
                $routingUtility->addArgument('referrer', $this->addLogoutRedirect());
            }

            $returnUrl = $routingUtility->getUri();
            $this->redirectToUri($returnUrl);
        }

        $this->logger->notice('Proceed with single log out.');
        $this->auth0->logout();

        $logoutUri = $this->auth0->authentication()->getLogoutLink($this->getCallback('logout'));

        $this->redirectToUri($logoutUri);
    }

    protected function getCallback(string $loginType = 'login'): string
    {
        $uri = $GLOBALS['TYPO3_REQUEST']->getUri();
        $rawReferrer = $GLOBALS['TYPO3_REQUEST']->getQueryParams()['referrer'];
        $referrer = !empty($rawReferrer) ? $rawReferrer : sprintf('%s://%s%s', $uri->getScheme(), $uri->getHost(), $uri->getPath());

        if ($this->settings['referrerAnchor']) {
            $referrer .= '#' . $this->settings['referrerAnchor'];
        }

        $tokenUtility = GeneralUtility::makeInstance(TokenUtility::class);
        $tokenUtility->withPayload('application', $this->application);
        $tokenUtility->withPayload('referrer', $referrer);
        $tokenUtility->withPayload('redirectMode', $this->settings['redirectMode']);
        $tokenUtility->withPayload('redirectFirstMethod', $this->settings['redirectFirstMethod']);
        $tokenUtility->withPayload('redirectPageLogin', $this->settings['redirectPageLogin']);
        $tokenUtility->withPayload('redirectPageLoginError', $this->settings['redirectPageLoginError']);
        $tokenUtility->withPayload('redirectPageLogout', $this->settings['redirectPageLogout']);
        $tokenUtility->withPayload('redirectDisable', $this->settings['redirectDisable']);

        return sprintf(
            '%s%s?logintype=%s&%s=%s',
            $tokenUtility->getIssuer(),
            CallbackMiddleware::PATH,
            $loginType,
            CallbackMiddleware::TOKEN_PARAMETER,
            $tokenUtility->buildToken()->toString()
        );
    }

    protected function addLogoutRedirect(): string
    {
        $routingUtility = GeneralUtility::makeInstance(RoutingUtility::class);

        if (!empty($this->settings['redirectPageLogout'])) {
            $routingUtility->setTargetPage((int)$this->settings['redirectPageLogout']);
        }

        return $routingUtility->getUri();
    }
}
