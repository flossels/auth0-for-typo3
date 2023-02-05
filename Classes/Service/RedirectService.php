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

use Bitmotion\Auth0\Event\RedirectPreProcessingEvent;
use Doctrine\DBAL\Connection as ConnectionAlias;
use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Driver\Exception;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Restriction\FrontendRestrictionContainer;
use TYPO3\CMS\Core\Exception\SiteNotFoundException;
use TYPO3\CMS\Core\Log\Logger;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Site\SiteFinder;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\StringUtility;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;

class RedirectService implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    protected array $settings = [];

    protected string $referrer = '';

    public function __construct(array $redirectSettings)
    {
        $this->settings = $redirectSettings;

        if (!$this->logger instanceof Logger) {
            $this->logger = GeneralUtility::makeInstance(LogManager::class)->getLogger(__CLASS__);
        }
    }

    public function setReferrer(string $referrer)
    {
        $this->referrer = $referrer;
    }

    /**
     * @throws NotFoundExceptionInterface
     * @throws SiteNotFoundException
     * @throws Exception
     * @throws DBALException
     * @throws ContainerExceptionInterface
     */
    public function handleRedirect(array $allowedMethods, array $additionalParameters = []): void
    {
        if ((bool)$this->settings['redirectDisable'] === false && !empty($this->settings['redirectMode'])) {
            $this->logger->notice('Try to redirect user.');
            $redirectUris = $this->getRedirectUri($allowedMethods);

            if (!empty($redirectUris)) {
                $redirectUri = $this->addAdditionalParamsToRedirectUri($this->getUri($redirectUris), $additionalParameters);
                $redirectUri = $this->getEventDispatcher()->dispatch(new RedirectPreProcessingEvent($redirectUri, $this))->getRedirectUri();

                $this->logger->notice(sprintf('Redirect to: %s', $redirectUri));
                header('Location: ' . $redirectUri, false, 307);
                die;
            }

            $this->logger->warning('Redirect failed.');
        }
    }

    /**
     * @throws NotFoundExceptionInterface
     * @throws DBALException
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws SiteNotFoundException
     */
    public function forceRedirectByReferrer($additionalParameters = []): void
    {
        $this->setRedirectDisable(false);
        $this->setRedirectMode('referrer');
        $this->handleRedirect(['referrer'], $additionalParameters);
    }

    /**
     * @throws Exception
     * @throws DBALException
     * @throws SiteNotFoundException
     */
    public function getRedirectUri(array $allowedRedirects): array
    {
        $redirect_url = [];

        if ($this->settings['redirectMode']) {
            $redirectMethods = GeneralUtility::trimExplode(',', $this->settings['redirectMode'], true);
            foreach ($redirectMethods as $redirMethod) {
                if (in_array($redirMethod, $allowedRedirects)) {
                    // Logintype is needed because the login-page wouldn't be accessible anymore after a login (would always redirect)
                    switch ($redirMethod) {
                        case 'groupLogin':
                            // taken from dkd_redirect_at_login written by Ingmar Schlecht; database-field changed
                            $groupData = $GLOBALS['TSFE']->fe_user->groupData;
                            if (!empty($groupData['uid'])) {
                                // take the first group with a redirect page
                                $userGroupTable = $GLOBALS['TSFE']->fe_user->usergroup_table;
                                $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($userGroupTable);
                                $queryBuilder->getRestrictions()->removeAll();
                                $row = $queryBuilder
                                    ->select('felogin_redirectPid')
                                    ->from($userGroupTable)
                                    ->where(
                                        $queryBuilder->expr()->neq(
                                            'felogin_redirectPid',
                                            $queryBuilder->createNamedParameter('')
                                        ),
                                        $queryBuilder->expr()->in(
                                            'uid',
                                            $queryBuilder->createNamedParameter(
                                                $groupData['uid'],
                                                ConnectionAlias::PARAM_INT_ARRAY
                                            )
                                        )
                                    )
                                    ->execute()
                                    ->fetchAssociative();
                                if ($row) {
                                    $redirect_url[] = $this->pi_getPageLink($row['felogin_redirectPid']);
                                }
                            }
                            break;

                        case 'userLogin':
                            $userTable = $GLOBALS['TSFE']->fe_user->user_table;
                            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($userTable);
                            $queryBuilder->getRestrictions()->removeAll();
                            $row = $queryBuilder
                                ->select('felogin_redirectPid')
                                ->from($userTable)
                                ->where(
                                    $queryBuilder->expr()->neq(
                                        'felogin_redirectPid',
                                        $queryBuilder->createNamedParameter('')
                                    ),
                                    $queryBuilder->expr()->eq(
                                        $GLOBALS['TSFE']->fe_user->userid_column,
                                        $queryBuilder->createNamedParameter(
                                            $GLOBALS['TSFE']->fe_user->user['uid'],
                                            \PDO::PARAM_INT
                                        )
                                    )
                                )
                                ->execute()
                                ->fetchAssociative();

                            if ($row) {
                                $redirect_url[] = $this->pi_getPageLink($row['felogin_redirectPid']);
                            }
                            break;

                        case 'login':
                            if (isset($this->settings['redirectPageLogin'])) {
                                $redirect_url[] = $this->pi_getPageLink((int)$this->settings['redirectPageLogin']);
                            }
                            break;

                        case 'referrer':
                            $redirect_url[] = $this->validateRedirectUrl($this->referrer ?? GeneralUtility::_GP('referrer'));
                            break;

                        case 'loginError':
                            if ($this->settings['redirectPageLoginError']) {
                                $redirect_url[] = $this->pi_getPageLink((int)$this->settings['redirectPageLoginError']);
                            }
                            break;

                        case 'logout':
                            if (isset($this->settings['redirectPageLogout'])) {
                                $redirect_url[] = $this->pi_getPageLink((int)$this->settings['redirectPageLogout']);
                            }
                            break;

                        case 'getpost':
                            $gpParameters = GeneralUtility::_GPmerged('tx_auth0_loginform');
                            if (isset($gpParameters['redirect']) && !(empty($gpParameters['redirect']))) {
                                $redirect_url[] = $gpParameters['redirect'];
                            }
                            break;
                    }
                }
            }
        }

        // Remove empty values, but keep "0" as value (that's why "strlen" is used as second parameter)
        if (!empty($redirect_url)) {
            return array_filter($redirect_url, 'strlen');
        }

        return [];
    }

    public function getUri(array $redirectUris): string
    {
        return ($this->settings['redirectFirstMethod']) ? array_shift($redirectUris) : array_pop($redirectUris);
    }

    public function setRedirectDisable(bool $value): void
    {
        $this->settings['redirectDisable'] = $value;
    }

    public function setRedirectMode(string $value): void
    {
        $this->settings['redirectMode'] = $value;
    }

    protected function addAdditionalParamsToRedirectUri(string $uri, array $additionalParams): string
    {
        if (!empty($additionalParams)) {
            $uri .= '?';
        }

        foreach ($additionalParams as $key => $value) {
            $uri .= $key . '=' . $value . '&';
        }

        return rtrim($uri, '&');
    }

    /**
     * @throws SiteNotFoundException
     */
    protected function pi_getPageLink(int $id, string $target = '', array $urlParameters = []): string
    {
        if ($GLOBALS['TSFE']->cObj instanceof ContentObjectRenderer) {
            return $GLOBALS['TSFE']->cObj->getTypoLink_URL($id, $urlParameters, $target);
        }

        return (string)GeneralUtility::makeInstance(SiteFinder::class)->getSiteByPageId($id)->getRouter()->generateUri($id);
    }

    /**
     * @throws Exception
     * @throws DBALException
     */
    protected function validateRedirectUrl(string $url): string
    {
        if (empty($url)) {
            return '';
        }
        // Validate the URL:
        if ($this->isRelativeUrl($url) || $this->isInCurrentDomain($url) || $this->isInLocalDomain($url)) {
            return $url;
        }
        // URL is not allowed
        $this->logger->warning('Url "' . $url . '"" for redirect was not accepted!');

        return '';
    }

    /**
     * Determines whether the URL is relative to the
     * current TYPO3 installation.
     */
    protected function isRelativeUrl(string $url): bool
    {
        $parsedUrl = @parse_url($url);
        if ($parsedUrl !== false && !isset($parsedUrl['scheme']) && !isset($parsedUrl['host'])) {
            // If the relative URL starts with a slash, we need to check if it's within the current site path
            return $parsedUrl['path'][0] !== '/' || GeneralUtility::isFirstPartOfStr(
                $parsedUrl['path'],
                GeneralUtility::getIndpEnv('TYPO3_SITE_PATH')
            );
        }

        return false;
    }

    /**
     * Determines whether the URL is on the current host and belongs to the
     * current TYPO3 installation. The scheme part is ignored in the comparison.
     */
    protected function isInCurrentDomain(string $url): bool
    {
        $urlWithoutSchema = preg_replace('#^https?://#', '', $url);
        $siteUrlWithoutSchema = preg_replace('#^https?://#', '', GeneralUtility::getIndpEnv('TYPO3_SITE_URL'));

        return StringUtility::beginsWith($urlWithoutSchema . '/', GeneralUtility::getIndpEnv('HTTP_HOST') . '/')
            && StringUtility::beginsWith($urlWithoutSchema, $siteUrlWithoutSchema);
    }

    /**
     * Determines whether the URL matches a domain
     * in the sys_domain database table.
     *
     * @throws DBALException
     * @throws Exception
     */
    protected function isInLocalDomain(string $url): bool
    {
        $result = false;
        if (GeneralUtility::isValidUrl($url)) {
            $parsedUrl = parse_url($url);
            if ($parsedUrl['scheme'] === 'http' || $parsedUrl['scheme'] === 'https') {
                $host = $parsedUrl['host'];
                // Removes the last path segment and slash sequences like /// (if given):
                $path = preg_replace('#/+[^/]*$#', '', $parsedUrl['path']);

                $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('sys_domain');
                $queryBuilder->setRestrictions(GeneralUtility::makeInstance(FrontendRestrictionContainer::class));
                $localDomains = $queryBuilder->select('domainName')
                    ->from('sys_domain')
                    ->execute()
                    ->fetchAllAssociative();

                if (is_array($localDomains)) {
                    foreach ($localDomains as $localDomain) {
                        // strip trailing slashes (if given)
                        $domainName = rtrim($localDomain['domainName'], '/');
                        if (GeneralUtility::isFirstPartOfStr($host . $path . '/', $domainName . '/')) {
                            $result = true;
                            break;
                        }
                    }
                }
            }
        }

        return $result;
    }

    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    protected function getEventDispatcher(): EventDispatcherInterface
    {
        return GeneralUtility::getContainer()->get(EventDispatcherInterface::class);
    }
}
