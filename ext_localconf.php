<?php
defined('TYPO3_MODE') || die('Access denied.');

call_user_func(
    function ($extensionKey) {
        // Load extension configuration
        $configuration = new \Bitmotion\Auth0\Domain\Transfer\EmAuth0Configuration();

        // Get proper subtypes for authentication service
        $subtypes = [];
        if ($configuration->isEnableFrontendLogin()) {
            $subtypes[] = 'authUserFE';
            $subtypes[] = 'getUserFE';

            // Configure Auth0 plugin
            \TYPO3\CMS\Extbase\Utility\ExtensionUtility::configurePlugin(
                'Auth0',
                'LoginForm',
                [\Bitmotion\Auth0\Controller\LoginController::class => 'form, login, logout'],
                [\Bitmotion\Auth0\Controller\LoginController::class => 'form, login, logout']
            );
        }

        if ($configuration->isEnableBackendLogin()) {
            $subtypes[] = 'getUserBE';
            $subtypes[] = 'authUserBE';
        }

        if (!empty($subtypes)) {
            // Get priority for Auth0 Authentication Service
            $highestPriority = 0;

            foreach ($GLOBALS['T3_SERVICES']['auth'] ?? [] as $service) {
                if ($service['priority'] > $highestPriority) {
                    $highestPriority = $service['priority'];
                }
            }

            $overrulingPriority = $highestPriority + 10;

            // Register login provider
            \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addService(
                $extensionKey,
                'auth',
                \Bitmotion\Auth0\Service\AuthenticationService::class,
                [
                    'title' => 'Auth0 authentication',
                    'description' => 'Authentication with Auth0.',
                    'subtype' => implode(',', $subtypes),
                    'available' => true,
                    'priority' => $overrulingPriority,
                    'quality' => $overrulingPriority,
                    'os' => '',
                    'exec' => '',
                    'className' => \Bitmotion\Auth0\Service\AuthenticationService::class
                ]
            );
        }
    }, 'auth0'
);
