<?php

/*
 * This file is part of the "Auth0" extension for TYPO3 CMS.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * Florian Wessels <f.wessels@Leuchtfeuer.com>, Leuchtfeuer Digital Marketing
 */

namespace Leuchtfeuer\Auth0\EventListener;

use Leuchtfeuer\Auth0\Middleware\CallbackMiddleware;
use TYPO3\CMS\Core\Authentication\Event\BeforeRequestTokenProcessedEvent;
use TYPO3\CMS\Core\Security\RequestToken;

class BeforeRequestTokenProcessed
{
    public function __invoke(BeforeRequestTokenProcessedEvent $event)
    {
        if (!$event->getRequestToken() instanceof RequestToken) {
            $request = $event->getRequest();

            if (str_starts_with($request->getUri()->getPath(), CallbackMiddleware::PATH)) {
                $event->setRequestToken(new RequestToken('core/user-auth/fe'));
            }
        }
    }
}
