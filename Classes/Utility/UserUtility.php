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

use Bitmotion\Auth0\Domain\Repository\UserRepository;
use Bitmotion\Auth0\Domain\Transfer\EmAuth0Configuration;
use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Driver\Exception;
use GuzzleHttp\Utils;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Crypto\PasswordHashing\InvalidPasswordHashException;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\SingletonInterface;
use TYPO3\CMS\Core\Utility\ArrayUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class UserUtility implements SingletonInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    protected $extensionConfiguration;

    public function __construct()
    {
        $this->extensionConfiguration = GeneralUtility::makeInstance(EmAuth0Configuration::class);
    }

    /**
     * @throws DBALException
     * @throws Exception
     */
    public function checkIfUserExists(string $tableName, string $auth0UserId): array
    {
        $userRepository = GeneralUtility::makeInstance(UserRepository::class, $tableName);
        $user = $userRepository->getUserByAuth0Id($auth0UserId);

        return $user ?? $this->findUserWithoutRestrictions($tableName, $auth0UserId);
    }

    /**
     * @throws Exception
     * @throws DBALException
     */
    protected function findUserWithoutRestrictions(string $tableName, string $auth0UserId): array
    {
        $this->logger->notice('Try to find user without restrictions.');
        $userRepository = GeneralUtility::makeInstance(UserRepository::class, $tableName);
        $userRepository->removeRestrictions();
        $userRepository->setOrdering('uid', 'DESC');
        $userRepository->setMaxResults(1);
        $user = $userRepository->getUserByAuth0Id($auth0UserId);

        if (!empty($user)) {
            $userRepository = GeneralUtility::makeInstance(UserRepository::class, $tableName);
            $userRepository->updateUserByUid(['disable' => 0, 'deleted' => 0], (int)$user['uid']);

            $this->logger->notice(sprintf('Reactivated user with ID %s.', $user['uid']));
        }

        return $user ?? [];
    }

    /**
     * @throws InvalidPasswordHashException
     * @throws DBALException
     */
    public function insertUser(string $tableName, array $user): void
    {
        switch ($tableName) {
            case 'fe_users':
                $this->insertFeUser($tableName, $user);
                break;
            case 'be_users':
                $this->insertBeUser($tableName, $user);
                break;
            default:
                $this->logger->error(sprintf('"%s" is not a valid table name.', $tableName));
        }
    }

    /**
     * Inserts a new frontend user
     *
     * @throws InvalidPasswordHashException
     * @throws DBALException
     */
    public function insertFeUser(string $tableName, array $user): void
    {
        $values = $this->getTcaDefaults($tableName);
        $userIdentifier = $this->extensionConfiguration->getUserIdentifier();

        ArrayUtility::mergeRecursiveWithOverrule($values, [
            'pid' => $this->extensionConfiguration->getUserStoragePage(),
            'tstamp' => time(),
            'username' => $user['email'] ?? $user[$userIdentifier] ?? $user['user_id'],
            'password' => $this->getPassword(),
            'email' => $user['email'] ?? '',
            'crdate' => time(),
            'auth0_user_id' => $user[$userIdentifier] ?? $user['user_id'],
            'auth0_metadata' => Utils::jsonEncode($user['user_metadata'] ?? ''),
        ]);

        GeneralUtility::makeInstance(UserRepository::class, $tableName)->insertUser($values);
    }

    /**
     * Inserts a new backend user
     *
     * @throws InvalidPasswordHashException
     * @throws DBALException
     */
    public function insertBeUser(string $tableName, array $user): void
    {
        $values = $this->getTcaDefaults($tableName);
        $userIdentifier = $this->extensionConfiguration->getUserIdentifier();

        ArrayUtility::mergeRecursiveWithOverrule($values, [
            'pid' => 0,
            'tstamp' => time(),
            'username' => $user['email'] ?? $user[$userIdentifier],
            'password' => $this->getPassword(),
            'email' => $user['email'] ?? '',
            'crdate' => time(),
            'auth0_user_id' => $user[$userIdentifier],
        ]);

        GeneralUtility::makeInstance(UserRepository::class, $tableName)->insertUser($values);
    }

    protected function getTcaDefaults(string $tableName): array
    {
        $defaults = [];
        $columns = $GLOBALS['TCA'][$tableName]['columns'] ?? [];

        foreach ($columns as $fieldName => $field) {
            if (isset($field['config']['default'])) {
                $defaults[$fieldName] = $field['config']['default'];
            }
        }

        return $defaults;
    }

    /**
     * @throws InvalidPasswordHashException
     */
    protected function getPassword(): string
    {
        $saltFactory = GeneralUtility::makeInstance(PasswordHashFactory::class)->getDefaultHashInstance(TYPO3_MODE);
        $password = GeneralUtility::makeInstance(Random::class)->generateRandomHexString(50);

        return $saltFactory->getHashedPassword($password);
    }

    /**
     * @throws DBALException
     */
    public function setLastUsedApplication(string $auth0UserId, int $application): void
    {
        $userRepository = GeneralUtility::makeInstance(UserRepository::class, 'fe_users');
        $userRepository->updateUserByAuth0Id(['auth0_last_application' => $application], $auth0UserId);
    }
}
