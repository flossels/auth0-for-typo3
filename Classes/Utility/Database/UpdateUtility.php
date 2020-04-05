<?php
declare(strict_types = 1);
namespace Bitmotion\Auth0\Utility\Database;

/***
 *
 * This file is part of the "Auth0" extension for TYPO3 CMS.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 *  (c) 2018 Florian Wessels <f.wessels@Leuchtfeuer.com>, Leuchtfeuer Digital Marketing
 *
 ***/

use Bitmotion\Auth0\Domain\Model\Auth0\Management\User;
use Bitmotion\Auth0\Domain\Repository\UserRepository;
use Bitmotion\Auth0\Domain\Transfer\EmAuth0Configuration;
use Bitmotion\Auth0\Utility\ConfigurationUtility;
use Bitmotion\Auth0\Utility\ParseFuncUtility;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Symfony\Component\Serializer\NameConverter\CamelCaseToSnakeCaseNameConverter;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Serializer;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Configuration\Exception\InvalidConfigurationTypeException;

class UpdateUtility implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    const TYPO_SCRIPT_NODE_VALUE = '_typoScriptNodeValue';

    /**
     * @var string
     */
    protected $tableName = '';

    /**
     * @var User
     */
    protected $user;

    /**
     * @var ParseFuncUtility
     */
    protected $parseFuncUtility;

    public function __construct(string $tableName, User $user)
    {
        $this->tableName = $tableName;
        $this->user = $user;
    }

    public function updateGroups(): void
    {
        try {
            $groupMapping = ConfigurationUtility::getSetting('roles', $this->tableName);
        } catch (\Exception $exception) {
            $this->logger->error($exception->getCode() . ': ' . $exception->getMessage());

            return;
        }

        if (empty($groupMapping)) {
            $this->logger->error(sprintf('Cannot update user groups: No role mapping for %s found', $this->tableName));

            return;
        }

        $shouldUpdate = false;
        $isBeAdmin = false;
        $groupsToAssign = [];

        // Map Auth0 roles on TYPO3 user groups
        $this->mapRoles($groupMapping, $groupsToAssign, $isBeAdmin, $shouldUpdate);

        // Update user only if necessary
        if ($shouldUpdate === true) {
            $this->logger->notice('Update user groups.');
            $this->performGroupUpdate($groupsToAssign, $isBeAdmin);
        }
    }

    public function updateUser(bool $reactivateUser = false): void
    {
        try {
            // Get mapping configuration
            $mappingConfiguration = ConfigurationUtility::getSetting('propertyMapping', $this->tableName);
        } catch (\Exception $exception) {
            $this->logger->error($exception->getCode() . ': ' . $exception->getMessage());

            return;
        }

        if (empty($mappingConfiguration)) {
            $this->logger->error(sprintf('Cannot update user: No mapping configuration for %s found', $this->tableName));

            return;
        }

        $this->performUserUpdate($mappingConfiguration, $reactivateUser);
    }

    protected function mapRoles(array $groupMapping, array &$groupsToAssign, bool &$isBeAdmin, bool &$shouldUpdate): void
    {
        try {
            // TODO: Support dot syntax for roles; e.g. roles.application
            $rolesKey = ConfigurationUtility::getSetting('roles', 'key') ?? 'roles';
        } catch (InvalidConfigurationTypeException $exception) {
            $rolesKey = 'roles';
        }

        foreach ($this->user->getAppMetadata()[$rolesKey] ?? [] as $role) {
            if (isset($groupMapping[$role])) {
                if ($this->tableName === 'be_users' && $groupMapping[$role] === 'admin') {
                    $isBeAdmin = true;
                } else {
                    $this->logger->notice(sprintf('Assign group "%s" to user.', $groupMapping[$role]));
                    $groupsToAssign[] = $groupMapping[$role];
                }
                $shouldUpdate = true;
            } else {
                $this->logger->warning(sprintf('No mapping for Auth0 role "%s" found.', $role));
            }
        }
    }

    protected function performGroupUpdate(array $groupsToAssign, bool $isBeAdmin): void
    {
        $updates = [];

        // Update usergroup in database
        if (!empty($groupsToAssign)) {
            $updates['usergroup'] = implode(',', $groupsToAssign);
        }

        // Set admin flag for backend users
        if ($this->tableName === 'be_users') {
            $updates['admin'] = (int)$isBeAdmin;
        }

        if (!empty($updates)) {
            $userRepository = GeneralUtility::makeInstance(UserRepository::class, $this->tableName);
            $userRepository->updateUserByAuth0Id($updates, $this->user->getUserId());
        }
    }

    protected function performUserUpdate(array $mappingConfiguration, bool $reactivateUser): void
    {
        $this->logger->debug(sprintf('%s: Prepare update for Auth0 user "%s"', $this->tableName, $this->user->getUserId()));

        $updates = [];
        $userRepository = GeneralUtility::makeInstance(UserRepository::class, $this->tableName);

        $this->mapUserData($updates, $mappingConfiguration);

        // Fixed values
        if ($reactivateUser) {
            $updates['disable'] = 0;
            $updates['deleted'] = 0;
        }

        $this->addRestrictions($userRepository);
        $userRepository->updateUserByAuth0Id($updates, $this->user->getUserId());
    }

    protected function addRestrictions(UserRepository &$userRepository): void
    {
        $emConfiguration = GeneralUtility::makeInstance(EmAuth0Configuration::class);
        $reactivateDeleted = false;
        $reactivateDisabled = false;

        if ($this->tableName === 'fe_users') {
            $reactivateDeleted = $emConfiguration->isReactivateDeletedFrontendUsers();
            $reactivateDisabled = $emConfiguration->isReactivateDisabledFrontendUsers();
        } elseif ($this->tableName === 'be_users') {
            $reactivateDeleted = $emConfiguration->isReactivateDeletedBackendUsers();
            $reactivateDisabled = $emConfiguration->isReactivateDisabledBackendUsers();
        } else {
            $this->logger->notice('Undefined environment');
        }

        if ($reactivateDeleted === false) {
            $userRepository->addDeletedRestriction();
        }

        if ($reactivateDisabled === false) {
            $userRepository->addDisabledRestriction();
        }
    }

    protected function mapUserData(array &$updates, array $mappingConfiguration): void
    {
        $this->parseFuncUtility = $parseFuncUtility = GeneralUtility::makeInstance(ParseFuncUtility::class);
        $normalizer = new ObjectNormalizer(null, new CamelCaseToSnakeCaseNameConverter());
        $serializer = new Serializer([$normalizer]);
        $user = $serializer->normalize($this->user, 'array');
        $value = false;

        foreach ($mappingConfiguration as $typo3FieldName => $auth0FieldName) {
            if (!is_array($auth0FieldName)) {
                // Update without parsing function
                $value = $this->parseFuncUtility->updateWithoutParseFunc($auth0FieldName, $user);
            } elseif (is_array($auth0FieldName) && isset($auth0FieldName[self::TYPO_SCRIPT_NODE_VALUE])) {
                // Update with parsing function
                $value = $this->parseFuncUtility->updateWithParseFunc($typo3FieldName, $auth0FieldName, $user);
            }

            if ($value !== false) {
                $updates[$typo3FieldName] = $value;
            }
        }
    }
}
