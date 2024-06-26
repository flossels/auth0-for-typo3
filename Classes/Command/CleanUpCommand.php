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

namespace Leuchtfeuer\Auth0\Command;

use Auth0\SDK\Exception\ArgumentException;
use Auth0\SDK\Exception\NetworkException;
use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Driver\Exception;
use GuzzleHttp\Exception\GuzzleException;
use Leuchtfeuer\Auth0\Domain\Transfer\EmAuth0Configuration;
use Leuchtfeuer\Auth0\Factory\ApplicationFactory;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\HiddenRestriction;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class CleanUpCommand extends Command implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    protected array $allowedMethods = [
        'disable',
        'delete',
        'deleteIrrevocable',
    ];

    protected array $tableNames = [
        'users' => 'be_users',
        'sessions' => 'be_sessions',
    ];

    protected array $users = [];

    protected string $method = '';

    protected OutputInterface $output;

    protected EmAuth0Configuration $configuration;

    protected function configure(): void
    {
        $this->addArgument('method', InputArgument::REQUIRED, '"disable", "delete" or "deleteIrrevocable"');
    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     * @throws ArgumentException
     * @throws NetworkException
     * @throws DBALException
     * @throws Exception
     */
    public function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->output = $output;

        if (!$this->isInputValid($input)) {
            $output->writeln(sprintf('<error>Unknown method: %s</error>', $input->getArgument('method')));

            return Command::FAILURE;
        }

        if (!$this->isBackendLoginEnabled()) {
            $output->writeln('<error>Backend login is not enabled.</error>');

            return Command::FAILURE;
        }

        if ($this->setUsers()) {
            $output->writeln('<info>No users found.</info>');
        }

        $userCount = $this->updateUsers();

        if ($userCount > 0) {
            $output->writeln(sprintf('<info>Removed %i users from %s</info>', $userCount, $this->tableNames['users']));
        } else {
            $output->writeln(sprintf('<info>No users removed for table %s.</info>', $this->tableNames['users']));
        }

        return Command::SUCCESS;
    }

    protected function isInputValid(InputInterface $input): bool
    {
        if (!in_array($input->getArgument('method'), $this->allowedMethods)) {
            return false;
        }

        $this->method = $input->getArgument('method');

        return true;
    }

    protected function isBackendLoginEnabled(): bool
    {
        $configuration = new EmAuth0Configuration();

        if ($configuration->isEnableBackendLogin() === false) {
            return false;
        }

        $this->configuration = $configuration;

        return true;
    }

    /**
     * @throws Exception
     * @throws DBALException
     */
    protected function setUsers(): bool
    {
        $queryBuilder = $this->getQueryBuilder('users');

        if ($this->method === 'delete') {
            $queryBuilder->getRestrictions()->removeByType(HiddenRestriction::class);
        }

        $this->users = $queryBuilder
            ->select('uid', 'auth0_user_id')
            ->from($this->tableNames['users'])
            ->where($queryBuilder->expr()->neq('auth0_user_id', $queryBuilder->createNamedParameter('')))
            ->execute()
            ->fetchAllAssociative();

        return !empty($this->users);
    }

    /**
     * @throws DBALException
     */
    protected function handleUser(array $user): void
    {
        $queryBuilder = $this->getQueryBuilder('users');

        switch ($this->method) {
            // Set disable flag to 1
            case 'disable':
                $queryBuilder->update($this->tableNames['users'])->set('disable', 1);
                break;

                // Set deleted flag to 1
            case 'delete':
                $queryBuilder->update($this->tableNames['users'])->set('deleted', 1);
                break;

                // Remove record from database
            case 'deleteIrrevocable':
                $queryBuilder->delete($this->tableNames['users']);
                break;
        }

        $queryBuilder
            ->where($queryBuilder->expr()->eq('uid', $user['uid']))
            ->execute();
    }

    protected function getQueryBuilder(string $type): QueryBuilder
    {
        return GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($this->tableNames[$type]);
    }

    /**
     * @throws DBALException
     */
    protected function clearSessionData(array $user): void
    {
        $queryBuilder = $this->getQueryBuilder('sessions');
        $queryBuilder
            ->delete($this->tableNames['sessions'])
            ->where(
                $queryBuilder->expr()->eq(
                    'ses_userid',
                    $queryBuilder->createNamedParameter($user['uid'], \PDO::PARAM_INT)
                )
            )->execute();
    }

    /**
     * @return int
     */
    protected function updateUsers(): int
    {
        $userCount = 0;
        try {
            $auth0 = ApplicationFactory::build($this->configuration->getBackendConnection());
            foreach ($this->users as $user) {
                $auth0User = $auth0->management()->users()->get($user['auth0_user_id']);
                if (isset($auth0User['statusCode']) && $auth0User['statusCode'] === 404) {
                    $this->handleUser($user);
                    $this->clearSessionData($user);
                    $userCount++;
                }
            }
        } catch (\Exception $exception) {
            $this->logger->critical($exception->getMessage());
        } catch (GuzzleException $exception) {
            $this->logger->critical($exception->getMessage());
        }

        return $userCount;
    }
}
