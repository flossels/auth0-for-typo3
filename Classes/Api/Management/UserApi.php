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

namespace Bitmotion\Auth0\Api\Management;

use Auth0\SDK\Exception\ApiException;
use Auth0\SDK\Exception\CoreException;
use Bitmotion\Auth0\Domain\Model\Auth0\Api\Client;
use Bitmotion\Auth0\Domain\Model\Auth0\Management\User;
use Symfony\Component\PropertyInfo\Extractor\ReflectionExtractor;
use Symfony\Component\Serializer\Normalizer\DateTimeNormalizer;
use TYPO3\CMS\Extbase\Object\Exception;

class UserApi extends GeneralManagementApi
{
    public function __construct(Client $client)
    {
        $this->extractor = new ReflectionExtractor();
        $this->normalizer[] = new DateTimeNormalizer();

        parent::__construct($client);
    }

    /**
     * This endpoint can be used to retrieve user details given the user_id.
     * Required scopes: "read:users read:user_idp_tokens"
     *
     * @param string $id            The user_id of the user to retrieve
     * @param string $fields        A comma separated list of fields to include or exclude (depending on include_fields) from
     *                              the result, empty to retrieve all fields
     * @param bool   $includeFields true if the fields specified are to be included in the result, false otherwise. Defaults to true
     *
     * @throws ApiException
     * @throws Exception
     * @throws CoreException
     * @return User|User[]
     * @see https://auth0.com/docs/api/management/v2#!/Users/get_users_by_id
     */
    public function get(string $id, string $fields = '', bool $includeFields = true)
    {
        $params = [
            'include_fields' => $includeFields,
        ];

        $this->addStringProperty($params, 'fields', $fields);

        $response = $this->client
            ->request(Client::METHOD_GET)
            ->addPath('users')
            ->addPath($id)
            ->withDictParams($params)
            ->setReturnType('object')
            ->call();

        return $this->mapResponse($response);
    }
}
