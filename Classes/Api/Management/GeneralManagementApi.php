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
use Bitmotion\Auth0\Domain\Model\Auth0\Api\Client;
use Bitmotion\Auth0\Domain\Model\Auth0\Api\Error;
use Bitmotion\Auth0\Domain\Model\Auth0\Management\User;
use Bitmotion\Auth0\Exception\UnexpectedResponseException;
use GuzzleHttp\Psr7\Response;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\NameConverter\CamelCaseToSnakeCaseNameConverter;
use Symfony\Component\Serializer\Normalizer\ArrayDenormalizer;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Serializer;
use TYPO3\CMS\Core\Core\Environment;

class GeneralManagementApi implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    protected $client;

    protected $objectNormalizer;

    protected $normalizer = [];

    protected $serializeFormat = 'json';

    protected $extractor;

    protected $defaultContext = [];

    public function __construct(Client $client)
    {
        $this->client = $client;
        $this->objectNormalizer = $this->getObjectNormalizer();
    }

    protected function getObjectNormalizer(): ObjectNormalizer
    {
        return new ObjectNormalizer(
            null,
            new CamelCaseToSnakeCaseNameConverter(),
            null,
            $this->extractor,
            null,
            null,
            $this->defaultContext
        );
    }

    /**
     * @return object|object[]
     * @throws ApiException
     * @throws UnexpectedResponseException
     */
    protected function mapResponse(Response $response, string $objectName = '', bool $returnRaw = false)
    {
        $json = $this->getJsonFromResponse($response);
        $objectName = ($objectName !== '') ? $objectName : $this->getObjectName($response, $returnRaw);

        if ($returnRaw === true && !$objectName !== Error::class) {
            return $json;
        }

        if (substr($json, 0, 1) === '[') {
            $this->normalizer[] = new ArrayDenormalizer();
            $objectName .= '[]';
        }

        $object =  $this->getSerializer()->deserialize($json, $objectName, $this->serializeFormat);

        if ($object instanceof Error) {
            $this->getResponseObject($object);
        }

        if (is_array($object) && count($object) === 1) {
            return array_shift($object);
        }

        return $object;
    }

    protected function getJsonFromResponse(Response $response): string
    {
        $contents = $response->getBody()->getContents();
        json_decode($contents);
        $error = json_last_error();

        if ($error !== JSON_ERROR_NONE) {
            $this->logger->error(
                sprintf(
                    'Unexpected response: %s - Status code: %d (%s)',
                    $contents,
                    $response->getStatusCode(),
                    $response->getReasonPhrase()
                )
            );

            throw new UnexpectedResponseException(
                sprintf(
                    '%s (actual error: "%s"). See log for further details.',
                    mb_substr($contents, 0, 100),
                    json_last_error_msg()
                ),
                $error
            );
        }

        return $contents;
    }

    protected function getSerializer(): Serializer
    {
        return new Serializer(
            array_merge($this->normalizer, [$this->objectNormalizer]),
            [new JsonEncoder()]
        );
    }

    private function getObjectName(Response $response, bool $returnRaw): string
    {
        $statusCode = $response->getStatusCode();

        if ($statusCode !== 200 && $statusCode !== 201) {
            return Error::class;
        }

        if ($returnRaw === true) {
            return '';
        }

        return User::class;
    }

    /**
     * @throws ApiException
     */
    private function getResponseObject(Error $error): void
    {
        $errorMessage = sprintf('%s (%s): %s', $error->getError(), $error->getErrorCode(), $error->getMessage());
        $this->logger->critical($errorMessage);

        if (Environment::getContext()->isProduction()) {
            throw new ApiException('Could not handle request. See log for further details.', 1549382279);
        }

        throw new ApiException($errorMessage, 1549559117);
    }

    protected function addStringProperty(array &$data, string $key, string $value): void
    {
        if ($value !== '') {
            $data[$key] = $value;
        }
    }
}
