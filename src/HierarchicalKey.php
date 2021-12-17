<?php

namespace Jundayw\Bip44;

use Elliptic\EC;
use Exception;
use InvalidArgumentException;
use RuntimeException;
use Jundayw\Bip32\Buffer;
use Jundayw\Bip32\Hash;

class HierarchicalKey
{
    /**
     * @var int
     */
    private $depth = 0;

    /**
     * @var int
     */
    private $index = 0;

    /**
     * @var string
     */
    private $privateKey;

    /**
     * @var string
     */
    private $publicKey;

    /**
     * @var string
     */
    private $chainCode;

    /**
     * @var string
     */
    private $fingerprint = '00000000';

    /**
     * @var string
     */
    private $parentFingerprint = '00000000';

    /**
     * bip32PrefixMap
     */
    protected $bip32PrefixMap = [
        'BIP32_PREFIX_XPRV' => 0x0488ADE4,
        'BIP32_PREFIX_XPUB' => 0x0488B21E,
    ];

    /**
     * Elliptic curve
     *
     * @EC
     */
    protected $ellipticCurve;

    /**
     * Return the depth of this key. This is limited to 256 sequential derivations.
     *
     * @return int
     */
    public function getDepth(): int
    {
        return $this->depth;
    }

    /**
     * Get the sequence number for this address. Hardened keys are
     * created with sequence > 0x80000000. a sequence number lower
     * than this can be derived with the public key.
     *
     * @return int
     */
    public function getIndex(): int
    {
        return $this->index;
    }

    /**
     * Get private key.
     *
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    /**
     * Get the public key.
     *
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Return the chain code - a deterministic 'salt' for HMAC-SHA512
     * in child derivations
     *
     * @return string
     */
    public function getChainCode()
    {
        return $this->chainCode;
    }

    /**
     * Get the fingerprint of the parent key. For master keys, this is 00000000.
     *
     * @return string
     */
    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    /**
     * Return the fingerprint to be used for child keys.
     *
     * @return string
     */
    public function getParentFingerprint(): string
    {
        return $this->parentFingerprint;
    }

    /**
     * Return whether the key is hardened
     *
     * @return bool
     */
    public function isHardened(): bool
    {
        return ($this->index >> 31) === 1;
    }

    /**
     * HierarchicalKey constructor.
     *
     * @param array $options
     * @throws Exception
     */
    public function __construct($options = [])
    {
        if (!$this->validateOptions($options)) {
            throw new Exception('Invalid options');
        }

        $this->ellipticCurve = new EC('secp256k1');

        if (isset($options['privateKey'])) {
            $this->generateKeysFromPrivate($options['privateKey']);
        }

        if ($this->getDepth() < 0 || $this->getDepth() > IntRange::U8_MAX) {
            throw new InvalidArgumentException('Invalid depth for BIP32 key, must be in range [0 - 255] inclusive');
        }

        if ($this->getIndex() < 0 || $this->getIndex() > IntRange::U32_MAX) {
            throw new InvalidArgumentException('Invalid sequence for BIP32 key, must be in range [0 - (2^31)-1] inclusive');
        }

        if ($this->getParentFingerprint() < 0 || $this->getParentFingerprint() > IntRange::U32_MAX) {
            throw new InvalidArgumentException('Invalid fingerprint for BIP32 key, must be in range [0 - (2^31)-1] inclusive');
        }

        if (strlen($this->getChainCode()) !== 64) {
            throw new RuntimeException('Chaincode should be 64 bytes');
        }
    }

    /**
     * Validate constructor options
     *
     * @param array $options
     * @return bool
     */
    protected function validateOptions(array $options): bool
    {
        $fields = ['depth', 'index', 'privateKey', 'publicKey', 'chainCode', 'fingerprint', 'parentFingerprint'];
        foreach ($options as $field => $option) {
            if (!in_array($field, $fields)) {
                return false;
            }
            $this->{$field} = $option;
        }
        return true;
    }

    /**
     * Generate private key, public key and fingerprint
     *
     * @param string $privateKey
     * @throws Exception
     */
    public function generateKeysFromPrivate(string $privateKey): void
    {
        if (empty($privateKey)) {
            throw new Exception('Invalid private key');
        }

        $this->privateKey  = str_repeat('0', 64 - strlen($privateKey)) . $privateKey;
        $this->publicKey   = $this->getPublicKeyFromPrivate($privateKey);
        $this->fingerprint = $this->computeFingerprint($this->getPublicKey());
    }

    /**
     * Compute public key from private using elliptic curve
     *
     * @param string $privateKey
     * @return string
     */
    protected function getPublicKeyFromPrivate(string $privateKey): string
    {
        $keyPair = new HierarchicalKeyPair($this->ellipticCurve, [
            'priv' => $privateKey,
            'privEnc' => 'hex',
        ]);

        return $keyPair->getPublic(true, 'hex');
    }

    /**
     * Compute fingerprint by public key
     *
     * @param string $publicKey
     * @return string
     */
    protected function computeFingerprint(string $publicKey): string
    {
        $identifier = Helper::hash160($publicKey);
        return Helper::hex_decode(substr($identifier, 0, 8));
    }

    /**
     * Derive HD key by path
     *
     * @param string $path
     * @return HierarchicalKey
     */
    public function derive(string $path): HierarchicalKey
    {
        if (in_array($path, ["m", "M", "m'", "M'"])) {
            return $this;
        }

        $sequences = new HierarchicalKeySequence();
        $entries   = $sequences->decodeRelative($path);

        $HDKey = $this;
        foreach ($entries as $key => $entry) {
            $HDKey = $HDKey->deriveChild($entry);
        }

        return $HDKey;
    }

    /**
     * Derive child key by index
     *
     * @param int $index
     * @return HierarchicalKey
     */
    public function deriveChild(int $index): HierarchicalKey
    {
        [$IL, $IR] = $this->hmac($this->getHmacSeed($index), $this->chainCode);

        $keyPair = new HierarchicalKeyPair($this->ellipticCurve, []);

        try {
            $privateKey = $keyPair->privateKeyTweakAdd($this->getPrivateKey(), $IL, 'hex')->toString('hex');
        } catch (Exception $e) {
            return $this->deriveChild($index + 1);
        }

        $HDKey = new HierarchicalKey([
            'depth' => $this->depth + 1,
            'index' => $index,
            'chainCode' => $IR,
            'parentFingerprint' => $this->getFingerprint(),
        ]);

        $HDKey->generateKeysFromPrivate($privateKey);

        return $HDKey;
    }

    /**
     * Prepare index to hex
     *
     * @param int $index
     * @return string
     */
    protected function convertIndexToHex(int $index): string
    {
        $indexHex = dechex($index);
        return str_repeat('0', 8 - strlen($indexHex)) . $indexHex;
    }

    /**
     * Prepare data string for HMAC hashing
     *
     * @param int $index
     * @return string
     */
    protected function getHmacSeed(int $index)
    {
        $indexHex = $this->convertIndexToHex($index);

        if ($index >> 31 === 1) {
            return $this->privateKeyWithNulls($this->getPrivateKey()) . $indexHex;
        }

        return $this->getPublicKey() . $indexHex;
    }

    /**
     * And nulls for private key
     *
     * @param string $privateKey
     * @return string
     */
    protected function privateKeyWithNulls(string $privateKey): string
    {
        return '00' . $privateKey;
    }

    /**
     * Create HMAC hash and return key/chaincode (IL, IR)
     *
     * @param $data
     * @param $password
     * @return array
     */
    protected function hmac($data, $password): array
    {
        // Generate HMAC hash, and the key/chaincode.
        $I = hash_hmac('sha512', pack('H*', $data), pack('H*', $password));

        return [
            substr($I, 0, 64),
            substr($I, 64, 64),
        ];
    }

    /**
     * Get current private extended key
     *
     * @return string
     */
    public function getPrivateExtendedKey(): string
    {
        return $this->encode($this->bip32PrefixMap['BIP32_PREFIX_XPRV']);
    }

    /**
     * Get current public extended key
     *
     * @return string
     */
    public function getPublicExtendedKey(): string
    {
        return $this->encode($this->bip32PrefixMap['BIP32_PREFIX_XPUB']);
    }

    /**
     * Encode data to base58 by the version
     *
     * @param $bip32PrefixMap
     * @return string
     */
    protected function encode($bip32PrefixMap): string
    {
        $data = [
            dechex($bip32PrefixMap),
            Helper::hex_encode($this->getDepth()),
            Helper::hex_encode(intval($this->getFingerprint()) !== 0 ? $this->getParentFingerprint() : $this->getFingerprint()),
            $this->convertIndexToHex($this->getIndex()),
            $this->getChainCode(),
            ($bip32PrefixMap === $this->bip32PrefixMap['BIP32_PREFIX_XPRV'] ? $this->privateKeyWithNulls($this->getPrivateKey()) : $this->getPublicKey()),
        ];

        $string = implode('', $data);
        if (strlen($string) % 2 !== 0) {
            $string = '0' . $string;
        }

        $bs       = @pack("H*", $string);
        $checksum = hash("sha256", hash("sha256", $bs, true));
        $checksum = substr($checksum, 0, 8);

        return Helper::base58_encode($string . $checksum);
    }

    /**
     * isZeroPrefixed
     *
     * @param string $value
     * @return bool
     */
    public function isZeroPrefixed(string $value): bool
    {
        return (strpos($value, '0x') === 0);
    }

    /**
     * stripZero
     *
     * @param string $value
     * @return string
     */
    public function stripZero(string $value): string
    {
        if ($this->isZeroPrefixed($value)) {
            $count = 1;
            return str_replace('0x', '', $value, $count);
        }
        return $value;
    }

    /**
     * publicKeyToAddress
     *
     * @param string $publicKey
     * @return string
     */
    public function publicKeyToAddress(string $publicKey)
    {
        $publicKey = $this->stripZero($publicKey);

        if (strlen($publicKey) !== 66) {
            throw new InvalidArgumentException('Invalid public key length.');
        }

        return '0x' . $publicKey;
    }
}