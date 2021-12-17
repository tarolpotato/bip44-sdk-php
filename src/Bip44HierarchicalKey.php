<?php

namespace Jundayw\Bip44;

class Bip44HierarchicalKey
{
    /**
     * Generate deterministic key from seed phrase
     *
     * @param string $seed
     * @return HierarchicalKey
     */
    public static function fromEntropy(string $entropy): HierarchicalKey
    {
        // Generate HMAC hash, and the key/chaincode.
        $I  = hash_hmac('sha512', hex2bin($entropy), 'Bitcoin seed');
        $IL = substr($I, 0, 64);
        $IR = substr($I, 64, 64);

        // Return deterministic key
        return new HierarchicalKey([
            'privateKey' => $IL,
            'chainCode' => $IR,
        ]);
    }
}