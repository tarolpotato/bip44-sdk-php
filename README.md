# 安装方法
命令行下, 执行 composer 命令安装:
````
composer require jundayw/bip44-sdk-php
````

## Bip44HierarchicalKey
```php

use Jundayw\Bip44\Bip44HierarchicalKey;

$seed = '4076216a6f099f264cf261f1f07892b1851eea6c1c17cc14d13faf6b356cbdd57e137ab5cb88139b575dc29b87692c2db5ff51be8af5fccaea196ca7235bb82c';

$HDKey = Bip44HierarchicalKey::fromEntropy($seed)->derive("44'/60'/0'/0");

echo $HDKey->getPrivateKey();
echo PHP_EOL;
echo $HDKey->getPublicKey();
echo PHP_EOL;
echo $HDKey->getPrivateExtendedKey();
echo PHP_EOL;
echo $HDKey->getPublicExtendedKey();
echo PHP_EOL;
echo $HDKey->publicKeyToAddress($HDKey->getPublicKey());
echo PHP_EOL;
echo PHP_EOL;
for ($i = 0; $i <= 1; $i++) {
    $hdChild = $HDKey->deriveChild($i);
    echo $hdChild->getPrivateKey();
    echo PHP_EOL;
    echo $hdChild->getPublicKey();
    echo PHP_EOL;
    echo $hdChild->getPrivateExtendedKey();
    echo PHP_EOL;
    echo $hdChild->getPublicExtendedKey();
    echo PHP_EOL;
    echo $hdChild->publicKeyToAddress($hdChild->getPublicKey());
    echo PHP_EOL;
}
```
## Online verify
[BIP39 - Mnemonic Code](https://iancoleman.io/bip39/)
