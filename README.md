# PHP Digest Auth library
> [![Downloads](https://img.shields.io/packagist/dt/rakshazi/digestauth.svg)](https://packagist.org/packages/rakshazi/digestauth)
> [![License](https://img.shields.io/packagist/l/rakshazi/digestauth.svg)](https://packagist.org/packages/rakshazi/digestauth)

## Usage
```php
$auth = new \Rakshazi\Digestauth;
$auth->setUsers(array('admin' => 'password'))->setRealm("It's optional")->enable();
```

## Installation

```bash
php composer.phar require rakshazi/digestauth:dev-master
```
