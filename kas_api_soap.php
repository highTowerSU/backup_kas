<?php
declare(strict_types=1);

$opts = getopt('', [
    'wsdl:',
    'endpoint::',
    'action:',
    'login:',
    'auth-type:',
    'auth-data:',
    'otp::',
    'param::',
]);

$required = ['wsdl', 'action', 'login', 'auth-type', 'auth-data'];
foreach ($required as $key) {
    if (!isset($opts[$key]) || $opts[$key] === '') {
        fwrite(STDERR, "Fehlender Parameter --{$key}." . PHP_EOL);
        exit(1);
    }
}

$params = $opts['param'] ?? [];
if (!is_array($params)) {
    $params = [$params];
}

$kasParams = [];
foreach ($params as $pair) {
    if (!is_string($pair) || $pair === '') {
        continue;
    }
    $parts = explode('=', $pair, 2);
    if (count($parts) !== 2) {
        fwrite(STDERR, "Ungültiger Parameter: {$pair}" . PHP_EOL);
        exit(1);
    }
    [$key, $value] = $parts;
    $kasParams[$key] = $value;
}

$clientOptions = [
    'trace' => false,
    'exceptions' => true,
];

if (!empty($opts['endpoint'])) {
    $clientOptions['location'] = $opts['endpoint'];
    $clientOptions['uri'] = 'urn:KasApi';
}

try {
    $client = new SoapClient($opts['wsdl'], $clientOptions);
} catch (Throwable $e) {
    fwrite(STDERR, 'Konnte SoapClient nicht initialisieren: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

$request = [
    'kas_login' => $opts['login'],
    'kas_auth_type' => $opts['auth-type'],
    'kas_auth_data' => $opts['auth-data'],
    'kas_action' => $opts['action'],
    'kas_params' => $kasParams,
];

if (!empty($opts['otp'])) {
    $request['kas_auth_otp'] = $opts['otp'];
}

try {
    $response = $client->KasApi($request);
} catch (Throwable $e) {
    fwrite(STDERR, 'API-Aufruf fehlgeschlagen: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT;
$output = json_encode($response, $flags);

if ($output === false) {
    fwrite(STDERR, 'Konnte SOAP-Antwort nicht als JSON kodieren.' . PHP_EOL);
    exit(1);
}

echo $output . PHP_EOL;
