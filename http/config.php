<?php
// config.php

// Load credentials from Environment Variables (Best Practice) or fall back to defaults

// Make sure to place outside your webtree
$host = getenv('DB_HOST') ?: ''; // CHANGE THIS
$db   = getenv('DB_NAME') ?: ''; // CHANGE THIS
$user = getenv('DB_USER') ?: ''; // CHANGE THIS
$pass = getenv('DB_PASS') ?: ''; // CHANGE THIS
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    // In production, log this to a file instead of showing the user
    throw new \PDOException($e->getMessage(), (int)$e->getCode());
}
?>
