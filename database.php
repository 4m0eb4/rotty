<?php
// database.php

// This function will be the single point of entry for getting a database connection.
function get_database_connection() {
    // Use the global keyword to import variables from the main script's scope.
    global $db_host, $db_name, $db_user, $db_pass;

    // A static variable to ensure we only connect to the database ONCE per page load.
    static $pdo = null;

    if ($pdo === null) {
        try {
            $dsn = "mysql:host={$db_host};dbname={$db_name};charset=utf8mb4";
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];
            $pdo = new PDO($dsn, $db_user, $db_pass, $options);
        } catch (PDOException $e) {
            // In a real production environment, you would log this error, not display it.
            // For now, this is a safe way to handle a connection failure.
            die("Database connection failed. Please check your configuration.");
        }
    }

    return $pdo;
}