<?php
// config.php - Centralized Database Configuration

$db_host = 'your_database_host';
$db_name = 'your_database_name';
$db_user = 'your_database_user';
$db_pass = 'your_database_password';

// --- General Configuration ---
$session_timeout = 300; // 5 minutes - Users will be timed out after 5 mins of inactivity.
$kick_cooldown_minutes = 5; // The duration of a soft-ban/cooldown after being kicked by a mod.

// --- PDO Connection Object (Optional but Recommended) ---
// You can create the PDO object here to be used globally, or just keep the variables.
// For this project's structure, we will stick to including the variables.
?>