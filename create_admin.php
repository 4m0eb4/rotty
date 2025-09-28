<?php
// create_admin.php - A temporary script to create the first administrator account.
// !! WARNING: DELETE THIS FILE IMMEDIATELY AFTER USE !!

ini_set('display_errors', 1);
error_reporting(E_ALL);

// --- HTML & Form ---
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Include necessary files only when the form is submitted.
    require_once 'config.php';
    require_once 'database.php';

    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if (empty($username) || empty($password)) {
        $message = "<p class='error'>Username and password cannot be empty.</p>";
    } else {
        try {
            $pdo = get_database_connection();

            // Check if ANY user exists. If so, abort for safety.
            $stmt = $pdo->query("SELECT id FROM users LIMIT 1");
            if ($stmt->fetch()) {
                 $message = "<p class='error'>An admin account (or other user) already exists. This script can only be used on a fresh installation. Please delete this file.</p>";
            } else {
                // Hash the password securely.
                $password_hash = password_hash($password, PASSWORD_ARGV2ID);

                // Insert the new admin user.
                $stmt = $pdo->prepare(
                    "INSERT INTO users (username, password_hash, role, color) VALUES (:username, :password_hash, 'admin', '#ff0000')"
                );
                $stmt->execute([
                    ':username' => $username,
                    ':password_hash' => $password_hash
                ]);

                $message = "<p class='success'>Admin user '{$username}' created successfully!</p>" .
                           "<h2><span class='error'>SECURITY WARNING:</span> Please delete this `create_admin.php` file from your server NOW.</h2>";
            }
        } catch (PDOException $e) {
            $message = "<p class='error'>Database error: " . $e->getMessage() . "</p>";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Create Admin Account</title>
    <style>
        body { font-family: monospace; background: #111; color: #eee; padding: 20px; text-align: center; }
        .container { max-width: 400px; margin: 50px auto; padding: 20px; border: 1px solid #555; border-radius: 5px; background: #222; }
        h1 { color: #ff5555; }
        label { display: block; margin-bottom: 10px; color: #aaa; }
        input[type="text"], input[type="password"] { width: calc(100% - 20px); padding: 10px; margin-bottom: 20px; background: #333; border: 1px solid #555; color: #eee; border-radius: 3px; }
        button { background: #ff5555; color: #fff; border: none; padding: 12px 20px; border-radius: 3px; cursor: pointer; font-size: 16px; }
        button:hover { background: #cc0000; }
        .success { color: #7f7; background: #252; padding: 10px; border-radius: 3px; }
        .error { color: #f77; background: #522; padding: 10px; border-radius: 3px; }
        .warning { color: yellow; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Create First Admin User</h1>
        <p class="warning">!! This script should only be run once on a new installation !!</p>
        <hr style="border-color: #333;">

        <?php if (!empty($message)) echo $message; ?>

        <form action="create_admin.php" method="POST">
            <label for="username">Admin Username:</label>
            <input type="text" id="username" name="username" required>

            <label for="password">Admin Password:</label>
            <input type="password" id="password" name="password" required>

            <button type="submit">Create Admin</button>
        </form>
         <p style="margin-top: 20px; color: #aaa;">After creating the admin, you MUST delete this file from your server.</p>
    </div>
</body>
</html>