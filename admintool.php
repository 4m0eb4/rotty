<?php
/******************************************************************************
 * Rot-Chat Admin Creation Tool (Corrected for Schema)
 *
 * This version uses the correct 'password_hash' column from your db_setup.php.
 * It is self-contained to prevent session and include-related errors.
 *
 * !!! SECURITY WARNING !!!
 * You MUST delete this file from your server immediately after use.
 ******************************************************************************/

// Start the session at the very beginning
session_start();

// Include the database configuration ONLY.
require_once 'config.php';

// Initialize variables
$message = '';
$error = '';
$conn = null;

// --- Handle Form Submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // --- Validation ---
    if (empty($username) || empty($password)) {
        $error = 'Username and password cannot be empty.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    } else {
        try {
            // --- Manual Database Connection ---
            $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
            if ($conn->connect_error) {
                throw new Exception("Connection failed: " . $conn->connect_error);
            }

            // --- Check if user exists ---
            $stmt_check = $conn->prepare("SELECT id FROM users WHERE username = ?");
            if (!$stmt_check) throw new Exception("Prepare failed (check): " . $conn->error);
            $stmt_check->bind_param("s", $username);
            $stmt_check->execute();
            $stmt_check->store_result();

            if ($stmt_check->num_rows > 0) {
                $error = 'Error: This username already exists.';
            } else {
                // --- Create new admin user ---
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $role = 'admin';

                // THE FIX IS HERE: Using 'password_hash' column
                $stmt_insert = $conn->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
                if (!$stmt_insert) throw new Exception("Prepare failed (insert): " . $conn->error);

                $stmt_insert->bind_param("sss", $username, $hashed_password, $role);

                if ($stmt_insert->execute()) {
                    $message = "Success! Admin user '<strong>" . htmlspecialchars($username) . "</strong>' has been created.";
                } else {
                    throw new Exception("Execute failed: " . $stmt_insert->error);
                }
                $stmt_insert->close();
            }
            $stmt_check->close();
            $conn->close();

        } catch (Exception $e) {
            $error = "An error occurred: " . $e->getMessage();
            if ($conn && $conn->ping()) {
                $conn->close();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rot-Chat Admin Creation Tool</title>
    <link rel="stylesheet" href="admin_style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { max-width: 450px; margin: auto; }
        .warning { background-color: #fcf8e3; color: #8a6d3b; padding: 1rem; border: 1px solid #faebcc; border-radius: 4px; margin-bottom: 1rem; text-align: center; }
        .message { padding: 1rem; margin-top: 1rem; border-radius: 4px; text-align: center; }
        .message.success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .message.error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Admin Creation Tool</h1>
        </div>
        <div class="warning">
            <strong>SECURITY RISK:</strong> Delete this file immediately after use.
        </div>

        <?php if ($message): ?>
            <div class="message success"><?php echo $message; ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="message error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form action="admintool.php" method="POST" class="form-container">
            <div class="form-group">
                <label for="username">Admin Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Admin Password (min 8 chars):</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <button type="submit">Create Admin User</button>
            </div>
        </form>
    </div>
</body>
</html>

