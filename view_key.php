<?php
// view_key.php - Displays a user's PGP Public Key

session_start();
require_once 'config.php';

// Security: Only logged-in members can view keys.
if (!isset($_SESSION['user_id']) || ($_SESSION['is_guest'] ?? true)) {
    die("Access Denied. You must be a logged-in member to view PGP keys.");
}

// Security: Ensure a valid user ID is provided.
if (!isset($_GET['user_id']) || !ctype_digit($_GET['user_id'])) {
    die("Invalid user specified.");
}

$user_id_to_view = (int)$_GET['user_id'];

// --- Database Connection ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Error: Could not connect to the database.");
}

// Fetch the key from the database
$stmt = $pdo->prepare("SELECT username, pgp_public_key FROM users WHERE id = ?");
$stmt->execute([$user_id_to_view]);
$key_data = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$key_data || empty($key_data['pgp_public_key'])) {
    die("This user does not have a public key set.");
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>PGP Key for <?php echo htmlspecialchars($key_data['username']); ?></title>
    <link rel="stylesheet" href="style.css?v=1.1">
    <style>
        /* This minimal style ensures the body uses the full viewport */
        html, body {
            height: 100%;
            width: 100%;
            overflow: hidden;
        }
    </style>
</head>
<body>
    <div class="pgp-modal-overlay">
        <div class="pgp-modal-content">
            <a href="chat.php" target="_top" class="close-pgp-button" title="Close">×</a>
            <h2>PGP Public Key for <?php echo htmlspecialchars($key_data['username']); ?></h2>
            <textarea readonly class="pgp-key-display"><?php echo htmlspecialchars($key_data['pgp_public_key']); ?></textarea>
            <a href="chat.php" target="_top" class="pgp-modal-close-link">Close</a>
        </div>
    </div>
</body>
</html>