<?php
session_start();
require_once 'config.php';
require_once 'functions.php'; // This line was missing

// --- Correct Database Connection ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed.");
}

// --- Security Headers ---
header("Content-Security-Policy: default-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'self'; media-src 'self';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("Referrer-Policy: strict-origin-when-cross-origin");

// --- Permission Check ---
$settings_stmt = $pdo->query("SELECT setting_key, setting_value FROM settings");
$settings = $settings_stmt->fetchAll(PDO::FETCH_KEY_PAIR);
$role_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];

$view_allowed_role = $settings['view_allowed_roles_audio'] ?? 'user';
$user_role = strtolower($_SESSION['user_role'] ?? 'guest');
$user_level = $role_hierarchy[$user_role] ?? 0;
$required_level = $role_hierarchy[$view_allowed_role] ?? 1;

if ($user_level < $required_level) {
    die("<!DOCTYPE html><html><head><title>Access Denied</title><link rel='stylesheet' href='admin_style.css'></head><body><div class='admin-container' style='text-align:center;'><h2>Access Denied</h2><p>Your user role does not have permission to view this content.</p><a href='chat.php' class='back-link'>Back to Chat</a></div></body></html>");
}

// --- Fetch Audio Data ---
$audio_id = $_GET['view_audio_id'] ?? 0;
if (!$audio_id) { die("Invalid audio file specified."); }

$stmt = $pdo->prepare("SELECT u.*, us.username as uploader_username FROM uploads u JOIN users us ON u.user_id = us.id WHERE u.id = ? AND u.upload_type = 'audio'");
$stmt->execute([$audio_id]);
$audio = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$audio) { die("Audio file not found or you do not have permission."); }

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Audio Player: <?php echo htmlspecialchars($audio['original_filename']); ?></title>
    <link rel="stylesheet" href="admin_style.css">
    <style>
        .audio-player-container { max-width: 800px; margin: 20px auto; padding: 20px; }
        .audio-player { width: 100%; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="admin-container audio-player-container">
        <header>
            <h1>Audio Player</h1>
            <a href="audio_lobby.php" class="back-link">Back to Lobby</a>
        </header>
        
        <div class="image-viewer">
            <h2><?php echo htmlspecialchars($audio['link_text'] ?: $audio['original_filename']); ?></h2>
            
            <audio controls class="audio-player" preload="auto">
                <source src="<?php echo htmlspecialchars($audio['file_path']); ?>" type="audio/mpeg">
                Your browser does not support the audio element.
            </audio>

            <div class="image-stats-bar">
                <span class="stat">Uploader: <strong><?php echo htmlspecialchars($audio['uploader_username']); ?></strong></span>
                <span class="stat">Uploaded: <strong><?php echo date('Y-m-d', strtotime($audio['created_at'])); ?></strong></span>
                <span class="stat">Size: <strong><?php echo round($audio['file_size'] / 1024, 2); ?> KB</strong></span>
            </div>
        </div>
    </div>
</body>
</html>