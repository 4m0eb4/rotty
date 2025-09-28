<?php
session_start();
require_once 'config.php';

// --- Correct Database Connection ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed.");
}

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

// --- Fetch Audio Files ---
$audio_files = $pdo->query("SELECT u.id, u.link_text, u.original_filename, u.created_at, us.username as uploader_username FROM uploads u JOIN users us ON u.user_id = us.id WHERE u.upload_type = 'audio' ORDER BY u.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Audio Lobby</title>
    <link rel="stylesheet" href="admin_style.css">
    <style>
        .audio-list-item { display: flex; align-items: center; background: #2a2a2a; padding: 10px 15px; border-radius: 4px; margin-bottom: 10px; text-decoration: none; color: var(--primary-text); transition: background-color 0.2s ease; }
        .audio-list-item:hover { background-color: #383838; }
        .audio-icon { font-size: 1.5em; margin-right: 15px; }
        .audio-info { flex-grow: 1; }
        .audio-info strong { font-size: 1.1em; }
        .audio-info small { color: #aaa; }
        .audio-date { font-size: 0.9em; color: #888; }
    </style>
</head>
<body>
    <div class="admin-container">
        <header>
            <h1>Audio Lobby</h1>
            <a href="chat.php" class="back-link">Back to Chat</a>
        </header>

        <div class="lobby-container">
            <?php if (empty($audio_files)): ?>
                <p style="text-align: center;">No audio files have been uploaded yet.</p>
            <?php else: ?>
                <?php foreach ($audio_files as $file): ?>
                    <a href="audio.php?view_audio_id=<?php echo $file['id']; ?>" class="audio-list-item">
                        <span class="audio-icon">🎵</span>
                        <div class="audio-info">
                            <strong><?php echo htmlspecialchars($file['link_text'] ?: $file['original_filename']); ?></strong><br>
                            <small>Uploaded by: <?php echo htmlspecialchars($file['uploader_username']); ?></small>
                        </div>
                        <div class="audio-date">
                            <?php echo date('Y-m-d', strtotime($file['created_at'])); ?>
                        </div>
                    </a>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>