<?php
// upload_handler.php (V22 - Hardcoded Types & Detailed Debugging)

ini_set('display_errors', 0);
error_reporting(E_ALL);

session_start();
require_once 'config.php';
require_once 'database.php';
require_once 'functions.php';

// A simple function to show an error and stop the script
function terminate_with_error($message) {
    die('
        <!DOCTYPE html><html><head><title>Upload Error</title><link rel="stylesheet" href="style.css"></head>
        <body><div class="auth-container"><div class="auth-form">
        <h2 style="color: #ff3333;">Upload Failed</h2>
        <p class="error-message">' . $message . '</p> <!-- Removed htmlspecialchars to allow HTML in error -->
        <a href="chat.php" target="_top">Return to Chat</a>
        </div></div></body></html>
    ');
}

// --- 0. Initial Security and Setup ---
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    render_csrf_error_page("Invalid submission token. Please refresh the main chat page and try uploading again.");
}
if (!isset($_SESSION['user_id']) || ($_SESSION['is_guest'] ?? true)) {
    terminate_with_error("You must be a logged-in member to upload files.");
}
if (!isset($_POST['submit_upload']) || !isset($_FILES['file_upload']) || $_FILES['file_upload']['error'] !== UPLOAD_ERR_OK) {
    terminate_with_error("File upload error. Please try again. Code: " . ($_FILES['file_upload']['error'] ?? 'N/A'));
}

// --- NEW: Filename Length Check ---
if (strlen($_FILES['file_upload']['name']) > 50) {
    terminate_with_error("Filename cannot exceed 50 characters.");
}

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    terminate_with_error("Database connection failed. Please contact an administrator.");
}
$settings = $pdo->query("SELECT setting_key, setting_value FROM settings")->fetchAll(PDO::FETCH_KEY_PAIR);
$role_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];
$user_id = $_SESSION['user_id'];
$user_role = strtolower($_SESSION['user_role'] ?? 'guest');

// --- NEW: Daily Upload Limit Check ---
if ($user_role !== 'admin') {
    $limit_key = 'upload_limit_' . $user_role;
    $daily_limit = (int)($settings[$limit_key] ?? 0);

    if ($daily_limit > 0) {
        $stmt_count = $pdo->prepare("SELECT COUNT(*) FROM uploads WHERE user_id = ? AND created_at >= NOW() - INTERVAL 1 DAY");
        $stmt_count->execute([$user_id]);
        $uploads_today = $stmt_count->fetchColumn();

        if ($uploads_today >= $daily_limit) {
            terminate_with_error("You have reached your daily upload limit of {$daily_limit} files.");
        }
    }
}
$settings = $pdo->query("SELECT setting_key, setting_value FROM settings")->fetchAll(PDO::FETCH_KEY_PAIR);
$role_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];
$user_id = $_SESSION['user_id'];
$user_role = strtolower($_SESSION['user_role'] ?? 'guest');
$file = $_FILES['file_upload'];
$file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

// --- 1. Determine File Type & BBCode Tag (FIXED) ---
$doc_exts   = ['pdf', 'txt', 'doc', 'docx'];
$zip_exts   = ['zip'];
$img_exts   = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4'];
$audio_exts = ['mp3']; // Added audio type

$upload_type    = null;
$bbcode_tag     = null;
$permission_key = null;

if (in_array($file_extension, $doc_exts)) {
    $upload_type = 'document';
    $bbcode_tag = 'DOC';
    $permission_key = 'upload_allowed_roles_docs';
} elseif (in_array($file_extension, $zip_exts)) {
    $upload_type = 'zip';
    $bbcode_tag = 'ZIP';
    $permission_key = 'upload_allowed_roles_zips';
} elseif (in_array($file_extension, $img_exts)) {
    $upload_type = 'image';
    $bbcode_tag = 'IMAGE';
    $permission_key = 'upload_allowed_roles';
} elseif (in_array($file_extension, $audio_exts)) {
    $upload_type = 'audio';
    $bbcode_tag = 'AUDIO';
    $permission_key = 'upload_allowed_roles_audio';
}

if ($upload_type === null) {
    terminate_with_error("Unsupported file type: ." . htmlspecialchars($file_extension));
}

// --- 2. Check Permissions ---
$allowed_role = $settings[$permission_key] ?? 'admin';
if (!isset($role_hierarchy[$user_role]) || $role_hierarchy[$user_role] < $role_hierarchy[$allowed_role]) {
    terminate_with_error("Your role does not have permission to upload this file type.");
}

// --- 3. Save the file and create the database record ---
$file_hash = hash_file('sha256', $file['tmp_name']);
$stmt_check_hash = $pdo->prepare("SELECT id, upload_type, link_text, original_filename FROM uploads WHERE file_hash = ?");
$stmt_check_hash->execute([$file_hash]);
$existing_upload = $stmt_check_hash->fetch(PDO::FETCH_ASSOC);

$item_id_for_link = 0;
$link_text = '';

if ($existing_upload) {
    $item_id_for_link = $existing_upload['id'];
    // Use the raw filename; it will be encoded on display
    $link_text = trim($_POST['link_name'] ?? '') ?: $existing_upload['link_text'] ?: $existing_upload['original_filename'];
    
    // Re-evaluate viewer page for existing uploads based on its correct type from DB
    $existing_type = $existing_upload['upload_type'];
    if ($existing_type === 'document') { $viewer_page = 'docs.php'; $viewer_param = 'view_doc_id'; }
    elseif ($existing_type === 'zip') { $viewer_page = 'zips.php'; $viewer_param = 'view_zip_id'; }
    else { $viewer_page = 'gallery.php'; $viewer_param = 'view_image_id'; }

} else {
    // New file: Validate size and save it
    $allowed_extensions = explode(',', strtolower($settings['allowed_file_types'] ?? ''));
    $max_size_kb = (int)($settings['max_file_size_kb'] ?? 2048);
    if ($file['size'] > ($max_size_kb * 1024)) terminate_with_error("File exceeds the {$max_size_kb} KB size limit.");
    if (!in_array($file_extension, $allowed_extensions)) terminate_with_error("File extension '.{$file_extension}' is not in the allowed list.");

    $upload_dir = 'uploads/';
    if (!is_dir($upload_dir) || !is_writable($upload_dir)) terminate_with_error("Server configuration error: Upload directory is not writable.");
    
    $unique_filename = uniqid('file_', true) . '.' . $file_extension;
    $destination_path = $upload_dir . $unique_filename;
    
    if (move_uploaded_file($file['tmp_name'], $destination_path)) {
        
        try {
            // Use the raw filename for the database record
            $link_text = trim($_POST['link_name'] ?? '') ?: basename($file['name']);
            $expires_at = !empty($_POST['expires_in_days']) && ctype_digit($_POST['expires_in_days']) ? date('Y-m-d H:i:s', strtotime("+" . (int)$_POST['expires_in_days'] . " days")) : null;
            $max_views = !empty($_POST['max_views']) && ctype_digit($_POST['max_views']) ? (int)$_POST['max_views'] : null;

            $params_to_insert = [
                $user_id,
                $upload_type,
                basename($file['name']),
                $unique_filename,
                $destination_path,
                mime_content_type($destination_path),
                $file['size'],
                $file_hash,
                $link_text,
                $expires_at,
                $max_views
            ];

            $stmt = $pdo->prepare("INSERT INTO uploads (user_id, upload_type, original_filename, unique_filename, file_path, mime_type, file_size, file_hash, link_text, expires_at, max_views) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute($params_to_insert);
            
            $item_id_for_link = $pdo->lastInsertId();

        } catch (PDOException $e) {
            if (file_exists($destination_path)) unlink($destination_path);
            
            $error_details = "Database error during upload record creation: " . $e->getMessage();
            terminate_with_error($error_details);
        }
    } else {
        terminate_with_error("Failed to move uploaded file. Check server permissions for the 'uploads' directory.");
    }
}

// --- 4. Build the Correct Link and Post to Chat (FIXED) ---
// Re-assign the correct BBCode tag if the uploaded file was a duplicate of an existing one
if ($existing_upload) {
    switch ($existing_upload['upload_type']) {
        case 'document': $bbcode_tag = 'DOC'; break;
        case 'zip':      $bbcode_tag = 'ZIP'; break;
        case 'audio':    $bbcode_tag = 'AUDIO'; break;
        default:         $bbcode_tag = 'IMAGE'; break;
    }
}

$message_to_send = "[{$bbcode_tag} id={$item_id_for_link}]";

$pdo->prepare("INSERT INTO messages (user_id, username, color, message, channel) VALUES (?, ?, ?, ?, ?)")
    ->execute([$user_id, $_SESSION['username'], $_SESSION['color'], $message_to_send, $_SESSION['current_channel'] ?? 'general']);

header('Location: chat.php');
exit();
?>
