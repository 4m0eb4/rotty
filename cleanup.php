<?php
// cleanup.php - A tool for admins to remove expired files and associated data.
ini_set('display_errors', 1);
error_reporting(E_ALL);

session_start();
require_once 'config.php';
require_once 'database.php';

// --- Security Check: Must be a logged-in admin. ---
if (strtolower($_SESSION['user_role'] ?? '') !== 'admin') {
    die("Access Denied. You must be an administrator to run this tool.");
}

// Generate CSRF token if it doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$pdo = get_database_connection();
$feedback_message = '';
$files_deleted_count = 0;

// --- Handle Form Submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token. Please return to the admin panel and try again.');
    }

    if (isset($_POST['run_cleanup'])) {
        $pdo->beginTransaction();
        try {
            // Find all files that have expired either by time or by view count
            $stmt_expired = $pdo->query("
                SELECT id, unique_filename, user_id 
                FROM uploads 
                WHERE (expires_at IS NOT NULL AND expires_at < NOW()) 
                   OR (max_views > 0 AND current_views >= max_views)
            ");
            
            $expired_files = $stmt_expired->fetchAll(PDO::FETCH_ASSOC);
            $files_deleted_count = count($expired_files);

            if ($files_deleted_count > 0) {
                foreach ($expired_files as $file) {
                    $upload_id = $file['id'];
                    $user_id = $file['user_id'];
                    
                    // 1. Delete the original chat message(s)
                    $message_tag1 = '[VIEWFILE%id=' . $upload_id . ']%';
                    $message_tag2 = '%id=' . $upload_id . ']%'; // For IMAGE, DOC, ZIP tags
                    $delete_msg_stmt = $pdo->prepare("DELETE FROM messages WHERE (message LIKE ? OR message LIKE ?) AND user_id = ?");
                    $delete_msg_stmt->execute([$message_tag1, $message_tag2, $user_id]);

                    // 2. Delete associated comments and votes
                    $pdo->prepare("DELETE FROM upload_comments WHERE upload_id = ?")->execute([$upload_id]);
                    $pdo->prepare("DELETE FROM votes WHERE item_type = 'upload' AND item_id = ?")->execute([$upload_id]);

                    // 3. Delete the physical file
                    $filePath = __DIR__ . '/uploads/' . $file['unique_filename'];
                    if (file_exists($filePath)) {
                        @unlink($filePath);
                    }
                    
                    // 4. Delete the main upload record
                    $pdo->prepare("DELETE FROM uploads WHERE id = ?")->execute([$upload_id]);
                }
            }
            
            $pdo->commit();
            if ($files_deleted_count > 0) {
                $feedback_message = "Cleanup successful! Removed {$files_deleted_count} expired file(s) and all associated data.";
            } else {
                $feedback_message = "No expired files found to clean up.";
            }

        } catch (Exception $e) {
            $pdo->rollBack();
            $feedback_message = "An error occurred during cleanup: " . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Expired File Cleanup</title>
    <link rel="stylesheet" href="admin_style.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
</head>
<body>
    <div class="admin-container" style="max-width: 800px;">
        <header>
            <h1>Expired File Cleanup</h1>
            <a href="admin.php?section=chat-tools" class="back-link">Back to Admin Panel</a>
        </header>

        <?php if ($feedback_message): ?>
            <div class="feedback-message success" style="margin-bottom: 20px;">
                <?php echo htmlspecialchars($feedback_message); ?>
            </div>
        <?php endif; ?>

        <div class="admin-section">
            <h2>Run Cleanup Process</h2>
            <p>This tool will find and permanently delete all files that have expired due to their set time or view limits. This process will remove:</p>
            <ul>
                <li>The original chat message link.</li>
                <li>All comments and votes on the file.</li>
                <li>The physical file from the server.</li>
                <li>The file's record from the database.</li>
            </ul>
            <p><strong>This action cannot be undone.</strong></p>
            <form method="post" onsubmit="return confirm('Are you sure you want to permanently delete all expired files?');">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <button type="submit" name="run_cleanup" class="danger-btn nuke-btn">RUN EXPIRED FILE CLEANUP</button>
            </form>
        </div>
    </div>
</body>
</html>