<?php
// emergency_cleanup.php - A dedicated tool for fixing database state issues.
session_start();
require_once 'config.php';

// --- Security Check: Must be a logged-in admin. ---
if (strtolower($_SESSION['user_role'] ?? '') !== 'admin') {
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!DOCTYPE html><html><head><title>Access Denied</title><link rel="stylesheet" href="admin_style.css"></head>
          <body><div class="admin-container" style="max-width: 600px; margin-top: 50px;"><div class="auth-form">
          <h2>ACCESS DENIED</h2><p class="error-message">You do not have permission to access this page.</p>
          <a href="chat.php" target="_top" class="back-link">Return to Chat</a>
          </div></div></body></html>';
    die();
}

// Generate CSRF token if it doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$feedback_message = '';
$feedback_type = 'success';

// --- Handle Form Submissions ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token.');
    }

    if (isset($_POST['clear_all_guest_data'])) {
        $pdo->beginTransaction();
        try {
            // 1. Boot all active guest sessions
            $sessions_cleared = $pdo->exec("DELETE FROM sessions WHERE is_guest = 1");
            
            // 2. Delete all messages sent by guests
            $messages_cleared = $pdo->exec("DELETE FROM messages WHERE guest_id IS NOT NULL");
            
            // 3. Use DELETE which is safer inside a transaction than TRUNCATE
            $guests_cleared = $pdo->exec("DELETE FROM guests");

            $pdo->commit();
            $feedback_message = "SUCCESS: Cleared all guest records ({$guests_cleared}), their messages ({$messages_cleared}), and terminated {$sessions_cleared} active guest sessions.";
        
        } catch (Exception $e) {
            $pdo->rollBack();
            $feedback_message = "ERROR: Could not clear guest data. Transaction rolled back. " . $e->getMessage();
            $feedback_type = 'error';
        }
    }
    if (isset($_POST['clear_stuck_sessions'])) {
        try {
            // This targets any session (guest or member) that has timed out.
            $stmt = $pdo->prepare("DELETE FROM sessions WHERE last_active < NOW() - INTERVAL ? SECOND");
            $stmt->execute([$session_timeout]);
            $sessions_cleared = $stmt->rowCount();
            $feedback_message = "SUCCESS: Cleared {$sessions_cleared} stuck/expired sessions.";
        } catch (Exception $e) {
            $feedback_message = "ERROR: Could not clear stuck sessions. " . $e->getMessage();
            $feedback_type = 'error';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Emergency Cleanup</title>
    <link rel="stylesheet" href="admin_style.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
</head>
<body>
    <div class="admin-container" style="max-width: 800px;">
        <header>
            <h1>Emergency Cleanup</h1>
            <a href="admin.php" class="back-link">Back to Admin Panel</a>
        </header>

        <?php if ($feedback_message): ?>
            <div class="feedback-message" style="background-color: <?php echo $feedback_type === 'success' ? '#004d00' : '#610000'; ?>; border-color: <?php echo $feedback_type === 'success' ? '#009900' : '#990000'; ?>;">
                <?php echo htmlspecialchars($feedback_message); ?>
            </div>
        <?php endif; ?>

        <div class="admin-section">
            <h2>Clear All Guest Data</h2>
            <p>This action will permanently delete **ALL** guest accounts, **ALL** messages sent by guests, and will immediately **kick all currently online guests** from the chat. This cannot be undone.</p>
            <form method="post" onsubmit="return confirm('Are you absolutely sure you want to delete ALL guest data and kick all active guests?');">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <button type="submit" name="clear_all_guest_data" class="danger-btn nuke-btn">NUKE ALL GUEST DATA</button>
            </form>
        </div>

        <div class="admin-section">
            <h2>Clear Stuck & Expired Sessions</h2>
            <p>This will clear any user session (guest or member) that has been inactive longer than the session timeout (<?php echo $session_timeout / 60; ?> minutes). This is useful for fixing "ghost" users who appear online but have left.</p>
            <form method="post" onsubmit="return confirm('Are you sure you want to clear all expired sessions?');">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <button type="submit" name="clear_stuck_sessions" class="danger-btn">Clear Expired Sessions</button>
            </form>
        </div>
    </div>
</body>
</html>