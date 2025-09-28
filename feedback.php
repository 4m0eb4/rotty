<?php
session_start();
require_once 'functions.php';
require_once 'config.php'; // Use our centralized config

// --- Get Submitter Info ---
$submitter_id = 'Guest';
if (isset($_SESSION['username'])) {
    $submitter_id = $_SESSION['username'];
}



$feedback_message = '';
$feedback_type = '';


// --- Handle Form Submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_feedback'])) {
    // CSRF Token Validation
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        render_csrf_error_page();
    }

    $submission_type = $_POST['submission_type'] ?? 'Other';
    $subject = trim($_POST['subject'] ?? '');
    $content = trim($_POST['content'] ?? '');
    $submitter_ip = get_client_ip();
    $submitter_fingerprint = $_COOKIE['rotchat_fp'] ?? 'unknown'; // Get fingerprint from cookie

    if (empty($subject) || empty($content)) {
        $feedback_message = 'Subject and Content fields cannot be empty.';
        $feedback_type = 'error';
    } else {
        try {
            $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            $stmt = $pdo->prepare("INSERT INTO feedback (submitter_id, submitter_ip, submitter_fingerprint, submission_type, subject, content) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$submitter_id, $submitter_ip, $submitter_fingerprint, $submission_type, $subject, $content]);
            
            $feedback_message = 'Thank you! Your feedback has been submitted successfully.';
            $feedback_type = 'success';

        } catch (PDOException $e) {
            $feedback_message = 'An error occurred while submitting your feedback. Please try again later.';
            $feedback_type = 'error';
            // For debugging: error_log($e->getMessage());
        }
    }
}


?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Feedback & Suggestions</title>
    <link rel="icon" href="/favicon.ico" type="image/x-icon"> </head>
    <link rel="stylesheet" href="admin_style.css"> <style>
        .feedback-form-container { max-width: 700px; }
        .feedback-message-page { text-align: center; padding: 15px; border-radius: 5px; margin-bottom: 20px; font-weight: bold; }
        .feedback-message-page.success { background-color: #004d00; color: #c2ffc2; border: 1px solid #009900; }
        .feedback-message-page.error { background-color: #4d0000; color: #ffc2c2; border: 1px solid #990000; }
    </style>
</head>
<body>
    <div class="admin-container feedback-form-container">
        <header>
            <h1>Feedback & Suggestions</h1>
      
        </header>

        <?php if ($feedback_message): ?>
            <div class="feedback-message-page <?php echo $feedback_type; ?>">
                <?php echo htmlspecialchars($feedback_message); ?>
            </div>
        <?php endif; ?>

        <div class="admin-section">
            <p>Have a suggestion to improve the chat? Found a bug? Let us know! Please be as detailed as possible in your report.</p>
            <form action="feedback.php" method="post">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? ''); ?>">
                <div class="form-group">
                    <label>Your Name</label>
                    <input type="text" value="<?php echo htmlspecialchars($submitter_id); ?>" disabled>
                </div>
                <div class="form-group">
                    <label for="submission_type">Submission Type</label>
                    <select id="submission_type" name="submission_type">
                        <option value="Suggestion">Suggestion</option>
                        <option value="Bug Report">Bug Report</option>
                        <option value="Other">Other</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="subject">Subject</label>
                    <input type="text" id="subject" name="subject" required>
                </div>
                <div class="form-group">
                    <label for="content">Details</label>
                    <textarea id="content" name="content" rows="8" required></textarea>
                </div>
                <button type="submit" name="submit_feedback">Submit Feedback</button>
            </form>
        </div>
    </div>
</body>
</html>