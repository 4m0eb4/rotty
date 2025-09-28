<?php
session_start();
require_once 'config.php'; // Use our centralized config

// --- Fingerprint Handling for Voters ---
// This ensures every browser has a unique ID to prevent duplicate votes.
$voter_fingerprint = $_COOKIE['rotchat_fp'] ?? null;
if (!$voter_fingerprint) {
    // Generate a fingerprint consistent with the main chat application.
    // This requires including the functions.php file.
    require_once 'functions.php';
    $voter_fingerprint = generate_header_fingerprint();
    
    // Set cookie for 10 years, httpOnly for security.
    setcookie('rotchat_fp', $voter_fingerprint, time() + (10 * 365 * 24 * 60 * 60), "/", "", false, true);
    $_COOKIE['rotchat_fp'] = $voter_fingerprint; // Make it available on this page load
}

// --- Database Connection ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Could not connect to the database.");
}

// --- Generate CSRF Token ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Handle Vote Submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_vote'])) {
    // CSRF Token Validation
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    render_csrf_error_page();
}

    $poll_id = $_POST['poll_id'] ?? null;
    $vote_value = (int)($_POST['submit_vote']); // +1 for upvote, -1 for downvote

    if ($poll_id && in_array($vote_value, [1, -1])) {
        // Use INSERT...ON DUPLICATE KEY UPDATE to handle new votes and vote changes.
        // The UNIQUE index on (poll_id, voter_fingerprint) makes this work.
        $sql = "INSERT INTO poll_votes (poll_id, voter_fingerprint, vote) VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE vote = VALUES(vote)";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$poll_id, $voter_fingerprint, $vote_value]);

        $_SESSION['poll_feedback'] = "Your vote has been counted!";
    }
    
    // Redirect to prevent form resubmission on refresh
    header("Location: polls.php#poll-" . $poll_id);
    exit;
}

// --- Fetch Polls, Vote Counts, and Admin Replies ---
// This query now also joins the users table to get the admin's username for the reply.
$polls_query = "
    SELECT
        f.id, f.subject, f.content, f.submitter_id, f.created_at,
        f.admin_reply, f.replied_at,
        u.username as replied_by_username,
        (SELECT COUNT(*) FROM poll_votes WHERE poll_id = f.id AND vote = 1) as upvotes,
        (SELECT COUNT(*) FROM poll_votes WHERE poll_id = f.id AND vote = -1) as downvotes
    FROM feedback f
    LEFT JOIN users u ON f.replied_by_user_id = u.id
    WHERE f.is_poll = 1
    ORDER BY (upvotes - downvotes) DESC, f.created_at DESC
";
$polls = $pdo->query($polls_query)->fetchAll(PDO::FETCH_ASSOC);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Polls & Suggestions</title>
    <link rel="stylesheet" href="admin_style.css">
    <style>
        .poll-container { margin-bottom: 25px; }
        .poll-header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #444; padding-bottom: 10px; margin-bottom: 15px;}
        .poll-header h3 { margin: 0; color: #ff5555; }
        .poll-content { line-height: 1.6; }
        .poll-actions { margin-top: 15px; display: flex; align-items: center; gap: 15px; }
        .vote-form { display: inline-block; margin: 0; }
        .vote-btn { padding: 5px 15px; font-size: 1.2em; font-weight: bold; line-height: 1; }
        .vote-btn.up { background-color: #004d00; color: #c2ffc2; border-color: #009900; }
        .vote-btn.down { background-color: #610000; color: #ffc2c2; border-color: #990000; }
        .vote-count { font-size: 1.2em; font-weight: bold; }
        .vote-count.positive { color: #7f7; }
        .vote-count.negative { color: #f77; }
        .feedback-message-page { text-align: center; padding: 15px; border-radius: 5px; margin-bottom: 20px; font-weight: bold; background-color: #004d00; color: #c2ffc2; border: 1px solid #009900; }
    </style>
</head>
<body>
    <div class="admin-container">
        <header>
            <h1>Polls & Suggestions</h1>
            <a href="chat.php" class="back-link">Back to Chat</a>
            <link rel="icon" href="/favicon.ico" type="image/x-icon"> </head>
        </header>

        <?php 
        // Display feedback message if a vote was just cast
        if (isset($_SESSION['poll_feedback'])) {
            echo '<div class="feedback-message-page">' . htmlspecialchars($_SESSION['poll_feedback']) . '</div>';
            unset($_SESSION['poll_feedback']); // Clear the message after displaying it
        }
        ?>

<?php if (empty($polls)): ?>
    <div class="admin-section">
        <p>There are no active polls at the moment. Check back later!</p>
    </div>
<?php else: ?>
    <?php foreach ($polls as $poll): 
        $net_score = $poll['upvotes'] - $poll['downvotes'];
    ?>
    <div class="admin-section poll-container" id="poll-<?php echo $poll['id']; ?>">
        <div class="poll-header">
            <div>
                <h3><?php echo htmlspecialchars($poll['subject']); ?></h3>
                <small>Suggested by: <?php echo htmlspecialchars($poll['submitter_id']); ?> on <?php echo date('Y-m-d', strtotime($poll['created_at'])); ?></small>
            </div>
            <div class="vote-count <?php echo ($net_score >= 0 ? 'positive' : 'negative'); ?>">
                <?php echo ($net_score > 0 ? '+' : '') . $net_score; ?>
            </div>
        </div>
        <div class="poll-content">
            <?php echo nl2br(htmlspecialchars($poll['content'])); ?>
        </div>
        <div class="poll-actions">
            <form action="polls.php" method="post" class="vote-form">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="poll_id" value="<?php echo $poll['id']; ?>">
                <button type="submit" name="submit_vote" value="1" class="vote-btn up" title="Upvote">▲</button>
            </form>
            <form action="polls.php" method="post" class="vote-form">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="poll_id" value="<?php echo $poll['id']; ?>">
                <button type="submit" name="submit_vote" value="-1" class="vote-btn down" title="Downvote">▼</button>
            </form>
            <span>(<?php echo $poll['upvotes']; ?> up / <?php echo $poll['downvotes']; ?> down)</span>
        </div>

        <?php // This block displays the admin reply with the correct styling. ?>
        <?php if (!empty($poll['admin_reply'])): ?>
            <div class="admin-reply-box" style="margin-top: 20px; padding: 15px; background: #2a2a2a; border-left: 4px solid #009900; border-radius: 4px;">
                <h4 style="margin-top: 0; color: #7f7;">Admin Comment (from <?php echo htmlspecialchars($poll['replied_by_username'] ?? 'Admin'); ?>):</h4>
                <p style="margin-bottom: 0; color: #ddd;"><?php echo nl2br(htmlspecialchars($poll['admin_reply'])); ?></p>
            </div>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
<?php endif; ?>
</div>
</body>
</html>