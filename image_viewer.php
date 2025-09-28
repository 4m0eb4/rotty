<?php
// image_viewer.php (V6 - Finalized Voting & Deletion)

session_start();
require_once 'config.php';
require_once 'functions.php';

// --- Establish Database Connection Early ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Error: Could not connect to the database.");
}

// --- Generate CSRF Token ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- ACTION: Delete an entire image post ---
if (
    isset($_GET['delete_post'], $_GET['id'], $_GET['csrf_token'])
    && hash_equals($_SESSION['csrf_token'], $_GET['csrf_token'])
    && isset($_SESSION['user_id'])
) {
    $post_id = (int)$_GET['id'];

    $stmt = $pdo->prepare("SELECT unique_filename, user_id FROM uploads WHERE id = ?");
    $stmt->execute([$post_id]);
    $upload_to_delete = $stmt->fetch(PDO::FETCH_ASSOC);

    // Ensure the user deleting the post is the one who uploaded it.
    if ($upload_to_delete && $upload_to_delete['user_id'] === $_SESSION['user_id']) {
        $pdo->beginTransaction();
        try {
            // New: Find and DELETE the original chat message
            $message_tag = '[VIEWFILE id=' . $post_id . ']%';
            $delete_msg_stmt = $pdo->prepare("DELETE FROM messages WHERE message LIKE ? AND user_id = ?");
            $delete_msg_stmt->execute([$message_tag, $_SESSION['user_id']]);

            // Delete the physical file
            $filePath = __DIR__ . '/uploads/' . $upload_to_delete['unique_filename'];
            if (file_exists($filePath)) {
                @unlink($filePath);
            }

            // Delete associated data from the database
            $pdo->prepare("DELETE FROM upload_comments WHERE upload_id = ?")->execute([$post_id]);
            $pdo->prepare("DELETE FROM votes WHERE item_type = 'upload' AND item_id = ?")->execute([$post_id]);
            $pdo->prepare("DELETE FROM uploads WHERE id = ?")->execute([$post_id]);

            $pdo->commit();
            // You can optionally set a feedback message for the gallery page here
            // $_SESSION['gallery_feedback'] = "Image post successfully deleted.";

        } catch (Exception $e) {
            $pdo->rollBack();
            // $_SESSION['gallery_feedback'] = "Error: Could not delete the image post.";
        }
    }
    // Redirect back to the gallery after the operation
    header("Location: gallery.php");
    exit;
}
// --- ACTION: Delete a single comment ---
if (
    isset($_GET['delete_comment'], $_GET['id'], $_GET['csrf_token'])
    && hash_equals($_SESSION['csrf_token'], $_GET['csrf_token'])
    && isset($_SESSION['username'])
) {
    $comment_id = (int)$_GET['delete_comment'];
    $post_id = (int)$_GET['id'];
    
    $stmt = $pdo->prepare("SELECT user_id, guest_id FROM upload_comments WHERE id = ?");
    $stmt->execute([$comment_id]);
    $comment_owner = $stmt->fetch(PDO::FETCH_ASSOC);

    $is_owner = ($comment_owner && (
        (!empty($comment_owner['user_id']) && $comment_owner['user_id'] == ($_SESSION['user_id'] ?? null)) ||
        (!empty($comment_owner['guest_id']) && $comment_owner['guest_id'] == ($_SESSION['guest_id'] ?? null))
    ));

    if ($is_owner) {
        $pdo->prepare("DELETE FROM votes WHERE item_type = 'comment' AND item_id = ?")->execute([$comment_id]);
        $pdo->prepare("DELETE FROM upload_comments WHERE id = ?")->execute([$comment_id]);
    }
    header("Location: image_viewer.php?id=" . $post_id);
    exit;
}


// --- Basic Setup & Validation ---
$upload_id = $_GET['id'] ?? null;
if (!$upload_id || !ctype_digit($upload_id)) {
    die("Invalid or missing image ID.");
}

// --- Voter Fingerprint ---
$voter_fingerprint = $_COOKIE['rotchat_fp'] ?? null;
if (!$voter_fingerprint) {
    $voter_fingerprint = bin2hex(random_bytes(32));
    setcookie('rotchat_fp', $voter_fingerprint, time() + (10 * 365 * 24 * 60 * 60), "/", "", false, true);
}

// --- Handle ALL POST Form Submissions ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    render_csrf_error_page();
}
    // --- Comment Submission ---
    if (isset($_POST['submit_comment'])) {
        $comment_text = trim($_POST['comment_text'] ?? '');
        $parent_id = !empty($_POST['parent_id']) ? (int)$_POST['parent_id'] : null;
        if (!empty($comment_text) && isset($_SESSION['username'])) {
            $stmt = $pdo->prepare("INSERT INTO upload_comments (upload_id, user_id, guest_id, username, comment_text, parent_id) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$upload_id, $_SESSION['user_id'] ?? null, $_SESSION['guest_id'] ?? null, $_SESSION['username'], $comment_text, $parent_id]);
        }
    }

    // --- Vote Submission ---
    // --- Vote Submission ---
    if (isset($_POST['submit_vote'])) {
        $item_id    = (int)($_POST['item_id']     ?? 0);
        $item_type  =      $_POST['item_type']   ?? '';
        $vote_value = (int) $_POST['submit_vote'];

        if ($item_id > 0 
            && in_array($item_type, ['upload','comment']) 
            && in_array($vote_value, [1,-1]) 
            && $voter_fingerprint
        ) {
            $pdo
              ->prepare(
                "INSERT INTO votes (voter_fingerprint,item_id,item_type,vote)
                   VALUES (?,?,?,?)
                 ON DUPLICATE KEY UPDATE vote = VALUES(vote)"
              )
              ->execute([$voter_fingerprint,$item_id,$item_type,$vote_value]);
        }
    }

    
    header("Location: image_viewer.php?id=" . $upload_id);
    exit();
}


// --- Fetch Upload Details (for page display) ---
// THIS QUERY NOW CALCULATES VOTES DIRECTLY
$stmt = $pdo->prepare("
    SELECT 
        u.*, 
        us.username as uploader_username,
        (SELECT COUNT(*) FROM votes WHERE item_id = u.id AND item_type = 'upload' AND vote = 1) as upvotes,
        (SELECT COUNT(*) FROM votes WHERE item_id = u.id AND item_type = 'upload' AND vote = -1) as downvotes
    FROM uploads u 
    JOIN users us ON u.user_id = us.id 
    WHERE u.id = ?
");
$stmt->execute([$upload_id]);
$upload = $stmt->fetch(PDO::FETCH_ASSOC);

// --- Handle Deleted or Expired Images ---
function render_error_page($title, $message) {
    die('<!DOCTYPE html><html lang="en"><head><title>' . htmlspecialchars($title) . '</title><link rel="stylesheet" href="style.css"></head><body><div class="admin-container viewer-container" style="text-align: center; padding-top: 50px;"><header><h1>' . htmlspecialchars($title) . '</h1><a href="chat.php" class="back-link">Back to Chat</a></header><div class="admin-section"><p style="font-size: 1.1em; color: #ffc2c2;">' . htmlspecialchars($message) . '</p></div></div></body></html>');
}

if (!$upload) {
    render_error_page('Not Found', 'This image could not be found. It may have been deleted.');
}

if (($upload['expires_at'] && strtotime($upload['expires_at']) < time()) || ($upload['max_views'] > 0 && $upload['current_views'] >= $upload['max_views'])) {
    render_error_page('Image Expired', 'This image is no longer available because its expiry time or view limit has been reached.');
}

// Increment view count if not expired and not the uploader
if ($_SESSION['user_id'] != $upload['user_id']) {
    try {
        $pdo->prepare("UPDATE uploads SET current_views = current_views + 1 WHERE id = ?")->execute([$upload_id]);
        $upload['current_views']++;
    } catch (PDOException $e) {
        error_log("Failed to increment view count for upload ID {$upload_id}: " . $e->getMessage());
    }
}

// --- Fetch and Process Comments ---
// --- NEW: Comment Sorting Logic ---
$sort_order = $_GET['sort'] ?? 'popular'; // Default to popular

$comments_stmt = $pdo->prepare("
    SELECT
      c.*,
      COALESCE(SUM(CASE WHEN v.vote =  1 THEN 1 ELSE 0 END), 0) AS upvotes,
      COALESCE(SUM(CASE WHEN v.vote = -1 THEN 1 ELSE 0 END), 0) AS downvotes
    FROM upload_comments AS c
    LEFT JOIN votes AS v
      ON v.item_type = 'comment'
     AND v.item_id   = c.id
    WHERE c.upload_id = ?
    GROUP BY c.id
    ORDER BY c.created_at ASC, c.id ASC -- Fetch in a consistent order for PHP processing
");

$comments_stmt->execute([$upload_id]);
$all_comments = $comments_stmt->fetchAll(PDO::FETCH_ASSOC);
$comments_by_id = [];
foreach ($all_comments as $comment) { $comments_by_id[$comment['id']] = $comment; $comments_by_id[$comment['id']]['replies'] = []; }
$comment_tree = [];
foreach ($comments_by_id as $id => &$comment) {
    if ($comment['parent_id'] && isset($comments_by_id[$comment['parent_id']])) {
        $comments_by_id[$comment['parent_id']]['replies'][] = &$comment;
    } else { $comment_tree[] = &$comment; }
}

// Sort the top-level comments in PHP after building the tree
if ($sort_order === 'popular') {
    usort($comment_tree, function($a, $b) {
        $score_a = $a['upvotes'] - $a['downvotes'];
        $score_b = $b['upvotes'] - $b['downvotes'];
        if ($score_a == $score_b) {
            return strtotime($b['created_at']) - strtotime($a['created_at']); // Secondary sort by newest if scores are equal
        }
        return $score_b <=> $score_a; // Sort by highest score first
    });
} elseif ($sort_order === 'newest') {
    usort($comment_tree, function($a, $b) {
        return strtotime($b['created_at']) - strtotime($a['created_at']); // Sort by newest first
    });
}

unset($comment);

// --- Get info for the comment being replied to, if any ---
$reply_to_comment = null;
if (isset($_GET['reply_to']) && ctype_digit($_GET['reply_to'])) {
    if (isset($comments_by_id[$_GET['reply_to']])) {
        $reply_to_comment = $comments_by_id[$_GET['reply_to']];
    }
}

function display_comments($comments, $upload_id, $csrf_token, $level = 0) {
    foreach ($comments as $comment) {
        $net_score = $comment['upvotes'] - $comment['downvotes'];
        $score_class = $net_score > 0 ? 'positive' : ($net_score < 0 ? 'negative' : '');
        $is_being_replied_to = (isset($_GET['reply_to']) && $_GET['reply_to'] == $comment['id']);

        echo '<div class="comment-container' . ($is_being_replied_to ? ' replying-to' : '') . '" style="display: flex; gap: 10px; margin-left: ' . ($level * 20) . 'px;">';

        // Vertical Vote Column
        echo '<div class="vote-column">';
        echo '<form class="vote-form" method="post" action="image_viewer.php?id=' . urlencode($upload_id) . '"><input type="hidden" name="csrf_token" value="' . htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') . '"/><input type="hidden" name="item_id" value="' . $comment['id'] . '"/><input type="hidden" name="item_type" value="comment"/><button name="submit_vote" type="submit" value="1" class="vote-btn up">▲</button></form>';
        echo '<span class="vote-count ' . $score_class . '">' . $net_score . '</span>';
        echo '<form class="vote-form" method="post" action="image_viewer.php?id=' . urlencode($upload_id) . '"><input type="hidden" name="csrf_token" value="' . htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') . '"/><input type="hidden" name="item_id" value="' . $comment['id'] . '"/><input type="hidden" name="item_type" value="comment"/><button name="submit_vote" type="submit" value="-1" class="vote-btn down">▼</button></form>';
        echo '</div>';

        // Comment Content Column
        echo '<div class="comment-content-column" style="flex-grow: 1;">';
        echo '<div class="comment-header"><strong>' . htmlspecialchars($comment['username'], ENT_QUOTES, 'UTF-8') . '</strong><small>' . date('M j, Y H:i', strtotime($comment['created_at'])) . '</small></div>';
        echo '<div class="comment-body">' . nl2br(htmlspecialchars($comment['comment_text'], ENT_QUOTES, 'UTF-8')) . '</div>';

        // Actions (Reply/Delete)
        echo '<div class="comment-actions" style="justify-content: flex-end;">';
        if (isset($_SESSION['username'])) {
            if ($_SESSION['username'] === $comment['username']) {
                echo '<a href="image_viewer.php?id=' . urlencode($upload_id) . '&delete_comment=' . urlencode($comment['id']) . '&csrf_token=' . urlencode($csrf_token) . '" class="delete-comment" onclick="return confirm(\'Delete this comment?\');">Delete</a>';
            }
            echo '<a href="image_viewer.php?id=' . urlencode($upload_id) . '&reply_to=' . $comment['id'] . '#comment-form" class="reply-toggle">Reply</a>';
        }
        echo '</div>'; // .comment-actions

        if (!empty($comment['replies'])) {
            display_comments($comment['replies'], $upload_id, $csrf_token, $level + 1);
        }
        echo '</div>'; // .comment-content-column
        echo '</div>'; // .comment-container
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Viewer: <?php echo htmlspecialchars($upload['link_text'] ?: $upload['original_filename']); ?></title>
    <link rel="icon" href="/favicon.ico" type="image/x-icon"> </head>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="admin_style.css">
    <style>
        .image-content-wrapper { display: flex; gap: 20px; }
        .vote-column { display: flex; flex-direction: column; align-items: center; gap: 5px; }
        .image-info-main { flex-grow: 1; }
    </style>
</head>
<body style="height: auto; overflow-y: auto !important;">
    <div class="admin-container viewer-container">
        <header>
            <h1><?php echo htmlspecialchars($upload['link_text'] ?: $upload['original_filename']); ?></h1>
            <?php if (isset($_SESSION['user_id']) && $_SESSION['user_id'] === $upload['user_id']): ?>
                <div style="display: flex; gap: 10px;">
                    <a href="image_viewer.php?id=<?php echo $upload_id; ?>&delete_post=1&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="back-link danger-btn" onclick="return confirm('Are you sure you want to delete this post? This cannot be undone.');">Delete Post</a>
                    <a href="gallery.php" class="back-link">Back to Gallery</a>
                </div>
            <?php else: ?>
                <a href="gallery.php" class="back-link">Back to Gallery</a>
            <?php endif; ?>
        </header>
        <div class="image-display-box">
            <?php
            // Check the MIME type of the file to determine how to display it
            if (strpos($upload['mime_type'], 'video/') === 0):
            ?>
                <video controls style="max-width: 100%; max-height: 50vh; border-radius: 5px;">
                    <source src="<?php echo htmlspecialchars($upload['file_path']); ?>" type="<?php echo htmlspecialchars($upload['mime_type']); ?>">
                    Your browser does not support the video tag.
                </video>
            <?php else: ?>
                <a href="<?php echo htmlspecialchars($upload['file_path']);?>" target="_blank" title="Click to view full image">
                    <img src="<?php echo htmlspecialchars($upload['file_path']); ?>" alt="<?php echo htmlspecialchars($upload['link_text'] ?: $upload['original_filename']); ?>">
                </a>
            <?php endif; ?>
        </div>
        
        <div class="image-content-wrapper">
            <div class="vote-column">
                <?php $img_net_score = $upload['upvotes'] - $upload['downvotes']; ?>
                <form class="vote-form" method="post" action="image_viewer.php?id=<?php echo $upload_id;?>"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']);?>"/><input type="hidden" name="item_id" value="<?php echo $upload_id;?>"/><input type="hidden" name="item_type" value="upload"/><button name="submit_vote" type="submit" value="1" class="vote-btn up">▲</button></form>
                <span class="vote-count <?php echo($img_net_score > 0 ? 'positive' : ($img_net_score < 0 ? 'negative' : ''));?>"><?php echo $img_net_score;?></span>
                <form class="vote-form" method="post" action="image_viewer.php?id=<?php echo $upload_id;?>"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']);?>"/><input type="hidden" name="item_id" value="<?php echo $upload_id;?>"/><input type="hidden" name="item_type" value="upload"/><button name="submit_vote" type="submit" value="-1" class="vote-btn down">▼</button></form>
            </div>
            <div class="image-info-main">
                <p>Uploaded by: <strong><?php echo htmlspecialchars($upload['uploader_username']); ?></strong> on <?php echo date('F j, Y, g:i a', strtotime($upload['created_at'])); ?></p>
                <p class="image-expiry-info">
                <?php
                    $expiry_info = [];
                    if ($upload['expires_at']) {
                        $expiry_info[] = "Expires: " . date('F j, Y, g:i a', strtotime($upload['expires_at']));
                    }

                    // Always show the current view count.
                    $view_string = "Views: " . htmlspecialchars($upload['current_views']);
                    if ($upload['max_views'] > 0) {
                        // If there's a max view count, append it.
                        $view_string .= " / " . htmlspecialchars($upload['max_views']);
                    }
                    $expiry_info[] = $view_string;

                    echo implode(' | ', $expiry_info);
                ?>
                </p>
            </div>
        </div>
        <hr>
        <div class="comments-section">
            <h2 id="comment-form">Comments</h2>

            <div class="comment-sort-options">
                <strong>Sort by:</strong>
                <a href="?id=<?php echo $upload_id; ?>&sort=popular#comment-form" class="<?php if($sort_order === 'popular') echo 'active'; ?>">Popular</a>
                <a href="?id=<?php echo $upload_id; ?>&sort=newest#comment-form" class="<?php if($sort_order === 'newest') echo 'active'; ?>">Newest</a>
            </div>

            <?php if(isset($_SESSION['username'])): ?>
                <form action="image_viewer.php?id=<?php echo $upload_id; ?>" method="post" class="sub-section-form" style="background:rgba(0,0,0,.2);border:1px solid #333;margin-bottom:30px">
                    <?php if ($reply_to_comment): ?>
                        <div class="reply-context"><p>Replying to <strong><?php echo htmlspecialchars($reply_to_comment['username']); ?></strong>... <a href="image_viewer.php?id=<?php echo $upload_id; ?>&sort=<?php echo $sort_order; ?>#comment-form">Cancel</a></p></div>
                        <input type="hidden" name="parent_id" value="<?php echo htmlspecialchars($reply_to_comment['id']); ?>">
                    <?php endif; ?>
                    <h4><?php echo $reply_to_comment ? 'Write Your Reply' : 'Leave a Comment'; ?></h4>
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <div class="form-group"><textarea name="comment_text" rows="4" required placeholder="Write your comment here..."></textarea></div>
                    <button type="submit" name="submit_comment">Post <?php echo $reply_to_comment ? 'Reply' : 'Comment'; ?></button>
                </form>
            <?php else: ?>
                <p style="text-align:center;color:#aaa">You must be logged in to comment.</p>
            <?php endif; ?>
            <?php
            if(!empty($comment_tree)){display_comments($comment_tree,$upload['id'],$_SESSION['csrf_token']);}else{echo '<p style="text-align:center;color:#aaa">No comments yet. Be the first!</p>';}
            ?>
        </div>
    </div>
</body>
</html>