<?php
// docs.php - V5 (Styled Permission Error)

session_start();
require_once 'config.php';
require_once 'database.php';
require_once 'functions.php';

// --- NEW: Helper function for a styled error page ---
function render_permission_denied_page($message) {
    http_response_code(403); // Use 403 Forbidden for permission errors
    $html = <<<HTML
    <!DOCTYPE html><html lang="en"><head><title>Access Denied</title><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="admin_style.css">
    <style>
        body.standalone-page {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }
        .error-container {
            max-width: 500px;
            text-align: center;
        }
        .error-container header h1 {
            color: #ff3333;
        }
        .error-container p {
            font-size: 1.2em;
            color: #eee;
            margin: 20px 0 30px 0;
        }
    </style>
    </head><body class="standalone-page">
        <div class="admin-container error-container">
            <header>
                <h1>Access Denied</h1>
            </header>
            <p>{$message}</p>
            <a href="chat.php" class="back-link">Return to Chat</a>
        </div>
    </body></html>
HTML;
    die($html);
}


// --- UNIFIED SETUP AND PERMISSION CHECK ---
$pdo = get_database_connection();
$settings = $pdo->query("SELECT setting_key, setting_value FROM settings")->fetchAll(PDO::FETCH_KEY_PAIR);
$role_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];
$user_role = strtolower($_SESSION['user_role'] ?? 'guest');

// Determine page context and set appropriate variables
$page_context = 'images'; // Default
$id_param = 'view_image_id';
$upload_type = 'image';
$filename = basename($_SERVER['PHP_SELF']);

if ($filename === 'docs.php') {
    $page_context = 'docs';
    $id_param = 'view_doc_id';
    $upload_type = 'document';
} elseif ($filename === 'zips.php') {
    $page_context = 'zips';
    $id_param = 'view_zip_id';
    $upload_type = 'zip';
}

$permission_key = 'view_allowed_roles_' . $page_context;
$required_role = $settings[$permission_key] ?? 'admin';

if (!isset($role_hierarchy[$user_role]) || $role_hierarchy[$user_role] < $role_hierarchy[$required_role]) {
    render_permission_denied_page("You do not have permission to view this page.");
}

// --- ACTION ROUTER ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle direct file serving action
if (isset($_GET['action']) && $_GET['action'] === 'serve_file' && isset($_GET[$id_param])) {
    if (!isset($_GET['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_GET['csrf_token'])) {
        die('Invalid security token for file serving.');
    }
    
    $upload_id = (int)$_GET[$id_param];
    $stmt = $pdo->prepare("SELECT user_id, file_path, original_filename, mime_type FROM uploads WHERE id = ? AND upload_type = ?");
    $stmt->execute([$upload_id, $upload_type]);
    $document = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$document) {
        http_response_code(404);
        die("Document not found in database.");
    }

    $file_path = __DIR__ . '/' . $document['file_path'];

    if (!file_exists($file_path)) {
        http_response_code(404);
        die("File not found on server.");
    }

    if (ob_get_level()) ob_end_clean();
    header('Content-Type: ' . $document['mime_type']);
    header('Content-Length: ' . filesize($file_path));
    $disposition = ($upload_type === 'zip') ? 'attachment' : 'inline';
    header('Content-Disposition: ' . $disposition . '; filename="' . basename($document['original_filename']) . '"');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    readfile($file_path);
    exit();
}

// Handle POST actions (comments, votes) and other GET actions (delete)
if ($_SERVER['REQUEST_METHOD'] === 'POST' || (isset($_GET['action']) && $_GET['action'] !== 'serve_file')) {
    if (!isset($_REQUEST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_REQUEST['csrf_token'])) {
        die('Invalid security token.');
    }

    $item_id = (int)($_REQUEST[$id_param] ?? 0);
    $sort = isset($_GET['sort']) ? '&sort=' . urlencode($_GET['sort']) : '';
    $redirect_url = $filename . ($item_id > 0 ? '?' . $id_param . '=' . $item_id . $sort : '');

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['submit_comment']) && $item_id > 0) {
            $comment_text = trim($_POST['comment_text'] ?? '');
            $parent_id = !empty($_POST['parent_id']) ? (int)$_POST['parent_id'] : null;
            if (!empty($comment_text) && isset($_SESSION['username'])) {
                $pdo->prepare("INSERT INTO upload_comments (upload_id, user_id, guest_id, username, comment_text, parent_id) VALUES (?, ?, ?, ?, ?, ?)")->execute([$item_id, $_SESSION['user_id'] ?? null, $_SESSION['guest_id'] ?? null, $_SESSION['username'], $comment_text, $parent_id]);
            }
        }
        if (isset($_POST['submit_vote'])) {
            $vote_item_id = (int)($_POST['item_id'] ?? 0);
            $vote_item_type = $_POST['item_type'] ?? '';
            $vote_value = (int)$_POST['submit_vote'];
            $voter_fp = $_COOKIE['rotchat_fp'] ?? 'unknown';
            if ($vote_item_id > 0 && in_array($vote_item_type, ['upload', 'comment']) && in_array($vote_value, [1, -1])) {
                $pdo->prepare("INSERT INTO votes (voter_fingerprint, item_id, item_type, vote) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE vote = VALUES(vote)")->execute([$voter_fp, $vote_item_id, $vote_item_type, $vote_value]);
            }
        }
    }
    
    if (isset($_GET['action']) && isset($_SESSION['user_id'])) {
        if ($_GET['action'] === 'delete_post' && $item_id > 0) {
            $stmt = $pdo->prepare("SELECT unique_filename, user_id FROM uploads WHERE id = ?");
            $stmt->execute([$item_id]);
            if (($upload = $stmt->fetch()) && ($upload['user_id'] === $_SESSION['user_id'] || $user_role === 'admin')) {
                $pdo->beginTransaction();
                try {
                    // 1. Delete the original chat message
                    $message_tag1 = '[VIEWFILE%id=' . $item_id . ']%';
                    $message_tag2 = '%id=' . $item_id . ']%';
                    $delete_msg_stmt = $pdo->prepare("DELETE FROM messages WHERE (message LIKE ? OR message LIKE ?) AND user_id = ?");
                    $delete_msg_stmt->execute([$message_tag1, $message_tag2, $upload['user_id']]);

                    // 2. Delete the physical file
                    $filePath = __DIR__ . '/uploads/' . $upload['unique_filename'];
                    if (file_exists($filePath)) @unlink($filePath);

                    // 3. Delete associated comments and votes
                    $pdo->prepare("DELETE FROM upload_comments WHERE upload_id = ?")->execute([$item_id]);
                    $pdo->prepare("DELETE FROM votes WHERE item_type = 'upload' AND item_id = ?")->execute([$item_id]);
                    
                    // 4. Delete the main upload record
                    $pdo->prepare("DELETE FROM uploads WHERE id = ?")->execute([$item_id]);

                    $pdo->commit();
                    $redirect_url = $filename; // Redirect to the main gallery page
                } catch (Exception $e) {
                    $pdo->rollBack();
                    // Optional: Log the error
                }
            }
        }
        if ($_GET['action'] === 'delete_comment' && $item_id > 0) {
            $comment_id = (int)($_GET['comment_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT user_id, guest_id FROM upload_comments WHERE id = ?");
            $stmt->execute([$comment_id]);
            if (($comment = $stmt->fetch())) {
                $is_owner = ($comment['user_id'] == ($_SESSION['user_id'] ?? -1)) || ($comment['guest_id'] == ($_SESSION['guest_id'] ?? -1));
                if ($is_owner || $user_role === 'admin') {
                    $pdo->prepare("DELETE FROM upload_comments WHERE id = ? OR parent_id = ?")->execute([$comment_id, $comment_id]);
                }
            }
        }
    }
    header('Location: ' . $redirect_url . '#comment-form');
    exit();
}
if (!isset($_SESSION['session_id'])) {
    render_permission_denied_page('You must be logged in to view this page.');
}

// --- Page Router ---
$item_id_to_view = $_GET[$id_param] ?? null;
if ($item_id_to_view && ctype_digit($item_id_to_view)) {
    // --- RENDER SINGLE DOCUMENT VIEWER ---
    $upload_id = (int)$item_id_to_view;
    
    $stmt = $pdo->prepare("SELECT u.*, us.username as uploader_username, (SELECT COALESCE(SUM(vote), 0) FROM votes WHERE item_id = u.id AND item_type = 'upload') as net_votes, (SELECT COUNT(*) FROM upload_comments WHERE upload_id=u.id) as comment_count FROM uploads u LEFT JOIN users us ON u.user_id = us.id WHERE u.id = ? AND u.upload_type = ?");
    $stmt->execute([$upload_id, $upload_type]);

    $upload = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$upload) {
        render_error_page('Not Found', 'This file could not be found. It may have been deleted.');
    }

    // --- CORRECTED LOGIC ---
    // Only perform expiration and view count checks if the current user is NOT the uploader.
    if (($_SESSION['user_id'] ?? -1) !== $upload['user_id']) {
        // 1. Check for expiration first.
        if (($upload['expires_at'] && strtotime($upload['expires_at']) < time()) || ($upload['max_views'] > 0 && $upload['current_views'] >= $upload['max_views'])) {
            render_error_page('File Expired', 'This file is no longer available because its expiry time or view limit has been reached.');
        }
        
        // 2. If not expired, increment the view count.
        $pdo->prepare("UPDATE uploads SET current_views = current_views + 1 WHERE id = ?")->execute([$upload_id]);
        $upload['current_views']++;
    }

function display_threaded_comments($comments, $parent_id, $csrf_token, $upload_id, $id_param, $filename, $level = 0) {
    $user_role = strtolower($_SESSION['user_role'] ?? 'guest');
    foreach ($comments as $comment) {
        if ($comment['parent_id'] == $parent_id) {
            $score_class = $comment['net_votes'] > 0 ? 'positive' : ($comment['net_votes'] < 0 ? 'negative' : '');
            $is_owner = (isset($_SESSION['user_id']) && $comment['user_id'] == $_SESSION['user_id']) || (isset($_SESSION['guest_id']) && $comment['guest_id'] == $_SESSION['guest_id']);
            
            echo '<div class="comment-container" style="'.($level > 0 ? 'margin-left: 25px;' : '').'">';
            echo '<div class="comment-header"><strong>' . htmlspecialchars($comment['username']) . '</strong><small>' . date('M j, Y H:i', strtotime($comment['created_at'])) . '</small></div>';
            echo '<div class="comment-body">' . nl2br(htmlspecialchars($comment['comment_text'])) . '</div>';
            
            echo '<div class="comment-actions">';
                echo '<div class="vote-bar">';
                    echo '<form class="vote-form" method="post" action="'.$filename.'?'.$id_param.'=' . $upload_id . '"><input type="hidden" name="csrf_token" value="' . $csrf_token . '"><input type="hidden" name="item_id" value="' . $comment['id'] . '"><input type="hidden" name="item_type" value="comment"><button name="submit_vote" type="submit" value="1" class="vote-btn up">▲</button></form>';
                    echo '<span class="vote-count ' . $score_class . '">' . ($comment['net_votes'] > 0 ? '+' : '') . $comment['net_votes'] . '</span>';
                    echo '<form class="vote-form" method="post" action="'.$filename.'?'.$id_param.'=' . $upload_id . '"><input type="hidden" name="csrf_token" value="' . $csrf_token . '"><input type="hidden" name="item_id" value="' . $comment['id'] . '"><input type="hidden" name="item_type" value="comment"><button name="submit_vote" type="submit" value="-1" class="vote-btn down">▼</button></form>';
                echo '</div>';
                
                echo '<div class="management-actions">';
                if ($is_owner || $user_role === 'admin') {
                    echo '<a href="'.$filename.'?action=delete_comment&'.$id_param.'=' . $upload_id . '&comment_id=' . $comment['id'] . '&csrf_token=' . $csrf_token . '" class="reply-toggle" onclick="return confirm(\'Delete this comment?\');">Delete</a>';
                }
                echo '<a href="'.$filename.'?'.$id_param.'=' . $upload_id . '&reply_to=' . $comment['id'] . '#comment-form" class="reply-toggle">Reply</a>';
                echo '</div>';
            echo '</div>'; 

            display_threaded_comments($comments, $comment['id'], $csrf_token, $upload_id, $id_param, $filename, $level + 1);
            echo '</div>';
        }
    }
}
    
    ?>
    <!DOCTYPE html><html lang="en"><head><title>Document Viewer</title><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="admin_style.css">
    <style>
        .viewer-container header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        .viewer-container header h1 {
            flex-grow: 1;
            margin: 0;
            word-break: break-word;
        }
        .viewer-container header > div {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-shrink: 0;
        }
    </style>
    </head><body class="standalone-page" style="padding: 20px;">
        <div class="admin-container viewer-container">
            <header>
                <h1><?php echo htmlspecialchars($upload['link_text'] ?: $upload['original_filename']); ?></h1>
                <div>
                    <a href="?action=serve_file&<?php echo $id_param; ?>=<?php echo $upload_id; ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="back-link" target="_blank" style="background-color: #2a7e48;">Open/Download File</a>

                    <?php if (($upload['user_id'] === ($_SESSION['user_id'] ?? -1)) || (strtolower($_SESSION['user_role'] ?? 'guest') === 'admin')): ?>
                        <a href="?action=delete_post&<?php echo $id_param; ?>=<?php echo $upload_id; ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="back-link danger-btn" onclick="return confirm('Are you sure you want to delete this post?');">Delete Post</a>
                    <?php endif; ?>
                    <a href="<?php echo $filename; ?>" class="back-link" style="margin-left: 10px;">Back to Gallery</a>
                </div>
            </header>
            <div class="image-display-box" style="height: auto; padding: 40px 20px; text-align: center; background: #222; border: 1px solid #333; margin-bottom: 15px;">
                <p style="font-size: 1.2em; color: #ccc; margin: 0;">Use the "Open/Download File" button above to view the document.</p>
                <p style="color: #888; margin: 5px 0 0 0;">Direct preview is disabled to ensure compatibility and security.</p>
            </div>
            <div class="image-stats-bar">
                <div class="vote-bar">
                    <form class="vote-form" method="post" action="?<?php echo $id_param; ?>=<?php echo $upload_id; ?>"><input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>"><input type="hidden" name="item_id" value="<?php echo $upload_id; ?>"><input type="hidden" name="item_type" value="upload"><button name="submit_vote" type="submit" value="1" class="vote-btn up">▲</button></form>
                    <span class="vote-count <?php echo ($upload['net_votes'] > 0 ? 'positive' : ($upload['net_votes'] < 0 ? 'negative' : ''));?>"><?php echo ($upload['net_votes'] > 0 ? '+' : '') . $upload['net_votes']; ?></span>
                    <form class="vote-form" method="post" action="?<?php echo $id_param; ?>=<?php echo $upload_id; ?>"><input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>"><input type="hidden" name="item_id" value="<?php echo $upload_id; ?>"><input type="hidden" name="item_type" value="upload"><button name="submit_vote" type="submit" value="-1" class="vote-btn down">▼</button></form>
                </div>
                <span class="stat">Uploader: <strong><?php echo htmlspecialchars($upload['uploader_username'] ?? 'Unknown'); ?></strong></span>
                <span class="stat">Views: <strong><?php echo $upload['current_views']; ?></strong></span>
                <span class="stat">Comments: <strong><?php echo $upload['comment_count']; ?></strong></span>
            </div>

            <div class="comments-section">
                <div class="comment-sort-options">
                    <strong>Sort by:</strong>
                    <a href="?<?php echo $id_param; ?>=<?php echo $upload_id; ?>&sort=popular#comment-form" class="<?php if(($_GET['sort']??'popular')==='popular') echo 'active';?>">Popular</a>
                    <a href="?<?php echo $id_param; ?>=<?php echo $upload_id; ?>&sort=newest#comment-form" class="<?php if(($_GET['sort']??'')==='newest') echo 'active';?>">Newest</a>
                </div>
                <h2 id="comment-form">Comments</h2>
                <?php
                    $reply_to_id = $_GET['reply_to'] ?? null;
                    if ($reply_to_id) {
                        $stmt = $pdo->prepare("SELECT username FROM upload_comments WHERE id = ?"); $stmt->execute([$reply_to_id]);
                        $reply_to_user = $stmt->fetchColumn();
                        if($reply_to_user) echo '<div class="reply-context"><p>Replying to <strong>'.htmlspecialchars($reply_to_user).'</strong>... <a href="?'.$id_param.'='.$upload_id.'#comment-form">Cancel</a></p></div>';
                    }
                ?>
                <form action="?<?php echo $id_param; ?>=<?php echo $upload_id; ?>" method="post" style="margin-bottom: 20px;">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <?php if($reply_to_id) echo '<input type="hidden" name="parent_id" value="'.(int)$reply_to_id.'">'; ?>
                    <div class="form-group"><textarea name="comment_text" rows="3" required placeholder="Leave a comment..."></textarea></div>
                    <button type="submit" name="submit_comment">Post Comment</button>
                </form>
                <?php 
                $sort_order = $_GET['sort'] ?? 'popular';
                $order_clause = ($sort_order === 'newest') ? "ORDER BY created_at DESC" : "ORDER BY net_votes DESC, created_at DESC";
                $stmt_all_comments = $pdo->prepare("SELECT c.*, (SELECT COALESCE(SUM(vote), 0) FROM votes WHERE item_id = c.id AND item_type = 'comment') as net_votes FROM upload_comments c WHERE c.upload_id = ? {$order_clause}");
                $stmt_all_comments->execute([$upload_id]);
                $all_comments_for_thread = $stmt_all_comments->fetchAll(PDO::FETCH_ASSOC);
                
                if(!empty($all_comments_for_thread)) {
                    display_threaded_comments($all_comments_for_thread, null, $_SESSION['csrf_token'], $upload_id, $id_param, $filename); 
                } else {
                    echo "<p style='text-align:center;color:#aaa'>No comments yet.</p>";
                }
                ?>
            </div>
        </div>
    </body></html>
    <?php
} else {
    // --- RENDER DOCUMENT GALLERY GRID ---
    $current_page = isset($_GET['page']) && ctype_digit($_GET['page']) ? (int)$_GET['page'] : 1;
    $items_per_page = 20;
    $offset = ($current_page - 1) * $items_per_page;

    $total_items_stmt = $pdo->query("SELECT COUNT(*) FROM uploads WHERE upload_type = 'document'");
    $total_items = (int)$total_items_stmt->fetchColumn();
    $total_pages = ceil($total_items / $items_per_page);

    $sort_order = $_GET['sort'] ?? 'popular';
    $order_by_clause = "ORDER BY net_votes DESC, u.created_at DESC";
    if ($sort_order === 'newest') { $order_by_clause = "ORDER BY u.created_at DESC"; }

    $query = "SELECT u.id, u.link_text, u.original_filename, us.username, 
              (SELECT COALESCE(SUM(vote),0) FROM votes WHERE item_id=u.id AND item_type='upload') as net_votes, 
              (SELECT COUNT(*) FROM upload_comments WHERE upload_id=u.id) as comment_count 
              FROM uploads u LEFT JOIN users us ON u.user_id=us.id 
              WHERE u.upload_type = 'document'
              {$order_by_clause} LIMIT :limit OFFSET :offset";
    
    $lobby_stmt = $pdo->prepare($query);
    $lobby_stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
    $lobby_stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $lobby_stmt->execute();
    ?>
    <!DOCTYPE html><html lang="en"><head><title>Documents</title><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="admin_style.css"><style>.pagination { text-align: center; margin-top: 20px; } .pagination a, .pagination span { margin: 0 5px; text-decoration: none; padding: 5px 10px; border: 1px solid #555; background: #333; color: #fff; border-radius: 3px; } .pagination span.current-page { background: #cc0000; border-color: #ff3333; } .pagination a:hover { background: #555; }</style></head><body class="standalone-page" style="padding: 20px;">
        <div class="admin-container gallery-grid-container">
            <header><h1>Documents</h1><a href="chat.php" class="back-link">Back to Chat</a></header>
            <div class="comment-sort-options" style="text-align:right;margin-bottom:15px;font-size:1.1em;"><a href="?sort=popular" style="margin-right:15px;<?php if($sort_order === 'popular') echo 'text-decoration:underline;';?>">Popular</a><a href="?sort=newest" style="<?php if($sort_order === 'newest') echo 'text-decoration:underline;';?>">Newest</a></div>
            <div class="image-lobby-grid">
                <?php
                if ($lobby_stmt->rowCount() === 0) {
                    echo "<p style='text-align:center; color:#aaa; width:100%;'>No documents have been uploaded yet.</p>";
                } else {
                    foreach ($lobby_stmt->fetchAll(PDO::FETCH_ASSOC) as $item) {
                        $display_text = htmlspecialchars($item['link_text'] ?: $item['original_filename']);
                        echo '<a href="?view_doc_id=' . $item['id'] . '" class="image-lobby-item">';
                        echo '<div class="image-lobby-header"><strong>' . $display_text . '</strong></div>';
                        echo '<div class="image-lobby-video-placeholder" style="display:flex; align-items:center; justify-content:center; height:120px; background:#222; font-size: 3em;">📄</div>';
                        echo '<div class="image-lobby-info"><small>by ' . htmlspecialchars($item['username'] ?? 'Unknown') . '</small>';
                        echo '<div class="image-lobby-footer"><span>Votes: ' . ($item['net_votes'] > 0 ? '+' : '') . $item['net_votes'] . '</span><span>Comments: ' . $item['comment_count'] . '</span></div>';
                        echo '</div></a>';
                    }
                }
                ?>
            </div>
            <div class="pagination">
                <?php
                if ($total_pages > 1) {
                    if ($current_page > 1) { echo '<a href="?sort=' . $sort_order . '&page=' . ($current_page - 1) . '">« Previous</a>'; }
                    for ($i = 1; $i <= $total_pages; $i++) { echo ($i == $current_page) ? '<span class="current-page">' . $i . '</span>' : '<a href="?sort=' . $sort_order . '&page=' . $i . '</a>'; }
                    if ($current_page < $total_pages) { echo '<a href="?sort=' . $sort_order . '&page=' . ($current_page + 1) . '">Next »</a>'; }
                }
                ?>
            </div>
        </div>
    </body></html>
    <?php
}