<?php
// gallery.php (V12 - Final Version with Threaded Comments & New Layout)

session_start();
require_once 'config.php';
require_once 'database.php';
require_once 'functions.php';
// --- Permission Check ---
$pdo = get_database_connection(); // Ensure PDO is available
$settings = $pdo->query("SELECT setting_key, setting_value FROM settings")->fetchAll(PDO::FETCH_KEY_PAIR);
$role_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];
$user_role = strtolower($_SESSION['user_role'] ?? 'guest');

// Determine the correct permission key based on the filename
$filename = basename($_SERVER['PHP_SELF']);
$permission_key = 'view_allowed_roles_images'; // Default for gallery.php
if ($filename === 'docs.php') {
    $permission_key = 'view_allowed_roles_docs';
} elseif ($filename === 'zips.php') {
    $permission_key = 'view_allowed_roles_zips';
}

$required_role = $settings[$permission_key] ?? 'admin';
if (!isset($role_hierarchy[$user_role]) || $role_hierarchy[$user_role] < $role_hierarchy[$required_role]) {
    die("You do not have permission to view this page.");
}



$pdo = get_database_connection();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Universal Action Handler ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['action'])) {
    if (!isset($_REQUEST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_REQUEST['csrf_token'])) {
        render_csrf_error_page();
    }

    $image_id = (int)($_REQUEST['view_image_id'] ?? 0);
    $sort = isset($_GET['sort']) ? '&sort=' . urlencode($_GET['sort']) : '';
    $redirect_url = 'gallery.php' . ($image_id > 0 ? '?view_image_id=' . $image_id . $sort : '');

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['submit_comment']) && $image_id > 0) {
            $comment_text = trim($_POST['comment_text'] ?? '');
            $parent_id = !empty($_POST['parent_id']) ? (int)$_POST['parent_id'] : null;
            if (!empty($comment_text) && isset($_SESSION['username'])) {
                $pdo->prepare("INSERT INTO upload_comments (upload_id, user_id, guest_id, username, comment_text, parent_id) VALUES (?, ?, ?, ?, ?, ?)")->execute([$image_id, $_SESSION['user_id'] ?? null, $_SESSION['guest_id'] ?? null, $_SESSION['username'], $comment_text, $parent_id]);
            }
        }
        if (isset($_POST['submit_vote'])) {
            $item_id=(int)($_POST['item_id']??0); $item_type=$_POST['item_type']??''; $vote_value=(int)$_POST['submit_vote'];
            $voter_fp = $_COOKIE['rotchat_fp'] ?? 'unknown';
            if ($item_id > 0 && in_array($item_type, ['upload', 'comment']) && in_array($vote_value, [1, -1])) {
                $pdo->prepare("INSERT INTO votes (voter_fingerprint, item_id, item_type, vote) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE vote = VALUES(vote)")->execute([$voter_fp, $item_id, $item_type, $vote_value]);
            }
        }
    }
    
    if (isset($_GET['action']) && isset($_SESSION['user_id'])) {
        $user_role = strtolower($_SESSION['user_role'] ?? 'guest');
        if ($_GET['action'] === 'delete_post' && $image_id > 0) {
            $stmt = $pdo->prepare("SELECT unique_filename, user_id FROM uploads WHERE id = ?");
            $stmt->execute([$image_id]);
            if (($upload = $stmt->fetch()) && ($upload['user_id'] === $_SESSION['user_id'] || $user_role === 'admin')) {
                $pdo->beginTransaction();
                try {
                    // 1. Delete the original chat message that created the link
                    $message_tag1 = '[VIEWFILE%id=' . $image_id . ']%';
                    $message_tag2 = '%id=' . $image_id . ']%'; // For IMAGE, DOC, ZIP tags
                    $delete_msg_stmt = $pdo->prepare("DELETE FROM messages WHERE (message LIKE ? OR message LIKE ?) AND user_id = ?");
                    $delete_msg_stmt->execute([$message_tag1, $message_tag2, $upload['user_id']]);

                    // 2. Delete the physical file
                    $filePath = __DIR__ . '/uploads/' . $upload['unique_filename'];
                    if (file_exists($filePath)) {
                        @unlink($filePath);
                    }

                    // 3. Delete all associated comments
                    $pdo->prepare("DELETE FROM upload_comments WHERE upload_id = ?")->execute([$image_id]);
                    
                    // 4. Delete all associated votes
                    $pdo->prepare("DELETE FROM votes WHERE item_type = 'upload' AND item_id = ?")->execute([$image_id]);
                    
                    // 5. Delete the main upload record
                    $pdo->prepare("DELETE FROM uploads WHERE id = ?")->execute([$image_id]);

                    $pdo->commit();
                    $redirect_url = 'gallery.php';
                } catch (Exception $e) {
                    $pdo->rollBack();
                    // Optional: Log error $e->getMessage()
                }
            }
        }
        if ($_GET['action'] === 'delete_comment' && $image_id > 0) {
            $comment_id = (int)($_GET['comment_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT user_id, guest_id FROM upload_comments WHERE id = ?");
            $stmt->execute([$comment_id]);
            if (($comment = $stmt->fetch())) {
                $is_owner = ($comment['user_id'] == ($_SESSION['user_id'] ?? -1)) || ($comment['guest_id'] == ($_SESSION['guest_id'] ?? -1));
                if ($is_owner || $user_role === 'admin') {
                    $pdo->prepare("DELETE FROM upload_comments WHERE parent_id = ?")->execute([$comment_id]);
                    $pdo->prepare("DELETE FROM upload_comments WHERE id = ?")->execute([$comment_id]);
                }
            }
        }
    }
    header('Location: ' . $redirect_url . '#comment-form');
    exit();
}

if (!isset($_SESSION['session_id'])) {
    die('Access Denied.');
}

// --- Page Router ---
$image_id_to_view = $_GET['view_image_id'] ?? null;
if ($image_id_to_view && ctype_digit($image_id_to_view)) {
    // --- RENDER SINGLE IMAGE VIEWER ---
    $upload_id = (int)$image_id_to_view;
    $stmt = $pdo->prepare("SELECT u.*, us.username as uploader_username, (SELECT COALESCE(SUM(vote), 0) FROM votes WHERE item_id = u.id AND item_type = 'upload') as net_votes, (SELECT COUNT(*) FROM upload_comments WHERE upload_id=u.id) as comment_count FROM uploads u LEFT JOIN users us ON u.user_id = us.id WHERE u.id = ?");
    $stmt->execute([$upload_id]);
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

function display_threaded_comments($comments, $parent_id, $csrf_token, $upload_id, $level = 0) {
    $user_role = strtolower($_SESSION['user_role'] ?? 'guest');
    foreach ($comments as $comment) {
        if ($comment['parent_id'] == $parent_id) {
            $score_class = $comment['net_votes'] > 0 ? 'positive' : ($comment['net_votes'] < 0 ? 'negative' : '');
            $is_owner = (isset($_SESSION['user_id']) && $comment['user_id'] == $_SESSION['user_id']) || (isset($_SESSION['guest_id']) && $comment['guest_id'] == $_SESSION['guest_id']);
            
            echo '<div class="comment-container" style="'.($level > 0 ? 'margin-left: 25px;' : '').'">';
            echo '<div class="comment-header"><strong>' . htmlspecialchars($comment['username']) . '</strong><small>' . date('M j, Y H:i', strtotime($comment['created_at'])) . '</small></div>';
            echo '<div class="comment-body">' . nl2br(htmlspecialchars($comment['comment_text'])) . '</div>';
            
            echo '<div class="comment-actions">';
                echo '<div class="vote-bar">'; // New streamlined container for votes
                    echo '<form class="vote-form" method="post" action="gallery.php?view_image_id=' . $upload_id . '"><input type="hidden" name="csrf_token" value="' . $csrf_token . '"><input type="hidden" name="item_id" value="' . $comment['id'] . '"><input type="hidden" name="item_type" value="comment"><button name="submit_vote" type="submit" value="1" class="vote-btn up">▲</button></form>';
                    echo '<span class="vote-count ' . $score_class . '">' . ($comment['net_votes'] > 0 ? '+' : '') . $comment['net_votes'] . '</span>';
                    echo '<form class="vote-form" method="post" action="gallery.php?view_image_id=' . $upload_id . '"><input type="hidden" name="csrf_token" value="' . $csrf_token . '"><input type="hidden" name="item_id" value="' . $comment['id'] . '"><input type="hidden" name="item_type" value="comment"><button name="submit_vote" type="submit" value="-1" class="vote-btn down">▼</button></form>';
                echo '</div>';
                
                echo '<div class="management-actions">'; // New container for reply/delete
                if ($is_owner || $user_role === 'admin') {
                    echo '<a href="gallery.php?action=delete_comment&view_image_id=' . $upload_id . '&comment_id=' . $comment['id'] . '&csrf_token=' . $csrf_token . '" class="reply-toggle" onclick="return confirm(\'Delete this comment?\');">Delete</a>';
                }
                echo '<a href="gallery.php?view_image_id=' . $upload_id . '&reply_to=' . $comment['id'] . '#comment-form" class="reply-toggle">Reply</a>';
                echo '</div>';
            echo '</div>'; // .comment-actions

            display_threaded_comments($comments, $comment['id'], $csrf_token, $upload_id, $level + 1);
            echo '</div>'; // .comment-container
        }
    }
}
    
    ?>
    <!DOCTYPE html><html lang="en"><head><title>Viewer</title><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="admin_style.css"></head><body class="standalone-page" style="padding: 20px;">
        <div class="admin-container viewer-container">
            <header>
                <h1><?php echo htmlspecialchars($upload['link_text'] ?: $upload['original_filename']); ?></h1>
                <div>
                    <?php if (($upload['user_id'] === ($_SESSION['user_id'] ?? -1)) || (strtolower($_SESSION['user_role'] ?? 'guest') === 'admin')): ?>
                        <a href="gallery.php?action=delete_post&view_image_id=<?php echo $upload_id; ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="back-link danger-btn" onclick="return confirm('Are you sure you want to delete this post?');">Delete Post</a>
                    <?php endif; ?>
                    <a href="gallery.php" class="back-link" style="margin-left: 10px;">Back to Gallery</a>
                </div>
            </header>
            <div class="image-display-box">
                <?php if (strpos($upload['mime_type'], 'video/') === 0): ?>
                    <video controls style="max-width: 100%; max-height: 50vh;" preload="metadata">
                        <source src="<?php echo htmlspecialchars($upload['file_path']); ?>" type="<?php echo htmlspecialchars($upload['mime_type']); ?>">
                        Your browser does not support the video tag.
                    </video>
                <?php else: // Default to image if not a video ?>
                    <a href="<?php echo htmlspecialchars($upload['file_path']); ?>" target="_blank" title="View full size image"><img src="<?php echo htmlspecialchars($upload['file_path']); ?>" alt="Image"></a>
                <?php endif; ?>
            </div>
            <div class="image-stats-bar">
                <div class="vote-bar">
                    <form class="vote-form" method="post" action="<?php echo basename($_SERVER['PHP_SELF']); ?>?view_<?php echo rtrim(str_replace('.php', '', basename($_SERVER['PHP_SELF'])), 's'); ?>_id=<?php echo $upload_id; ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="hidden" name="item_id" value="<?php echo $upload_id; ?>">
                        <input type="hidden" name="item_type" value="upload">
                        <button name="submit_vote" type="submit" value="1" class="vote-btn up">▲</button>
                    </form>
                    <span class="vote-count <?php echo ($upload['net_votes'] > 0 ? 'positive' : ($upload['net_votes'] < 0 ? 'negative' : ''));?>"><?php echo ($upload['net_votes'] > 0 ? '+' : '') . $upload['net_votes']; ?></span>
                    <form class="vote-form" method="post" action="<?php echo basename($_SERVER['PHP_SELF']); ?>?view_<?php echo rtrim(str_replace('.php', '', basename($_SERVER['PHP_SELF'])), 's'); ?>_id=<?php echo $upload_id; ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="hidden" name="item_id" value="<?php echo $upload_id; ?>">
                        <input type="hidden" name="item_type" value="upload">
                        <button name="submit_vote" type="submit" value="-1" class="vote-btn down">▼</button>
                    </form>
                </div>
                <span class="stat">Uploader: <strong><?php echo htmlspecialchars($upload['uploader_username'] ?? 'Unknown'); ?></strong></span>
                <span class="stat">Views: <strong><?php echo $upload['current_views']; ?><?php if ($upload['max_views']) echo ' / ' . $upload['max_views']; ?></strong></span>
                <?php if (basename($_SERVER['PHP_SELF']) === 'zips.php'): ?>
                    <span class="stat">Downloads: <strong><?php echo $upload['download_count']; ?></strong></span>
                <?php endif; ?>
                <span class="stat">Comments: <strong><?php echo $upload['comment_count']; ?></strong></span>
            </div>
            <?php if ($upload['expires_at'] || $upload['max_views']): ?>
            <div class="image-expiry-info" style="text-align: center; margin-top: -15px; margin-bottom: 20px;">
                <?php
                    $expiry_parts = [];
                    if ($upload['expires_at']) $expiry_parts[] = "Expires on " . date('M j, Y', strtotime($upload['expires_at']));
                    if ($upload['max_views']) $expiry_parts[] = "deletes after " . $upload['max_views'] . " views";
                    echo "ℹ️ This file " . implode(", or ", $expiry_parts) . ".";
                ?>
            </div>
            <?php endif; ?>

            <div class="comments-section">
                <div class="comment-sort-options">
                    <strong>Sort by:</strong>
                    <a href="?view_image_id=<?php echo $upload_id; ?>&sort=popular#comment-form" class="<?php if(($_GET['sort']??'popular')==='popular') echo 'active';?>">Popular</a>
                    <a href="?view_image_id=<?php echo $upload_id; ?>&sort=newest#comment-form" class="<?php if(($_GET['sort']??'')==='newest') echo 'active';?>">Newest</a>
                </div>
                <h2 id="comment-form">Comments</h2>
                <?php
                    $reply_to_id = $_GET['reply_to'] ?? null;
                    if ($reply_to_id) {
                        $stmt = $pdo->prepare("SELECT username FROM upload_comments WHERE id = ?"); $stmt->execute([$reply_to_id]);
                        $reply_to_user = $stmt->fetchColumn();
                        if($reply_to_user) echo '<div class="reply-context"><p>Replying to <strong>'.htmlspecialchars($reply_to_user).'</strong>... <a href="?view_image_id='.$upload_id.'#comment-form">Cancel</a></p></div>';
                    }
                ?>
                <form action="gallery.php?view_image_id=<?php echo $upload_id; ?>" method="post" style="margin-bottom: 20px;">
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
                    display_threaded_comments($all_comments_for_thread, null, $_SESSION['csrf_token'], $upload_id); 
                } else {
                    echo "<p style='text-align:center;color:#aaa'>No comments yet.</p>";
                }
                ?>
            </div>
        </div>
    </body></html>
    <?php
} else {
    // --- RENDER GALLERY GRID WITH PAGINATION ---
    $sort_order = $_GET['sort'] ?? 'popular';
    $current_page = isset($_GET['page']) && ctype_digit($_GET['page']) ? (int)$_GET['page'] : 1;
    $images_per_page = 20;
    $offset = ($current_page - 1) * $images_per_page;

    // Get total number of images for pagination
    $total_images_stmt = $pdo->query("SELECT COUNT(*) FROM uploads WHERE (mime_type LIKE 'image/%' OR mime_type LIKE 'video/%')");
    $total_images = (int)$total_images_stmt->fetchColumn();
    $total_pages = ceil($total_images / $images_per_page);

    // Determine the sorting order
    $order_by_clause = "ORDER BY net_votes DESC, u.created_at DESC";
    if ($sort_order === 'newest') { $order_by_clause = "ORDER BY u.created_at DESC"; }

    // Fetch the images for the current page
    $query = "SELECT u.id, u.link_text, u.original_filename, u.file_path, u.mime_type, u.thumbnail_path, us.username, 
              (SELECT COALESCE(SUM(vote),0) FROM votes WHERE item_id=u.id AND item_type='upload') as net_votes, 
              (SELECT COUNT(*) FROM upload_comments WHERE upload_id=u.id) as comment_count 
              FROM uploads u LEFT JOIN users us ON u.user_id=us.id 
              WHERE (u.mime_type LIKE 'image/%' OR u.mime_type LIKE 'video/%') 
              {$order_by_clause} LIMIT :limit OFFSET :offset";
    
    $lobby_stmt = $pdo->prepare($query);
    $lobby_stmt->bindValue(':limit', $images_per_page, PDO::PARAM_INT);
    $lobby_stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $lobby_stmt->execute();
    ?>
    <!DOCTYPE html><html lang="en"><head><title>Gallery</title><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="admin_style.css"><style>.pagination { text-align: center; margin-top: 20px; } .pagination a, .pagination span { margin: 0 5px; text-decoration: none; padding: 5px 10px; border: 1px solid #555; background: #333; color: #fff; border-radius: 3px; } .pagination span.current-page { background: #cc0000; border-color: #ff3333; } .pagination a:hover { background: #555; }</style></head><body class="standalone-page" style="padding: 20px;">
        <div class="admin-container gallery-grid-container">
            <header><h1>Image Gallery</h1></header>
            <div class="comment-sort-options" style="text-align:right;margin-bottom:15px;font-size:1.1em;"><a href="?sort=popular" style="margin-right:15px;<?php if($sort_order === 'popular') echo 'text-decoration:underline;';?>">Popular</a><a href="?sort=newest" style="<?php if($sort_order === 'newest') echo 'text-decoration:underline;';?>">Newest</a></div>
            <div class="image-lobby-grid">
                <?php
                foreach ($lobby_stmt->fetchAll(PDO::FETCH_ASSOC) as $item) {
                    $display_text = htmlspecialchars($item['link_text'] ?: $item['original_filename']);
                    $is_video = strpos($item['mime_type'], 'video/') === 0;
                    $display_src = htmlspecialchars($item['thumbnail_path'] ?: $item['file_path']);

                    echo '<a href="?view_image_id=' . $item['id'] . '" class="image-lobby-item">';
                    echo '<div class="image-lobby-header"><strong>' . $display_text . '</strong></div>';
                    
                    if ($is_video && empty($item['thumbnail_path'])) {
                        echo '<div class="image-lobby-video-placeholder" style="display:flex; align-items:center; justify-content:center; height:120px; background:#000; font-size: 3em;">🎬</div>';
                    } else {
                        echo '<img src="' . $display_src . '" alt="' . $display_text . '">';
                    }
                    
                    echo '<div class="image-lobby-info"><small>by ' . htmlspecialchars($item['username'] ?? 'Unknown') . '</small>';
                    echo '<div class="image-lobby-footer"><span>Votes: ' . ($item['net_votes'] > 0 ? '+' : '') . $item['net_votes'] . '</span><span>Comments: ' . $item['comment_count'] . '</span></div>';
                    echo '</div></a>';
                }
                ?>
            </div>
            <div class="pagination">
                <?php
                if ($current_page > 1) {
                    echo '<a href="?sort=' . $sort_order . '&page=' . ($current_page - 1) . '">« Previous</a>';
                }
                for ($i = 1; $i <= $total_pages; $i++) {
                    if ($i == $current_page) {
                        echo '<span class="current-page">' . $i . '</span>';
                    } else {
                        echo '<a href="?sort=' . $sort_order . '&page=' . $i . '">' . $i . '</a>';
                    }
                }
                if ($current_page < $total_pages) {
                    echo '<a href="?sort=' . $sort_order . '&page=' . ($current_page + 1) . '">Next »</a>';
                }
                ?>
            </div>
        </div>
    </body></html>
    <?php
}
?>