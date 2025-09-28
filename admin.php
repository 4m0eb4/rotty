<?php
// admin.php (V19 - Tabbed Layout Overhaul)
// Production Error Handling: Log errors, don't display them.
ini_set('display_errors', 0);
ini_set('log_errors', 1);
// Note: It's best to set error_log in your server's php.ini file.
error_reporting(E_ALL);

session_start();

require_once 'config.php';
require_once 'database.php';

// Renders a styled, full-page access denied message and terminates the script.
function render_access_denied($message = 'Access Denied.')
{
    // Check for our internal fatal error signal
    $is_fatal_error = ($message === 'SYSTEM_FATAL_ERROR');
    $display_message = $is_fatal_error ? 'A critical error occurred. The incident has been logged.' : $message;

    // Only send headers if they haven't been sent already
    if (!headers_sent()) {
        header('Content-Type: text/html; charset=UTF-8');
        if ($is_fatal_error) {
            header('HTTP/1.1 500 Internal Server Error');
        }
    }

    ob_start();
    ?>
    <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Access Denied</title><link rel="stylesheet" href="admin_style.css"></head><body>
    <div class="admin-container" style="display: block; max-width: 600px; margin: 50px auto;"><div class="admin-section active" style="text-align: center; border-color: var(--danger-border); box-shadow: 0 0 15px var(--red-glow);">
    <h2>ACCESS DENIED</h2><p style="background: var(--danger-bg); color: var(--danger-text); padding: 15px; border-radius: 5px;"><?php echo htmlspecialchars($display_message); ?></p>
    <a href="chat.php" target="_top" class="btn" style="background: #333; color: #fff; margin-top: 20px;">Return to Chat</a>
    </div></div></body></html>
    <?php
    echo ob_get_clean();
    die();
}

// --- Global Exception Handler ---
// Catches fatal errors (like DB connection failure) to prevent path disclosure.
set_exception_handler(function($exception) {
    // Log the actual error message to the server's error log.
    error_log("Uncaught Exception: " . $exception->getMessage() . " in " . $exception->getFile() . " on line " . $exception->getLine());
    // Display a generic, safe error page to the user.
    render_access_denied('SYSTEM_FATAL_ERROR');
});

// --- Security Check: Must be a logged-in admin. ---
if (strtolower($_SESSION['user_role'] ?? '') !== 'admin') {
    render_access_denied("You must be an admin to view this page.");
}

// --- Generate CSRF token if it doesn't exist ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Establish DB connection
$pdo = get_database_connection();

// --- Section & State Management ---
$sections = [
    'dashboard' => 'Dashboard',
    'core-config' => 'Core Config',
    'moderation' => 'Content & Spam',
    'upload-management' => 'Uploads & Files',
    'live-visuals' => 'Live Visuals',
    'site-wide-settings' => 'Site-Wide Settings',
    'channel-management' => 'Channel Management',
    'chat-tools' => 'Chat Tools',
    'session-management' => 'Session Management',
    'game-management' => 'Game Management',
    'new-members' => 'New Members',
    'online-users' => 'Online Users',
    'guest-management' => 'Guest Management',
    'guest-ban-management' => 'Guest Ban Management',
    'active-cooldowns' => 'Active Cooldowns',
    'user-management' => 'User Management',
    'banned-users' => 'Banned Members',
    'deactivated-users' => 'Deactivated Accounts',
    'ban-management' => 'Ban System (IP/Fingerprint)',
    'kick-logs' => 'Kick Logs',
    'deletion-logs' => 'Deletion Logs',
    'feedback-viewer' => 'Feedback Viewer',
];

$current_section = $_GET['section'] ?? 'dashboard';
if (!array_key_exists($current_section, $sections)) {
    $current_section = 'dashboard';
}

// --- Handle ALL Admin Actions (POST Requests) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token.');
    }

    $source_section = $_POST['source_section'] ?? $current_section;

    // --- Channel Management ---
    if (isset($_POST['create_channel'])) {
        $name = trim($_POST['channel_name'] ?? ''); $topic = trim($_POST['channel_topic'] ?? ''); $min_role = $_POST['min_role'] ?? 'guest';
        if (!empty($name) && preg_match('/^[a-zA-Z0-9_-]+$/', $name) && in_array($min_role, ['guest', 'user', 'trusted', 'moderator', 'admin'])) {
            try { $pdo->prepare("INSERT INTO channels (name, topic, min_role) VALUES (?, ?, ?)")->execute([$name, $topic, $min_role]); $_SESSION['admin_feedback'] = "Channel '".htmlspecialchars($name)."' created."; } catch (PDOException $e) { $_SESSION['admin_feedback'] = "Error: Channel name already exists."; }
        } else { $_SESSION['admin_feedback'] = "Error: Invalid channel name."; }
    }
    if (isset($_POST['update_channel'])) {
        $channel_id = $_POST['channel_id_to_update'] ?? null; $topic = trim($_POST['updated_channel_topic'] ?? ''); $min_role = $_POST['updated_min_role'] ?? 'guest';
        $stmt = $pdo->prepare("SELECT name FROM channels WHERE id = ?"); $stmt->execute([$channel_id]); $channel_name = $stmt->fetchColumn();
        if ($channel_name === 'general') { $min_role = 'guest'; }
        if ($channel_id && in_array($min_role, ['guest', 'user', 'trusted', 'moderator', 'admin'])) {
            $pdo->prepare("UPDATE channels SET topic = ?, min_role = ? WHERE id = ?")->execute([$topic, $min_role, $channel_id]); $_SESSION['admin_feedback'] = "Channel '".htmlspecialchars($channel_name)."' updated.";
        } else { $_SESSION['admin_feedback'] = "Error: Invalid data for channel update."; }
    }
    if (isset($_POST['delete_channel'])) {
        $channel_id = $_POST['channel_id'] ?? null;
        $stmt = $pdo->prepare("SELECT name FROM channels WHERE id = ?"); $stmt->execute([$channel_id]);
        if (($channel_name = $stmt->fetchColumn()) && $channel_name !== 'general') {
            $pdo->prepare("DELETE FROM channels WHERE id = ?")->execute([$channel_id]); $_SESSION['admin_feedback'] = "Channel deleted.";
        } else { $_SESSION['admin_feedback'] = "Error: Cannot delete this channel."; }
    }

    // --- Core Config ---
    if (isset($_POST['update_core_settings'])) {
        $guest_tokens = (int)($_POST['guest_default_tokens'] ?? 0); $history_limit = (int)($_POST['chat_history_limit'] ?? 150); $kick_cooldown = (int)($_POST['kick_cooldown_minutes'] ?? 5);
        if ($guest_tokens >= 0 && $history_limit > 0 && $kick_cooldown >= 0) {
            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'guest_default_tokens'")->execute([$guest_tokens]);
            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'chat_history_limit'")->execute([$history_limit]);
            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'kick_cooldown_minutes'")->execute([$kick_cooldown]);
            $_SESSION['admin_feedback'] = "Core settings updated.";
        } else { $_SESSION['admin_feedback'] = "Error: Invalid core settings values."; }
    }

    // --- Content & Spam Moderation ---
    if (isset($_POST['update_filters'])) {
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'banned_words_list'")->execute([$_POST['banned_words_list'] ?? '']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'banned_name_words_list'")->execute([$_POST['banned_name_words_list'] ?? '']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'forbidden_domains'")->execute([$_POST['forbidden_domains_list'] ?? '']);
        $_SESSION['admin_feedback'] = "Moderation filters saved.";
    }

// --- Upload Management ---
if (isset($_POST['update_upload_settings'])) {
    // Save permissions for Images, Docs, Zips, and new Audio type
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'upload_allowed_roles'")->execute([$_POST['upload_allowed_roles_images'] ?? 'admin']);
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'view_allowed_roles_images'")->execute([$_POST['view_allowed_roles_images'] ?? 'admin']);
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'upload_allowed_roles_docs'")->execute([$_POST['upload_allowed_roles_docs'] ?? 'admin']);
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'view_allowed_roles_docs'")->execute([$_POST['view_allowed_roles_docs'] ?? 'admin']);
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'upload_allowed_roles_zips'")->execute([$_POST['upload_allowed_roles_zips'] ?? 'admin']);
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'view_allowed_roles_zips'")->execute([$_POST['view_allowed_roles_zips'] ?? 'admin']);
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'upload_allowed_roles_audio'")->execute([$_POST['upload_allowed_roles_audio'] ?? 'admin']);
    $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'view_allowed_roles_audio'")->execute([$_POST['view_allowed_roles_audio'] ?? 'admin']);

    $limit_user = (int)($_POST['upload_limit_user'] ?? 5);
    $limit_trusted = (int)($_POST['upload_limit_trusted'] ?? 20);
    $limit_moderator = (int)($_POST['upload_limit_moderator'] ?? 50);
    $max_size = (int)($_POST['max_file_size_kb'] ?? 2048);

    // IMPORTANT: To allow MP3s, you must manually add 'mp3' to the "Allowed File Extensions" field on the form.
    // This code just saves whatever is in that field.
    $allowed_types = strtolower(preg_replace('/[^a-zA-Z0-9,]/', '', $_POST['allowed_file_types'] ?? ''));

    if ($max_size > 0 && $limit_user >= 0 && $limit_trusted >= 0 && $limit_moderator >= 0) {
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'upload_limit_user'")->execute([$limit_user]);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'upload_limit_trusted'")->execute([$limit_trusted]);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'upload_limit_moderator'")->execute([$limit_moderator]);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'allowed_file_types'")->execute([$allowed_types]);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'max_file_size_kb'")->execute([$max_size]);
        $_SESSION['admin_feedback'] = "Upload settings updated. Make sure you have added 'mp3' to the allowed file types list.";
    } else {
        $_SESSION['admin_feedback'] = "Error: Invalid upload settings values.";
    }
}

    // --- Live Visuals ---
    if (isset($_POST['update_visual_settings'])) {
        $glow_colors = array_filter([trim($_POST['glow_color_1'] ?? ''), trim($_POST['glow_color_2'] ?? ''), trim($_POST['glow_color_3'] ?? '')]);
        $final_glow_value = 'linear-gradient(to bottom, #cc0000, #ff00ff)';
        if (count($glow_colors) === 1) { $final_glow_value = "linear-gradient(to bottom, " . $glow_colors[0] . ", " . $glow_colors[0] . ")"; }
        elseif (count($glow_colors) > 1) { $final_glow_value = "linear-gradient(to bottom, " . implode(', ', $glow_colors) . ")"; }
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'chat_border_color'")->execute([$_POST['chat_border_color'] ?? '#cc0000']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'chat_glow_color'")->execute([$final_glow_value]);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'title_animation'")->execute([$_POST['title_animation'] ?? '1']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'special_effect'")->execute([$_POST['special_effect'] ?? 'none']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'default_enable_visual_effects'")->execute([$_POST['default_enable_visual_effects'] ?? '0']);
        $_SESSION['admin_feedback'] = "Visual settings updated.";
    }

    // --- Site-Wide Settings ---
    if (isset($_POST['update_site_settings'])) {
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'announcement_message'")->execute([$_POST['announcement_message'] ?? '']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'announcement_level'")->execute([$_POST['announcement_level'] ?? 'hidden']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'system_message_level'")->execute([$_POST['system_message_level'] ?? 'all']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'site_rules'")->execute([$_POST['site_rules'] ?? '']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'stats_show_total_members'")->execute([isset($_POST['stats_show_total_members']) ? '1' : '0']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'stats_show_messages_today'")->execute([isset($_POST['stats_show_messages_today']) ? '1' : '0']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'stats_show_online_total'")->execute([isset($_POST['stats_show_online_total']) ? '1' : '0']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'stats_show_online_guests'")->execute([isset($_POST['stats_show_online_guests']) ? '1' : '0']);
        $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'enable_login_captcha'")->execute([isset($_POST['enable_login_captcha']) ? '1' : '0']);
        $_SESSION['admin_feedback'] = "Site-wide settings updated.";
    }
    
// Role & delete-permission settings update
if (isset($_POST['update_role_delete_config'])) {
    if (!empty($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
        // Normalize CSVs to lowercase, trimmed, unique
        $norm = function($csv) {
            $parts = array_filter(array_map(function($p){ return strtolower(trim($p)); }, explode(',', (string)$csv)));
            return implode(',', array_values(array_unique($parts)));
        };

        $trusted_mode = (($_POST['trusted_delete_mode'] ?? 'own') === 'all') ? 'all' : 'own';
        $known_roles  = $norm($_POST['known_roles']  ?? ($settings['known_roles']  ?? 'admin,moderator,supermod,trusted,member,guest'));
        $del_any      = $norm($_POST['roles_delete_any'] ?? ($settings['roles_delete_any'] ?? 'admin,moderator,supermod'));
        $del_own      = $norm($_POST['roles_delete_own'] ?? ($settings['roles_delete_own'] ?? 'trusted,member'));

        $up = $pdo->prepare("
            INSERT INTO settings (setting_key, setting_value) VALUES
            ('trusted_delete_mode', ?),
            ('known_roles', ?),
            ('roles_delete_any', ?),
            ('roles_delete_own', ?)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
        ");
        $up->execute([$trusted_mode, $known_roles, $del_any, $del_own]);

        // keep in-memory if available
        if (isset($settings) && is_array($settings)) {
            $settings['trusted_delete_mode'] = $trusted_mode;
            $settings['known_roles'] = $known_roles;
            $settings['roles_delete_any'] = $del_any;
            $settings['roles_delete_own'] = $del_own;
        }

        $_SESSION['admin_feedback'] = "Role configuration saved.";
    }
}
    
// Role & delete-permission settings update
if (isset($_POST['update_role_delete_config'])) {
    if (!empty($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
        // Normalize CSVs to lowercase, trimmed, unique
        $norm = function($csv) {
            $parts = array_filter(array_map(function($p){ return strtolower(trim($p)); }, explode(',', (string)$csv)));
            return implode(',', array_values(array_unique($parts)));
        };

        $trusted_mode = (($_POST['trusted_delete_mode'] ?? 'own') === 'all') ? 'all' : 'own';
        $known_roles  = $norm($_POST['known_roles']  ?? ($settings['known_roles']  ?? 'admin,moderator,supermod,trusted,member,guest'));
        $del_any      = $norm($_POST['roles_delete_any'] ?? ($settings['roles_delete_any'] ?? 'admin,moderator,supermod'));
        $del_own      = $norm($_POST['roles_delete_own'] ?? ($settings['roles_delete_own'] ?? 'trusted,member'));

        $up = $pdo->prepare("
            INSERT INTO settings (setting_key, setting_value) VALUES
            ('trusted_delete_mode', ?),
            ('known_roles', ?),
            ('roles_delete_any', ?),
            ('roles_delete_own', ?)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
        ");
        $up->execute([$trusted_mode, $known_roles, $del_any, $del_own]);

        // keep in-memory if available
        if (isset($settings) && is_array($settings)) {
            $settings['trusted_delete_mode'] = $trusted_mode;
            $settings['known_roles'] = $known_roles;
            $settings['roles_delete_any'] = $del_any;
            $settings['roles_delete_own'] = $del_own;
        }

        $_SESSION['admin_feedback'] = "Role configuration saved.";
    }
}


    // --- Chat Tools ---
    if (isset($_POST['update_lock_status'])) {
        if (in_array($_POST['chat_lock_level'] ?? '', ['unlocked', 'guest', 'user', 'all'])) {
            $new_lock_level = $_POST['chat_lock_level'];
            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'chat_locked'")->execute([$new_lock_level]);
            $lock_message = "unlocked the chat.";
            if ($new_lock_level === 'guest') { $lock_message = "locked the chat for Guests."; }
            elseif ($new_lock_level === 'user') { $lock_message = "locked the chat for Members and below."; }
            elseif ($new_lock_level === 'all') { $lock_message = "locked the chat for everyone."; }
            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute([$_SESSION['username'], '#ff5555', $lock_message, 1, 'general']);
        }
        if (in_array($_POST['registration_locked'] ?? '', ['0', '1'])) {
            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'registration_locked'")->execute([$_POST['registration_locked']]);
        }
        $_SESSION['admin_feedback'] = "Lock statuses updated.";
    }
    if (isset($_POST['clear_chat'])) {
        $channel_to_clear = $_POST['channel_to_clear'] ?? 'none';
        
        // Fetch valid channel names directly from the database
        $channels_for_tools_stmt = $pdo->query("SELECT name FROM channels");
        $valid_channels = $channels_for_tools_stmt->fetchAll(PDO::FETCH_COLUMN);

        if ($channel_to_clear === 'all') {
            $pdo->exec("TRUNCATE TABLE messages");
            $system_message = htmlspecialchars($_SESSION['username']) . " cleared all messages.";
            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, 'general']);
            $_SESSION['admin_feedback'] = "Entire chat history has been cleared.";
        } elseif (in_array($channel_to_clear, $valid_channels)) {
            $pdo->prepare("DELETE FROM messages WHERE channel = ?")->execute([$channel_to_clear]);
            $system_message = htmlspecialchars($_SESSION['username']) . " cleared #" . htmlspecialchars($channel_to_clear) . ".";
            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel_to_clear]);
            $_SESSION['admin_feedback'] = "Messages from #" . htmlspecialchars($channel_to_clear) . " have been cleared.";
        } else {
            $_SESSION['admin_feedback'] = "Error: Invalid channel selected for clearing.";
        }
    }

    // --- Session Management ---
    if (isset($_POST['clear_idle_sessions'])) {
        $stmt = $pdo->prepare("DELETE FROM sessions WHERE last_active < NOW() - INTERVAL ? SECOND");
        $stmt->execute([$session_timeout]);
        $_SESSION['admin_feedback'] = "Cleared " . $stmt->rowCount() . " idle session(s).";
    }
    if (isset($_POST['generate_token'])) {
        $token = bin2hex(random_bytes(16));
        $placeholder_username = 'unclaimed_' . bin2hex(random_bytes(4));
        $user_color = sprintf('#%02X%02X%02X', mt_rand(100, 240), mt_rand(100, 240), mt_rand(100, 240));
        try {
            $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, registration_token, role, color) VALUES (?, NULL, ?, 'user', ?)");
            $stmt->execute([$placeholder_username, $token, $user_color]);
            $_SESSION['admin_feedback'] = "New Token Generated:\n" . htmlspecialchars($token);
        } catch (PDOException $e) { $_SESSION['admin_feedback'] = "Error generating token: " . $e->getMessage(); }
    }

    // --- Game Management ---
    if (isset($_POST['delete_selected_games'])) {
        $games_to_delete = $_POST['games_to_delete'] ?? [];
        if (!empty($games_to_delete)) {
            $placeholders = implode(',', array_fill(0, count($games_to_delete), '?'));
            $stmt = $pdo->prepare("DELETE FROM games WHERE game_uuid IN ($placeholders)");
            $stmt->execute($games_to_delete);
            $_SESSION['admin_feedback'] = "Deleted " . $stmt->rowCount() . " selected game(s).";
        } else { $_SESSION['admin_feedback'] = "No games selected."; }
    }
    if (isset($_POST['clear_completed_games'])) {
        $stmt = $pdo->prepare("DELETE FROM games WHERE status = 'finished'");
        $stmt->execute();
        $_SESSION['admin_feedback'] = "Cleared " . $stmt->rowCount() . " completed game(s).";
    }

    // --- New Members ---
    if (isset($_POST['bulk_new_member_action'])) {
        $user_ids = array_map('intval', $_POST['new_members_to_manage'] ?? []);
        $action = $_POST['bulk_new_member_action'];
        if (!empty($user_ids)) {
            $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
            if ($action === 'deactivate') {
                $pdo->prepare("UPDATE users SET is_deactivated = 1 WHERE id IN ($placeholders)")->execute($user_ids);
                $pdo->prepare("DELETE FROM sessions WHERE user_id IN ($placeholders)")->execute($user_ids);
                $_SESSION['admin_feedback'] = "Deactivated " . count($user_ids) . " new member(s).";
            } elseif ($action === 'ban') {
                $pdo->prepare("UPDATE users SET is_banned = 1 WHERE id IN ($placeholders)")->execute($user_ids);
                $pdo->prepare("UPDATE sessions SET kick_message = ? WHERE user_id IN ($placeholders)")->execute(["Your account has been banned.", ...$user_ids]);
                $_SESSION['admin_feedback'] = "Banned " . count($user_ids) . " new member(s).";
            }
        } else { $_SESSION['admin_feedback'] = "No new members were selected."; }
    }

// --- Guest Management (from Historical Guest Data) ---
if (isset($_POST['source_section']) && $_POST['source_section'] === 'guest-management') {
    $guest_ids_to_manage = $_POST['guests_to_delete'] ?? [];
    if (!empty($guest_ids_to_manage)) {
        $id_placeholders = implode(',', array_fill(0, count($guest_ids_to_manage), '?'));
        
        // Fetch fingerprint and username for banning and session cleanup
        $stmt_get_guests = $pdo->prepare("SELECT id, username, fingerprint FROM guests WHERE id IN ($id_placeholders)");
        $stmt_get_guests->execute($guest_ids_to_manage);
        $guests_to_process = $stmt_get_guests->fetchAll(PDO::FETCH_ASSOC);

        if (!empty($guests_to_process)) {
            $guest_names = array_column($guests_to_process, 'username');

            if (isset($_POST['ban_selected_guests'])) {
                $pdo->beginTransaction();
                try {
                    // Ban by FINGERPRINT, not by name
                    $stmt_ban_fp = $pdo->prepare("INSERT IGNORE INTO ban_list (ban_type, ban_value, reason, banned_by_user_id) VALUES ('fingerprint', ?, ?, ?)");
                    foreach ($guests_to_process as $guest) {
                        if (!empty($guest['fingerprint'])) {
                            $stmt_ban_fp->execute([$guest['fingerprint'], 'Banned via Guest Management', $_SESSION['user_id']]);
                        }
                    }
                    
                    // Clear active sessions for the banned guests
                    if (!empty($guest_names)) {
                        $name_placeholders = implode(',', array_fill(0, count($guest_names), '?'));
                        $pdo->prepare("DELETE FROM sessions WHERE username IN ($name_placeholders) AND is_guest = 1")->execute($guest_names);
                    }
                    
                    // Delete all associated data
                    $pdo->prepare("DELETE FROM messages WHERE guest_id IN ($id_placeholders)")->execute($guest_ids_to_manage);
                    $pdo->prepare("DELETE FROM guests WHERE id IN ($id_placeholders)")->execute($guest_ids_to_manage);
                    
                    $pdo->commit();
                    $_SESSION['admin_feedback'] = "Successfully banned " . count($guests_to_process) . " guest fingerprint(s) and deleted their records.";
                } catch (Exception $e) {
                    $pdo->rollBack();
                    $_SESSION['admin_feedback'] = "Error during guest banning: " . $e->getMessage();
                }
            } elseif (isset($_POST['delete_selected_guests'])) {
                $pdo->beginTransaction();
                try {
                    $pdo->prepare("DELETE FROM messages WHERE guest_id IN ($id_placeholders)")->execute($guest_ids_to_manage);
                    $stmt = $pdo->prepare("DELETE FROM guests WHERE id IN ($id_placeholders)");
                    $stmt->execute($guest_ids_to_manage);
                    $pdo->commit();
                    $_SESSION['admin_feedback'] = "Deleted " . $stmt->rowCount() . " selected guest record(s).";
                } catch (Exception $e) {
                    $pdo->rollBack();
                    $_SESSION['admin_feedback'] = "Error deleting guests: " . $e->getMessage();
                }
            }
        }
    } else {
        $_SESSION['admin_feedback'] = "No guests were selected.";
    }
}

// --- Online User Management (Bulk Actions) ---
    if (isset($_POST['bulk_online_action'])) {
        $session_ids = $_POST['online_users'] ?? [];
        $action = $_POST['bulk_online_action'];

        if (!empty($session_ids)) {
            // Filter out sessions belonging to admins to prevent self-actions or actions on other admins
            $safe_session_ids = [];
            $placeholders = implode(',', array_fill(0, count($session_ids), '?'));
            $stmt = $pdo->prepare("SELECT s.session_id, s.user_id FROM sessions s LEFT JOIN users u ON s.user_id = u.id WHERE s.session_id IN ($placeholders) AND (u.role IS NULL OR u.role != 'admin')");
            $stmt->execute($session_ids);
            $safe_sessions = $stmt->fetchAll(PDO::FETCH_ASSOC);

            foreach ($safe_sessions as $sess) {
                $safe_session_ids[] = $sess['session_id'];
                if ($sess['user_id']) { // Collect user_ids for member-specific actions
                    $user_ids_for_action[] = $sess['user_id'];
                }
            }

            if (!empty($safe_session_ids)) {
                $safe_placeholders = implode(',', array_fill(0, count($safe_session_ids), '?'));
                $count = 0;
                switch ($action) {
                    case 'kick':
                        $stmt = $pdo->prepare("UPDATE sessions SET kick_message = ? WHERE session_id IN ($safe_placeholders)");
                        $stmt->execute(array_merge(["Kicked by administrator."], $safe_session_ids));
                        $count = $stmt->rowCount();
                        $_SESSION['admin_feedback'] = "Kicked {$count} user(s).";
                        break;
                    case 'ghost':
                        $stmt = $pdo->prepare("UPDATE sessions SET is_shadow_kicked = 1 WHERE session_id IN ($safe_placeholders)");
                        $stmt->execute($safe_session_ids);
                        $count = $stmt->rowCount();
                        $_SESSION['admin_feedback'] = "Ghosted {$count} user(s).";
                        break;
                    case 'unghost':
                        $stmt = $pdo->prepare("UPDATE sessions SET is_shadow_kicked = 0 WHERE session_id IN ($safe_placeholders)");
                        $stmt->execute($safe_session_ids);
                        $count = $stmt->rowCount();
                        $_SESSION['admin_feedback'] = "Unghosted {$count} user(s).";
                        break;
                    case 'deactivate':
                        if (!empty($user_ids_for_action)) {
                            $user_placeholders = implode(',', array_fill(0, count($user_ids_for_action), '?'));
                            $pdo->prepare("UPDATE users SET is_deactivated = 1 WHERE id IN ($user_placeholders)")->execute($user_ids_for_action);
                            $pdo->prepare("DELETE FROM sessions WHERE user_id IN ($user_placeholders)")->execute($user_ids_for_action); // Also end their sessions
                            $_SESSION['admin_feedback'] = "Deactivated " . count($user_ids_for_action) . " selected member(s).";
                        } else {
                            $_SESSION['admin_feedback'] = "No members selected for deactivation.";
                        }
                        break;
                    case 'ban':
                        if (!empty($user_ids_for_action)) {
                            $user_placeholders = implode(',', array_fill(0, count($user_ids_for_action), '?'));
                            $pdo->prepare("UPDATE users SET is_banned = 1 WHERE id IN ($user_placeholders)")->execute($user_ids_for_action);
                            $pdo->prepare("UPDATE sessions SET kick_message = ? WHERE user_id IN ($user_placeholders)")->execute(["Your account has been banned.", ...$user_ids_for_action]); // Also kick and inform
                            $_SESSION['admin_feedback'] = "Banned " . count($user_ids_for_action) . " selected member(s).";
                        } else {
                            $_SESSION['admin_feedback'] = "No members selected for banning.";
                        }
                        break;
                }
            } else {
                $_SESSION['admin_feedback'] = "No non-admin users were selected for the action.";
            }
        } else {
            $_SESSION['admin_feedback'] = "No online users were selected.";
        }
    }

    // --- Deactivated Users ---
    if (isset($_POST['reactivate_selected_users'])) {
        $user_ids = array_map('intval', $_POST['deactivated_users_to_manage'] ?? []);
        if (!empty($user_ids)) {
            $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
            $stmt = $pdo->prepare("UPDATE users SET is_deactivated = 0 WHERE id IN ($placeholders)"); $stmt->execute($user_ids);
            $_SESSION['admin_feedback'] = "Reactivated " . $stmt->rowCount() . " user(s).";
        } else { $_SESSION['admin_feedback'] = "No users selected."; }
    }
    if (isset($_POST['delete_selected_users_perm'])) {
        $user_ids = array_map('intval', $_POST['deactivated_users_to_manage'] ?? []);
        if (!empty($user_ids)) {
            $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
            $pdo->beginTransaction();
            try {
                $pdo->prepare("DELETE FROM messages WHERE user_id IN ($placeholders)")->execute($user_ids);
                $pdo->prepare("DELETE FROM private_messages WHERE from_user_id IN ($placeholders) OR to_user_id IN ($placeholders)")->execute(array_merge($user_ids, $user_ids));
                $pdo->prepare("DELETE FROM sessions WHERE user_id IN ($placeholders)")->execute($user_ids);
                $stmt = $pdo->prepare("DELETE FROM users WHERE id IN ($placeholders)"); $stmt->execute($user_ids);
                $pdo->commit(); $_SESSION['admin_feedback'] = "Permanently deleted " . $stmt->rowCount() . " user(s).";
            } catch (Exception $e) { $pdo->rollBack(); $_SESSION['admin_feedback'] = "Error during deletion: " . $e->getMessage(); }
        } else { $_SESSION['admin_feedback'] = "No users selected for deletion."; }
    }
    
    // --- Ban Management ---
    if (isset($_POST['add_hard_ban'])) {
        $ban_type = $_POST['ban_type'] ?? ''; $ban_value = trim($_POST['ban_value'] ?? ''); $reason = trim($_POST['reason'] ?? 'Manually banned by admin.');
        if (!empty($ban_value) && in_array($ban_type, ['ip', 'fingerprint'])) {
            $pdo->prepare("INSERT INTO ban_list (ban_type, ban_value, reason, banned_by_user_id) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE reason = VALUES(reason), banned_by_user_id = VALUES(banned_by_user_id)")->execute([$ban_type, $ban_value, $reason, $_SESSION['user_id']]);
            $_SESSION['admin_feedback'] = "Added hard ban for '".htmlspecialchars($ban_value)."'.";
        } else { $_SESSION['admin_feedback'] = "Error: Invalid ban type or value."; }
    }
// --- Active Cooldowns Management ---
    if (isset($_POST['source_section']) && $_POST['source_section'] === 'active-cooldowns') {
        if (isset($_POST['remove_cooldown'])) {
            $type = $_POST['type'] ?? '';
            $id = $_POST['id'] ?? 0;
            if ($id > 0) {
                if ($type === 'user') {
                    $pdo->prepare("UPDATE users SET kick_cooldown_until = NULL WHERE id = ?")->execute([$id]);
                    $_SESSION['admin_feedback'] = "Cooldown removed for the member.";
                } elseif ($type === 'guest') {
                    // Correctly targets the guests table to clear the cooldown
                    $pdo->prepare("UPDATE guests SET kick_cooldown_until = NULL WHERE id = ?")->execute([$id]);
                    $_SESSION['admin_feedback'] = "Cooldown removed for the guest.";
                }
            }
        }
    }
// --- Guest Ban Management ---
    if (isset($_POST['source_section']) && $_POST['source_section'] === 'guest-ban-management') {
        if (isset($_POST['add_guest_name_ban'])) {
            $username_to_ban = trim($_POST['username_to_ban'] ?? '');
            $reason = trim($_POST['ban_reason'] ?? 'Banned via admin panel.');
            if (!empty($username_to_ban)) {
                try {
                    // Add the name to the permanent ban list
                    $pdo->prepare("INSERT INTO banned_guest_names (username, reason, banned_by_user_id) VALUES (?, ?, ?)")
                        ->execute([$username_to_ban, $reason, $_SESSION['user_id']]);

                    // Find and terminate any active session for that guest username
                    $kick_stmt = $pdo->prepare("DELETE FROM sessions WHERE username = ? AND is_guest = 1");
                    $kick_stmt->execute([$username_to_ban]);
                    $kicked_count = $kick_stmt->rowCount();

                    $feedback = "Permanently banned the guest name '".htmlspecialchars($username_to_ban)."'.";
                    if ($kicked_count > 0) {
                        $feedback .= " Kicked active session.";
                    }
                    $_SESSION['admin_feedback'] = $feedback;

                } catch (PDOException $e) {
                    if ($e->errorInfo[1] == 1062) { // Duplicate entry
                        $_SESSION['admin_feedback'] = "Error: That guest name is already permanently banned.";
                    } else {
                        $_SESSION['admin_feedback'] = "Database error: " . $e->getMessage();
                    }
                }
            } else {
                $_SESSION['admin_feedback'] = "Error: Username to ban cannot be empty.";
            }
        }
        if (isset($_POST['unban_perm_guest_name'])) {
            $perm_ban_id = $_POST['perm_ban_id'] ?? 0;
            if ($perm_ban_id > 0) {
                $pdo->prepare("DELETE FROM banned_guest_names WHERE id = ?")->execute([$perm_ban_id]);
                $_SESSION['admin_feedback'] = "Permanent guest name ban removed.";
            }
        }
    }


    if (isset($_POST['unban_hard'])) {
        $ban_id = $_POST['ban_id'] ?? '';
        if (!empty($ban_id)) {
            // First, find the ban value so we can use it in the feedback message.
            $stmt_get = $pdo->prepare("SELECT ban_value FROM ban_list WHERE id = ?");
            $stmt_get->execute([$ban_id]);
            $ban_value = $stmt_get->fetchColumn();

            // Now, proceed with deleting the ban.
            $stmt_del = $pdo->prepare("DELETE FROM ban_list WHERE id = ?");
            $stmt_del->execute([$ban_id]);

            // Provide specific feedback based on whether the deletion was successful.
            if ($stmt_del->rowCount() > 0) {
                $_SESSION['admin_feedback'] = "Successfully removed ban for value: '" . htmlspecialchars($ban_value) . "'.";
            } else {
                $_SESSION['admin_feedback'] = "Error: Could not remove ban. It may have been deleted by another administrator already.";
            }
        }
    }
    if (isset($_POST['unban_soft'])) {
        $ban_id = $_POST['name_ban_id'] ?? '';
        if (!empty($ban_id)) { $stmt = $pdo->prepare("DELETE FROM guest_name_bans WHERE id = ?"); $stmt->execute([$ban_id]); $_SESSION['admin_feedback'] = "Soft name ban removed."; }
    }
    if (isset($_POST['escalate_to_hard_ban'])) {
        $fp_to_ban = trim($_POST['fp_to_ban'] ?? ''); $name_ban_id_to_remove = $_POST['name_ban_id'] ?? null;
        if ($fp_to_ban) {
            $reason = "Escalated from soft ban by " . ($_SESSION['username'] ?? 'admin') . ".";
            $pdo->prepare("INSERT INTO ban_list (ban_type, ban_value, reason, banned_by_user_id) VALUES ('fingerprint', ?, ?, ?)")->execute([$fp_to_ban, $reason, $_SESSION['user_id']]);
            if ($name_ban_id_to_remove) { $pdo->prepare("DELETE FROM guest_name_bans WHERE id = ?")->execute([$name_ban_id_to_remove]); }
            $_SESSION['admin_feedback'] = "Escalated to Fingerprint hard ban.";
        } else { $_SESSION['admin_feedback'] = "Error: No fingerprint found to escalate."; }
    }
    
    // --- Deletion Logs ---
    if (isset($_POST['clear_all_deletion_logs'])) {
        $pdo->exec("TRUNCATE TABLE message_deletions");
        $_SESSION['admin_feedback'] = "All message deletion logs have been cleared.";
    }
    // --- Feedback Viewer Actions ---
    if (isset($_POST['source_section']) && $_POST['source_section'] === 'feedback-viewer') {
        $feedback_id = $_POST['feedback_id'] ?? 0;
        if ($feedback_id > 0) {
            if (isset($_POST['submit_feedback_reply'])) {
                $reply_content = trim($_POST['admin_reply_content'] ?? '');
                if (!empty($reply_content)) {
                    $pdo->prepare("UPDATE feedback SET admin_reply = ?, replied_by_user_id = ?, replied_at = NOW(), status = 'Reviewed' WHERE id = ?")
                        ->execute([$reply_content, $_SESSION['user_id'], $feedback_id]);
                    $_SESSION['admin_feedback'] = "Reply posted successfully.";
                }
            } elseif (isset($_POST['promote_to_poll'])) {
                $pdo->prepare("UPDATE feedback SET is_poll = 1 WHERE id = ?")->execute([$feedback_id]);
                $_SESSION['admin_feedback'] = "Feedback item has been promoted to a public poll.";
            }
        }
    }

    // --- Feedback ---
    if (isset($_POST['delete_selected_feedback'])) {
        $ids = array_map('intval', $_POST['feedback_ids'] ?? []);
        if (!empty($ids)) {
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $pdo->prepare("DELETE FROM feedback WHERE id IN ($placeholders)")->execute($ids);
            $_SESSION['admin_feedback'] = "Deleted " . count($ids) . " feedback entries.";
        }
    }

    // --- Banned Users Management ---
    if (isset($_POST['source_section']) && $_POST['source_section'] === 'banned-users') {
        if (isset($_POST['unban_user'])) {
            $user_id_to_unban = $_POST['user_id_to_unban'] ?? 0;
            if ($user_id_to_unban > 0) {
                $pdo->prepare("UPDATE users SET is_banned = 0 WHERE id = ?")->execute([$user_id_to_unban]);
                $_SESSION['admin_feedback'] = "User has been un-banned.";
            }
        } elseif (isset($_POST['bulk_unban'])) {
            $user_ids = array_map('intval', $_POST['selected_banned_users'] ?? []);
            if (!empty($user_ids)) {
                $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
                $stmt = $pdo->prepare("UPDATE users SET is_banned = 0 WHERE id IN ($placeholders)");
                $stmt->execute($user_ids);
                $_SESSION['admin_feedback'] = "Un-banned " . $stmt->rowCount() . " selected user(s).";
            } else {
                $_SESSION['admin_feedback'] = "No banned users were selected.";
            }
        }
    }

// --- Active User Management (Individual User Actions and Bulk Actions) ---
    if (isset($_POST['source_section']) && $_POST['source_section'] === 'user-management') {
        // Individual user actions (if a specific user_id is posted)
        if (isset($_POST['user_id'])) {
            $user_id = $_POST['user_id'];
            // Security check: ensure the target is not an admin, unless it's a self-edit.
            $stmt_check = $pdo->prepare("SELECT role, promoted_temp_pass FROM users WHERE id = ?");
            $stmt_check->execute([$user_id]);
            $user_data = $stmt_check->fetch(PDO::FETCH_ASSOC);
            $current_role = $user_data['role'] ?? 'user';
            $is_other_admin = (strtolower($current_role) === 'admin' && $_SESSION['user_id'] != $user_id);

            if (!$is_other_admin) {
                if (isset($_POST['update_user_details'])) {
                    $new_role = $_POST['new_role'] ?? 'user';
                    $custom_css = trim($_POST['custom_css'] ?? '');
                    $can_post_links = isset($_POST['can_post_links']) ? 1 : 0;
                    // Prevent self-demotion for admin role
                    $role_to_set = ($_SESSION['user_id'] == $user_id && strtolower($_SESSION['user_role']) === 'admin') ? 'admin' : $new_role;

                    // --- REVISED PROMOTION LOGIC ---
                    $role_hierarchy = ['user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];

                    // Check if the role is being upgraded for an existing member
                    if (($role_hierarchy[$role_to_set] > $role_hierarchy[$current_role])) {
                        // For a member-to-member promotion, we don't need a new password.
                        // We will store the NEW ROLE NAME in 'promoted_temp_pass' as a signal.
                        $promotion_signal = $role_to_set;
                        
                        $pdo->prepare("UPDATE users SET role = ?, custom_css = ?, can_post_links = ?, promoted_temp_pass = ? WHERE id = ?")
                            ->execute([$role_to_set, $custom_css, $can_post_links, $promotion_signal, $user_id]);
                        
                        $_SESSION['admin_feedback'] = "User has been promoted to " . ucfirst($role_to_set) . ". They will be notified on their next page refresh.";

                    } else {
                        // Regular update without a promotion
                        // It's also good practice to clear the promotion flag if they are demoted or their role is just edited.
                        $pdo->prepare("UPDATE users SET role = ?, custom_css = ?, can_post_links = ?, promoted_temp_pass = NULL WHERE id = ?")
                            ->execute([$role_to_set, $custom_css, $can_post_links, $user_id]);
                        $_SESSION['admin_feedback'] = "User details updated successfully.";
                    }
                    // --- END OF REVISED PROMOTION LOGIC ---

                } elseif (isset($_POST['change_username'])) {
                    $new_username = trim($_POST['new_username'] ?? '');
                    if (!empty($new_username)) {
                        try {
                            $pdo->prepare("UPDATE users SET username = ? WHERE id = ?")->execute([$new_username, $user_id]);
                            $_SESSION['admin_feedback'] = "Username changed successfully.";
                        } catch (PDOException $e) {
                            $_SESSION['admin_feedback'] = "Error: That username is already taken.";
                        }
                    } else {
                        $_SESSION['admin_feedback'] = "Error: New username cannot be empty.";
                    }
                } elseif (isset($_POST['manual_password_reset'])) {
                    $temp_pass = substr(str_shuffle('abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789'), 0, 10);
                    $password_hash = password_hash($temp_pass, PASSWORD_DEFAULT);
                    $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$password_hash, $user_id]);
                    $_SESSION['admin_feedback'] = "Password for user ID {$user_id} has been reset. New temp pass: " . htmlspecialchars($temp_pass);
                } elseif (isset($_POST['toggle_ban'])) {
                    $pdo->prepare("UPDATE users SET is_banned = NOT is_banned WHERE id = ?")->execute([$user_id]);
                    $_SESSION['admin_feedback'] = "Ban status toggled for user ID {$user_id}.";
                } elseif (isset($_POST['kick_user'])) {
                    $session_id_to_kick = $_POST['session_id'];
                    $pdo->prepare("UPDATE sessions SET kick_message = ? WHERE session_id = ?")->execute(["Kicked by administrator.", $session_id_to_kick]);
                    $_SESSION['admin_feedback'] = "User has been kicked from their active session.";
                }
            } else {
                $_SESSION['admin_feedback'] = "Error: Cannot perform actions on other administrators.";
            }
        }

        
        // Bulk actions for user-management section (if bulk_active_user_action is posted)
        elseif (isset($_POST['bulk_active_user_action'])) {
            $user_ids = $_POST['selected_users'] ?? [];
            $action = $_POST['bulk_active_user_action'];

            if (!empty($user_ids)) {
                $safe_user_ids = [];
                $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
                // Select only non-admin users, excluding the current admin user
                $stmt = $pdo->prepare("SELECT id FROM users WHERE id IN ($placeholders) AND role != 'admin' AND id != ?");
                $stmt->execute(array_merge($user_ids, [$_SESSION['user_id']]));
                $safe_user_ids = $stmt->fetchAll(PDO::FETCH_COLUMN);

                if (!empty($safe_user_ids)) {
                    $safe_placeholders = implode(',', array_fill(0, count($safe_user_ids), '?'));
                    $count = 0;
                    switch ($action) {
                        case 'deactivate':
                            $pdo->prepare("UPDATE users SET is_deactivated = 1 WHERE id IN ($safe_placeholders)")->execute($safe_user_ids);
                            $pdo->prepare("DELETE FROM sessions WHERE user_id IN ($safe_placeholders)")->execute($safe_user_ids); // End sessions
                            $count = count($safe_user_ids);
                            $_SESSION['admin_feedback'] = "Deactivated {$count} selected user(s) and ended their sessions.";
                            break; // Important break
                        case 'ban':
                            $pdo->prepare("UPDATE users SET is_banned = 1 WHERE id IN ($safe_placeholders)")->execute($safe_user_ids);
                            $pdo->prepare("UPDATE sessions SET kick_message = ? WHERE user_id IN ($safe_placeholders)")->execute(["Your account has been banned.", ...$safe_user_ids]); // Kick and inform
                            $count = count($safe_user_ids);
                            $_SESSION['admin_feedback'] = "Banned {$count} selected user(s).";
                            break; // Important break
                    }
                } else {
                    $_SESSION['admin_feedback'] = "No non-admin users were selected or allowed for the action. (Admins cannot be affected).";
                }
            } else {
                $_SESSION['admin_feedback'] = "No users were selected for bulk action.";
            }
        }
    }

    // --- Redirect to the section where the action was performed ---
    // This is the correct way to end the POST handling block
    header("Location: admin.php?section=" . urlencode($source_section));
    exit();
} // End of if ($_SERVER['REQUEST_METHOD'] === 'POST')

$settings = $pdo->query("SELECT * FROM settings")->fetchAll(PDO::FETCH_KEY_PAIR);
$csrf_token = htmlspecialchars($_SESSION['csrf_token']);

// You can create specific data-fetching blocks for each section to keep it clean
function get_section_data($pdo, $section_name, $search_term = '') {
    $data = [];
    switch ($section_name) {
        case 'new-members':
            $stmt = $pdo->query("SELECT u.id, u.username, u.created_at, u.last_login_ip, (SELECT COUNT(*) FROM messages WHERE user_id = u.id) as message_count FROM users u WHERE u.created_at >= NOW() - INTERVAL 7 DAY ORDER BY u.created_at DESC");
            $data['new_members'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            break;
        case 'user-management':
            $sql = "SELECT id, username, role FROM users WHERE is_banned = 0 AND is_deactivated = 0";
            $params = [];
            if (!empty($search_term)) { $sql .= " AND username LIKE ?"; $params[] = '%' . $search_term . '%'; }
            $sql .= " ORDER BY role, username ASC";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $data['users'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            break;
        // Add cases for all your other sections...
    }
    return $data;
}

$section_data = get_section_data($pdo, $current_section, $_GET['search'] ?? '');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel</title>
    <link rel="stylesheet" href="admin_style.css?v=20">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
</head>
<body class="admin-panel-layout">
    <div class="admin-container">
        <nav class="admin-nav">
            <div class="admin-header">
                <h1>Rot-Chat</h1>
            </div>
            <ul class="nav-menu">
                <?php foreach ($sections as $key => $title): ?>
                    <li>
                        <a href="?section=<?php echo $key; ?>" class="<?php if ($key === $current_section) echo 'active'; ?>">
                            <?php echo htmlspecialchars($title); ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </nav>

        <main class="admin-main">
            <?php 
            if (isset($_SESSION['admin_feedback'])) {
                echo '<div class="feedback-message success">' . nl2br(htmlspecialchars($_SESSION['admin_feedback'])) . '</div>';
                unset($_SESSION['admin_feedback']);
            }
            ?>


            
            <section id="core-config" class="admin-section <?php if ($current_section === 'core-config') echo 'active'; ?>">
                <h2><?php echo $sections['core-config']; ?></h2>
                <p>Adjust core functionality of the chat. Changes here may affect how new users and guests experience the site.</p>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="core-config">
                    <div class="form-group">
                        <label for="guest_default_tokens">Default Guest Message Tokens</label>
                        <input type="number" id="guest_default_tokens" name="guest_default_tokens" value="<?php echo htmlspecialchars($settings['guest_default_tokens'] ?? '50'); ?>" min="0">
                        <small>The number of messages a brand new guest can send when they first join.</small>
                    </div>
                    <hr>
                    <div class="form-group">
                        <label for="chat_history_limit">Chat History Limit</label>
                        <input type="number" id="chat_history_limit" name="chat_history_limit" value="<?php echo htmlspecialchars($settings['chat_history_limit'] ?? '150'); ?>" min="10">
                        <small>The number of recent messages to load in the chat window. Higher numbers may increase load times.</small>
                    </div>
                    <hr>
                    <div class="form-group">
                        <label for="kick_cooldown_minutes">Kick Cooldown (Minutes)</label>
                        <input type="number" id="kick_cooldown_minutes" name="kick_cooldown_minutes" value="<?php echo htmlspecialchars($settings['kick_cooldown_minutes'] ?? '5'); ?>" min="0">
                        <small>How long a user is temporarily blocked from rejoining after being kicked by a moderator.</small>
                    </div>
                    <button type="submit" name="update_core_settings" class="success-btn">Save Core Settings</button>
                </form>
            </section>

            <section id="moderation" class="admin-section <?php if ($current_section === 'moderation') echo 'active'; ?>">
                <h2><?php echo $sections['moderation']; ?></h2>
                <p>Configure filters to automatically block unwanted content and manage link posting privileges.</p>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="moderation">
                    <div class="form-group">
                        <label for="banned_words_list">Banned Words in Messages</label>
                        <textarea id="banned_words_list" name="banned_words_list" rows="3"><?php echo htmlspecialchars($settings['banned_words_list'] ?? ''); ?></textarea>
                        <small>Comma-separated. Users (not admins) who post messages containing these words will be automatically kicked.</small>
                    </div>
                    <hr>
                    <div class="form-group">
                        <label for="banned_name_words_list">Banned Words in Usernames</label>
                        <textarea id="banned_name_words_list" name="banned_name_words_list" rows="3"><?php echo htmlspecialchars($settings['banned_name_words_list'] ?? ''); ?></textarea>
                        <small>Comma-separated. Guests and new members will be blocked from registering if their name contains any of these words.</small>
                    </div>
                    <hr>
                    <div class="form-group">
                        <label for="forbidden_domains_list">Forbidden Domains in Links</label>
                        <textarea id="forbidden_domains_list" name="forbidden_domains_list" rows="3"><?php echo htmlspecialchars($settings['forbidden_domains'] ?? ''); ?></textarea>
                        <small>Comma-separated. Links from these domains will be blocked for all users (except admins). Do not include 'http://' or 'www'.</small>
                    </div>
                    <button type="submit" name="update_filters" class="success-btn">Save Moderation Filters</button>
                </form>
            </section>

<section id="upload-management" class="admin-section <?php if ($current_section === 'upload-management') echo 'active'; ?>">
                <h2><?php echo $sections['upload-management']; ?></h2>
                <p>Configure file upload rules, limits, and permissions for each file type.</p>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="upload-management">
                    
                    <h4>Image Gallery Permissions</h4>
                    <div class="form-group"><label>Min. Role to Upload Images</label><select name="upload_allowed_roles_images">
                        <option value="user" <?php if (($settings['upload_allowed_roles'] ?? 'user') === 'user') echo 'selected'; ?>>Member</option>
                        <option value="trusted" <?php if (($settings['upload_allowed_roles'] ?? 'user') === 'trusted') echo 'selected'; ?>>Trusted</option>
                        <option value="moderator" <?php if (($settings['upload_allowed_roles'] ?? 'user') === 'moderator') echo 'selected'; ?>>Moderator</option>
                        <option value="admin" <?php if (($settings['upload_allowed_roles'] ?? 'user') === 'admin') echo 'selected'; ?>>Admin</option>
                    </select></div>
                    <div class="form-group"><label>Min. Role to View Image Gallery</label><select name="view_allowed_roles_images">
                        <option value="guest" <?php if (($settings['view_allowed_roles_images'] ?? 'user') === 'guest') echo 'selected'; ?>>Guest</option>
                        <option value="user" <?php if (($settings['view_allowed_roles_images'] ?? 'user') === 'user') echo 'selected'; ?>>Member</option>
                        <option value="trusted" <?php if (($settings['view_allowed_roles_images'] ?? 'user') === 'trusted') echo 'selected'; ?>>Trusted</option>
                        <option value="moderator" <?php if (($settings['view_allowed_roles_images'] ?? 'user') === 'moderator') echo 'selected'; ?>>Moderator</option>
                        <option value="admin" <?php if (($settings['view_allowed_roles_images'] ?? 'user') === 'admin') echo 'selected'; ?>>Admin</option>
                    </select></div>
                    <hr>

                    <h4>Document (PDF) Permissions</h4>
                    <div class="form-group"><label>Min. Role to Upload Documents</label><select name="upload_allowed_roles_docs">
                         <option value="user" <?php if (($settings['upload_allowed_roles_docs'] ?? 'user') === 'user') echo 'selected'; ?>>Member</option>
                         <option value="trusted" <?php if (($settings['upload_allowed_roles_docs'] ?? 'user') === 'trusted') echo 'selected'; ?>>Trusted</option>
                         <option value="moderator" <?php if (($settings['upload_allowed_roles_docs'] ?? 'user') === 'moderator') echo 'selected'; ?>>Moderator</option>
                         <option value="admin" <?php if (($settings['upload_allowed_roles_docs'] ?? 'user') === 'admin') echo 'selected'; ?>>Admin</option>
                    </select></div>
                    <div class="form-group"><label>Min. Role to View Documents</label><select name="view_allowed_roles_docs">
                        <option value="guest" <?php if (($settings['view_allowed_roles_docs'] ?? 'user') === 'guest') echo 'selected'; ?>>Guest</option>
                        <option value="user" <?php if (($settings['view_allowed_roles_docs'] ?? 'user') === 'user') echo 'selected'; ?>>Member</option>
                        <option value="trusted" <?php if (($settings['view_allowed_roles_docs'] ?? 'user') === 'trusted') echo 'selected'; ?>>Trusted</option>
                        <option value="moderator" <?php if (($settings['view_allowed_roles_docs'] ?? 'user') === 'moderator') echo 'selected'; ?>>Moderator</option>
                        <option value="admin" <?php if (($settings['view_allowed_roles_docs'] ?? 'user') === 'admin') echo 'selected'; ?>>Admin</option>
                    </select></div>
                    <hr>

<h4>ZIP Archive Permissions</h4>
<div class="form-group"><label>Min. Role to Upload ZIPs</label><select name="upload_allowed_roles_zips">
     <option value="user" <?php if (($settings['upload_allowed_roles_zips'] ?? 'user') === 'user') echo 'selected'; ?>>Member</option>
     <option value="trusted" <?php if (($settings['upload_allowed_roles_zips'] ?? 'user') === 'trusted') echo 'selected'; ?>>Trusted</option>
     <option value="moderator" <?php if (($settings['upload_allowed_roles_zips'] ?? 'user') === 'moderator') echo 'selected'; ?>>Moderator</option>
     <option value="admin" <?php if (($settings['upload_allowed_roles_zips'] ?? 'user') === 'admin') echo 'selected'; ?>>Admin</option>
</select></div>
<div class="form-group"><label>Min. Role to View ZIPs</label><select name="view_allowed_roles_zips">
    <option value="guest" <?php if (($settings['view_allowed_roles_zips'] ?? 'user') === 'guest') echo 'selected'; ?>>Guest</option>
    <option value="user" <?php if (($settings['view_allowed_roles_zips'] ?? 'user') === 'user') echo 'selected'; ?>>Member</option>
    <option value="trusted" <?php if (($settings['view_allowed_roles_zips'] ?? 'user') === 'trusted') echo 'selected'; ?>>Trusted</option>
    <option value="moderator" <?php if (($settings['view_allowed_roles_zips'] ?? 'user') === 'moderator') echo 'selected'; ?>>Moderator</option>
    <option value="admin" <?php if (($settings['view_allowed_roles_zips'] ?? 'user') === 'admin') echo 'selected'; ?>>Admin</option>
</select></div>
<hr>

<h4>Audio (MP3) Permissions</h4>
<div class="form-group"><label>Min. Role to Upload Audio</label><select name="upload_allowed_roles_audio">
     <option value="user" <?php if (($settings['upload_allowed_roles_audio'] ?? 'trusted') === 'user') echo 'selected'; ?>>Member</option>
     <option value="trusted" <?php if (($settings['upload_allowed_roles_audio'] ?? 'trusted') === 'trusted') echo 'selected'; ?>>Trusted</option>
     <option value="moderator" <?php if (($settings['upload_allowed_roles_audio'] ?? 'trusted') === 'moderator') echo 'selected'; ?>>Moderator</option>
     <option value="admin" <?php if (($settings['upload_allowed_roles_audio'] ?? 'trusted') === 'admin') echo 'selected'; ?>>Admin</option>
</select></div>
<div class="form-group"><label>Min. Role to Play Audio</label><select name="view_allowed_roles_audio">
    <option value="guest" <?php if (($settings['view_allowed_roles_audio'] ?? 'user') === 'guest') echo 'selected'; ?>>Guest</option>
    <option value="user" <?php if (($settings['view_allowed_roles_audio'] ?? 'user') === 'user') echo 'selected'; ?>>Member</option>
    <option value="trusted" <?php if (($settings['view_allowed_roles_audio'] ?? 'user') === 'trusted') echo 'selected'; ?>>Trusted</option>
    <option value="moderator" <?php if (($settings['view_allowed_roles_audio'] ?? 'user') === 'moderator') echo 'selected'; ?>>Moderator</option>
    <option value="admin" <?php if (($settings['view_allowed_roles_audio'] ?? 'user') === 'admin') echo 'selected'; ?>>Admin</option>
</select></div>
<hr>
                    
                    <h4>Global Limits</h4>
                    <div class="form-group">
                        <label for="upload_limit_user">Daily Uploads for Members</label>
                        <input type="number" id="upload_limit_user" name="upload_limit_user" value="<?php echo htmlspecialchars($settings['upload_limit_user'] ?? '5'); ?>" min="0">
                    </div>
                     <div class="form-group">
                        <label for="upload_limit_trusted">Daily Uploads for Trusted</label>
                        <input type="number" id="upload_limit_trusted" name="upload_limit_trusted" value="<?php echo htmlspecialchars($settings['upload_limit_trusted'] ?? '20'); ?>" min="0">
                    </div>
                     <div class="form-group">
                        <label for="upload_limit_moderator">Daily Uploads for Moderators</label>
                        <input type="number" id="upload_limit_moderator" name="upload_limit_moderator" value="<?php echo htmlspecialchars($settings['upload_limit_moderator'] ?? '50'); ?>" min="0">
                    </div>
                    <div class="form-group">
                        <label for="allowed_file_types">Allowed File Extensions</label>
                        <input type="text" id="allowed_file_types" name="allowed_file_types" value="<?php echo htmlspecialchars($settings['allowed_file_types'] ?? 'jpg,jpeg,png,gif,mp4,webp,pdf,zip'); ?>">
                    </div>
                    <div class="form-group">
                        <label for="max_file_size_kb">Maximum File Size (in KB)</label>
                        <input type="number" id="max_file_size_kb" name="max_file_size_kb" value="<?php echo htmlspecialchars($settings['max_file_size_kb'] ?? '2048'); ?>" min="1">
                    </div>
                    <button type="submit" name="update_upload_settings">Save All Upload Settings</button>
                </form>
            </section>
            
            <section id="live-visuals" class="admin-section <?php if ($current_section === 'live-visuals') echo 'active'; ?>">
                 <h2><?php echo $sections['live-visuals']; ?></h2>
                <p>Control the solid border and the multi-color glow effect around the main chat container.</p>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="live-visuals">
                    <?php
                        preg_match_all('/#([a-fA-F0-9]{3,6})/i', $settings['chat_glow_color'] ?? '', $matches);
                        $found_colors = $matches[0];
                        $glow_color1 = $found_colors[0] ?? '#cc0000';
                        $glow_color2 = $found_colors[1] ?? '#ff00ff';
                        $glow_color3 = $found_colors[2] ?? '#00cc66';
                    ?>
                    <div class="form-group">
                        <label for="chat_border_color">Border Color (Solid)</label>
                        <input type="color" id="chat_border_color" name="chat_border_color" value="<?php echo htmlspecialchars($settings['chat_border_color'] ?? '#cc0000'); ?>">
                    </div>
                    <hr>
                    <div class="form-group">
                        <label for="glow_color_1">Glow Gradient Start (Top)</label>
                        <input type="color" id="glow_color_1" name="glow_color_1" value="<?php echo htmlspecialchars($glow_color1); ?>">
                    </div>
                    <div class="form-group">
                        <label for="glow_color_2">Glow Gradient Middle</label>
                        <input type="color" id="glow_color_2" name="glow_color_2" value="<?php echo htmlspecialchars($glow_color2); ?>">
                    </div>
                    <div class="form-group">
                        <label for="glow_color_3">Glow Gradient End (Bottom)</label>
                        <input type="color" id="glow_color_3" name="glow_color_3" value="<?php echo htmlspecialchars($glow_color3); ?>">
                    </div>
                    <hr>
                    <div class="form-group"><label for="title_animation">"Molten" Title Animation</label><select name="title_animation" id="title_animation">
                        <option value="1" <?php if (($settings['title_animation'] ?? '1') == '1') echo 'selected'; ?>>Enabled</option><option value="0" <?php if (($settings['title_animation'] ?? '1') == '0') echo 'selected'; ?>>Disabled</option></select></div>
                    <div class="form-group"><label for="special_effect">Page Load Effect</label><select name="special_effect" id="special_effect">
                        <option value="none" <?php if (($settings['special_effect'] ?? 'none') == 'none') echo 'selected'; ?>>None</option>
                        <option value="fade-to-black" <?php if (($settings['special_effect'] ?? 'none') == 'fade-to-black') echo 'selected'; ?>>Fade to Black</option>
                        <option value="glitch-classic" <?php if (($settings['special_effect'] ?? 'none') == 'glitch-classic') echo 'selected'; ?>>Classic Glitch</option>
                        <option value="glitch-burn" <?php if (($settings['special_effect'] ?? 'none') == 'glitch-burn') echo 'selected'; ?>>Color Burn Glitch</option>
                    </select></div>
                    <hr>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" name="default_enable_visual_effects" value="1" <?php if (($settings['default_enable_visual_effects'] ?? '1') == '1') echo 'checked'; ?>>
                            Enable Global Chat Visual Effects (Glow, Animations) by default
                        </label>
                    </div>
                    <button type="submit" name="update_visual_settings">Save Visual Settings</button>
                </form>
            </section>
            
<section id="site-wide-settings" class="admin-section <?php if ($current_section === 'site-wide-settings') echo 'active'; ?>">
                <h2><?php echo $sections['site-wide-settings']; ?></h2>
                <form action="admin.php?section=site-wide-settings" method="post" class="inline-form" style="margin-top:16px; display:grid; gap:10px; max-width:680px;">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

    <label><strong>Trusted Delete Mode</strong></label>
    <select name="trusted_delete_mode" id="trusted_delete_mode">
        <option value="own" <?php echo (($settings['trusted_delete_mode'] ?? 'own') === 'own') ? 'selected' : ''; ?>>Own Messages Only</option>
        <option value="all" <?php echo (($settings['trusted_delete_mode'] ?? 'own') === 'all') ? 'selected' : ''; ?>>Any Non-System Message</option>
    </select>

    <label for="known_roles"><strong>Known Roles (CSV)</strong></label>
    <input type="text" name="known_roles" id="known_roles" value="<?php echo htmlspecialchars($settings['known_roles'] ?? 'admin,moderator,supermod,trusted,member,guest', ENT_QUOTES, 'UTF-8'); ?>">

    <label for="roles_delete_any"><strong>Roles that can delete ANY non-system message (CSV)</strong></label>
    <input type="text" name="roles_delete_any" id="roles_delete_any" value="<?php echo htmlspecialchars($settings['roles_delete_any'] ?? 'admin,moderator,supermod', ENT_QUOTES, 'UTF-8'); ?>">

    <label for="roles_delete_own"><strong>Roles that can delete ONLY their own messages (CSV)</strong></label>
    <input type="text" name="roles_delete_own" id="roles_delete_own" value="<?php echo htmlspecialchars($settings['roles_delete_own'] ?? 'trusted,member', ENT_QUOTES, 'UTF-8'); ?>">

    <button type="submit" name="update_role_delete_config" class="btn">Save Role Settings</button>
</form>

                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="site-wide-settings">
                    <div class="form-group">
                        <label>Announcement Message</label>
                        <textarea name="announcement_message" rows="2"><?php echo htmlspecialchars($settings['announcement_message'] ?? ''); ?></textarea>
                    </div>
                    <div class="form-group">
                        <label>Show Announcement To</label>
                        <select name="announcement_level">
                            <option value="hidden" <?php if (($settings['announcement_level'] ?? '') == 'hidden') echo 'selected'; ?>>Hidden</option>
                            <option value="all" <?php if (($settings['announcement_level'] ?? '') == 'all') echo 'selected'; ?>>All Users</option>
                            <option value="members" <?php if (($settings['announcement_level'] ?? '') == 'members') echo 'selected'; ?>>Members & Above</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Show Join/Leave Messages For</label>
                        <select name="system_message_level">
                            <option value="all" <?php if (($settings['system_message_level'] ?? '') == 'all') echo 'selected'; ?>>Everyone</option>
                            <option value="members" <?php if (($settings['system_message_level'] ?? '') == 'members') echo 'selected'; ?>>Members & Above</option>
                            <option value="mods" <?php if (($settings['system_message_level'] ?? '') == 'mods') echo 'selected'; ?>>Mods & Above</option>
                            <option value="none" <?php if (($settings['system_message_level'] ?? '') == 'none') echo 'selected'; ?>>Nobody</option>
                        </select>
                    </div>
                    
                    <hr>
                    <div class="form-group">
                        <label for="site_rules">Site Rules (for Registration page)</label>
                        <textarea id="site_rules" name="site_rules" rows="6"><?php echo htmlspecialchars($settings['site_rules'] ?? ''); ?></textarea>
                        <small>This text will be displayed on the registration form. Users must agree to these rules to register.</small>
                    </div>
                    <hr>
                    <div class="form-group">
                        <label>Login Page Statistics</label>
                        <small>Choose which stats to display publicly on the login/guest join page.</small>
                        <label class="checkbox-label" style="margin-top:10px;"><input type="checkbox" name="stats_show_total_members" value="1" <?php if (($settings['stats_show_total_members'] ?? '1') == '1') echo 'checked'; ?>> Total Members</label>
                        <label class="checkbox-label"><input type="checkbox" name="stats_show_messages_today" value="1" <?php if (($settings['stats_show_messages_today'] ?? '1') == '1') echo 'checked'; ?>> Messages Today</label>
                        <label class="checkbox-label"><input type="checkbox" name="stats_show_online_total" value="1" <?php if (($settings['stats_show_online_total'] ?? '0') == '1') echo 'checked'; ?>> Currently Online (Total)</label>
                        <label class="checkbox-label"><input type="checkbox" name="stats_show_online_guests" value="1" <?php if (($settings['stats_show_online_guests'] ?? '0') == '1') echo 'checked'; ?>> Currently Online (Guests)</label>
                    </div>
<hr>
<div class="form-group">
    <label class="checkbox-label">
        <input type="checkbox" name="enable_login_captcha" value="1" <?php if (($settings['enable_login_captcha'] ?? '0') == '1') echo 'checked'; ?>>
        Enable Captcha on Login
    </label>
    <small>Requires `captcha.php` to be configured correctly. Applies to members and guests.</small>
</div>
<button type="submit" name="update_site_settings">Save Site Settings</button>
                </form>
                
            </section>

<section id="channel-management" class="admin-section <?php if ($current_section === 'channel-management') echo 'active'; ?>">
                <h2><?php echo $sections['channel-management']; ?></h2>
                <p>Create, edit, and delete chat channels.</p>
                
                <?php if (isset($_GET['edit_channel_id'])):
                    $stmt = $pdo->prepare("SELECT * FROM channels WHERE id = ?");
                    $stmt->execute([$_GET['edit_channel_id']]);
                    $channel_to_edit = $stmt->fetch();
                    if ($channel_to_edit):
                ?>
                <form action="admin.php" method="post" class="sub-section-form">
                    <h4>Editing: #<?php echo htmlspecialchars($channel_to_edit['name']); ?></h4>
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="channel-management"><input type="hidden" name="channel_id_to_update" value="<?php echo $channel_to_edit['id']; ?>">
                    <div class="form-group"><label>Topic</label><input type="text" name="updated_channel_topic" value="<?php echo htmlspecialchars($channel_to_edit['topic']); ?>"></div>
                    <div class="form-group"><label>Minimum Role</label><select name="updated_min_role" <?php if ($channel_to_edit['name'] === 'general') echo 'disabled'; ?>><option value="guest" <?php if($channel_to_edit['min_role']=='guest') echo 'selected';?>>Guest</option><option value="user" <?php if($channel_to_edit['min_role']=='user') echo 'selected';?>>Member</option><option value="trusted" <?php if($channel_to_edit['min_role']=='trusted') echo 'selected';?>>Trusted</option><option value="moderator" <?php if($channel_to_edit['min_role']=='moderator') echo 'selected';?>>Moderator</option><option value="admin" <?php if($channel_to_edit['min_role']=='admin') echo 'selected';?>>Admin</option></select></div>
                    <button type="submit" name="update_channel">Save Changes</button>
                    <a href="?section=channel-management" class="btn" style="background: #444;">Cancel</a>
                </form>
                <?php endif; else: ?>
                <form action="admin.php" method="post" class="sub-section-form">
                    <h4>Create New Channel</h4>
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="channel-management">
                    <div class="form-group"><label>Channel Name</label><input type="text" name="channel_name" required pattern="[a-zA-Z0-9_-]+"></div>
                    <div class="form-group"><label>Topic</label><input type="text" name="channel_topic"></div>
                    <div class="form-group"><label>Minimum Role</label><select name="min_role"><option value="guest">Guest</option><option value="user">Member</option><option value="trusted">Trusted</option><option value="moderator">Moderator</option><option value="admin">Admin</option></select></div>
                    <button type="submit" name="create_channel">Create</button>
                </form>
                <?php endif; ?>
                
                <hr>
                <h4>Existing Channels</h4>
                <div class="table-container">
                    <table class="user-management-table">
                        <thead><tr><th>Name</th><th>Topic</th><th>Access</th><th>Actions</th></tr></thead>
                        <tbody>
                        <?php foreach ($pdo->query("SELECT * FROM channels ORDER BY name ASC") as $channel): ?>
                            <tr>
                                <td><strong>#<?php echo htmlspecialchars($channel['name']); ?></strong></td><td><?php echo htmlspecialchars($channel['topic']); ?></td><td><?php echo htmlspecialchars(ucfirst($channel['min_role'])); ?></td>
                                <td style="display: flex; gap: 5px;">
                                    <a href="?section=channel-management&edit_channel_id=<?php echo $channel['id']; ?>" class="btn" style="padding: 5px 10px;">Edit</a>
                                    <?php if ($channel['name'] !== 'general'): ?><form action="admin.php" method="post"><input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="channel-management"><input type="hidden" name="channel_id" value="<?php echo $channel['id']; ?>"><button type="submit" name="delete_channel" class="danger-btn" style="padding: 5px 10px;">Delete</button></form><?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>
            
            <section id="chat-tools" class="admin-section <?php if ($current_section === 'chat-tools') echo 'active'; ?>">
                <h2><?php echo $sections['chat-tools']; ?></h2>
                 <?php
                    $lock_status = $settings['chat_locked'] ?? 'unlocked';
                    $lock_display = 'Unlocked';
                    if ($lock_status === 'guest') { $lock_display = 'Locked for Guests'; } elseif ($lock_status === 'user') { $lock_display = 'Locked for Members & Below'; } elseif ($lock_status === 'all') { $lock_display = 'Locked for All'; }
                    $reg_lock_status = $settings['registration_locked'] ?? '0';
                    $reg_lock_display = ($reg_lock_status === '1') ? 'Locked (Token Required)' : 'Open';
                ?>
                <p>Current Chat Lock Status: <strong><?php echo $lock_display; ?></strong><br>Current Registration Status: <strong><?php echo $reg_lock_display; ?></strong></p>
                <form action="admin.php" method="post" style="margin-bottom: 20px;">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="chat-tools">
                    <div class="form-group"><label for="chat_lock_level">Set Chat Lock Level</label><select id="chat_lock_level" name="chat_lock_level">
                        <option value="unlocked" <?php if ($lock_status == 'unlocked') echo 'selected'; ?>>Unlocked</option>
                        <option value="guest" <?php if ($lock_status == 'guest') echo 'selected'; ?>>Lock for Guests</option>
                        <option value="user" <?php if ($lock_status == 'user') echo 'selected'; ?>>Lock for Members & Below</option>
                        <option value="all" <?php if ($lock_status == 'all') echo 'selected'; ?>>Lock for All (Admins Exempt)</option>
                    </select></div>
                    <div class="form-group"><label for="registration_locked">Member Registration</label><select id="registration_locked" name="registration_locked">
                        <option value="0" <?php if ($reg_lock_status == '0') echo 'selected'; ?>>Open</option>
                        <option value="1" <?php if ($reg_lock_status == '1') echo 'selected'; ?>>Locked (Token Required)</option>
                    </select></div>
                    <button type="submit" name="update_lock_status">Update Lock Status</button>
                </form>
                <hr>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="chat-tools">
                    <div class="form-group"><label for="channel_to_clear">Clear Messages From Channel</label><select name="channel_to_clear" id="channel_to_clear">
                        <option value="all">!! ALL MESSAGES !!</option>
                        <?php $channels_for_tools_stmt = $pdo->query("SELECT name FROM channels ORDER BY name ASC");
                        foreach ($channels_for_tools_stmt->fetchAll(PDO::FETCH_COLUMN) as $channel_name): ?>
                        <option value="<?php echo htmlspecialchars($channel_name); ?>">#<?php echo htmlspecialchars($channel_name); ?></option>
                        <?php endforeach; ?>
                    </select></div><button type="submit" name="clear_chat" class="danger-btn">Clear Selected</button>
                </form>
                <hr>
                <h4>Admin Tools</h4>
                <p>Access special tools for site maintenance. Use with caution.</p>
                <div style="display: flex; gap: 15px;">
                     <a href="cleanup.php" class="btn danger-btn" target="_blank" style="flex: 1;">Expired File Cleanup</a>
                     <a href="emergency_clear_sessions.php" class="btn danger-btn" target="_blank" style="flex: 1;">Emergency Tools</a>
                </div>
            </section>
            
            <section id="session-management" class="admin-section <?php if ($current_section === 'session-management') echo 'active'; ?>">
                <h2><?php echo $sections['session-management']; ?></h2>
                <p>Manually clear all idle sessions (both guests and members) from the database.</p>
                <form action="admin.php" method="post" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="session-management">
                    <button type="submit" name="clear_idle_sessions" class="danger-btn">Clear All Idle Sessions</button>
                </form>
                <hr>
                <h3>Registration Token Management</h3>
                <p>When registration is locked, you can generate single-use tokens here.</p>
                <form action="admin.php" method="post" style="margin-bottom: 20px;">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="session-management">
                    <button type="submit" name="generate_token">Generate New Token</button>
                </form>
                <div class="table-container">
                    <table class="user-management-table">
                         <thead><tr><th>Unclaimed Registration Tokens</th><th>Created On</th></tr></thead>
                         <tbody>
                         <?php
                            $tokens_stmt = $pdo->query("SELECT registration_token, created_at FROM users WHERE password_hash IS NULL AND registration_token IS NOT NULL ORDER BY created_at DESC");
                            foreach ($tokens_stmt as $token_row):
                         ?>
                            <tr><td><input type="text" class="copyable-token-input" value="<?php echo htmlspecialchars($token_row['registration_token']); ?>" readonly></td><td><?php echo $token_row['created_at']; ?></td></tr>
                         <?php endforeach; if ($tokens_stmt->rowCount() === 0) echo '<tr><td colspan="2" style="text-align: center;">No unclaimed tokens found.</td></tr>'; ?>
                         </tbody>
                    </table>
                </div>
            </section>

<section id="game-management" class="admin-section <?php if ($current_section === 'game-management') echo 'active'; ?>">
                <h2><?php echo $sections['game-management']; ?></h2>
                <p>Review and clear active or waiting games.</p>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="game-management">
                    <div class="table-container">
                         <table class="user-management-table">
                            <thead><tr><th><input type="checkbox" onclick="this.closest('table').querySelectorAll('.game_checkbox').forEach(c=>c.checked=this.checked)"></th><th>Creator</th><th>Board Size</th><th>Status</th><th>Actions</th></tr></thead>
                            <tbody>
                            <?php
                                $games_query = "SELECT g.game_uuid, g.board_size, g.status, g.created_at, COALESCE(u.username, gu.username) as creator_name FROM games g JOIN game_players gp ON g.id = gp.game_id AND gp.player_number = 1 LEFT JOIN users u ON gp.user_id = u.id LEFT JOIN guests gu ON gp.guest_id = gu.id WHERE g.status IN ('waiting', 'active') ORDER BY g.created_at DESC";
                                foreach ($pdo->query($games_query) as $game):
                            ?>
                                <tr>
                                    <td><input type="checkbox" name="games_to_delete[]" value="<?php echo $game['game_uuid']; ?>" class="game_checkbox"></td>
                                    <td><strong><?php echo htmlspecialchars($game['creator_name'] ?? 'N/A'); ?></strong></td>
                                    <td><?php echo $game['board_size']; ?>x<?php echo $game['board_size']; ?></td>
                                    <td><?php echo htmlspecialchars(ucfirst($game['status'])); ?></td>
                                    <td><a href="lines.php?game=<?php echo $game['game_uuid']; ?>" class="btn" target="_blank" style="padding: 5px 10px;">Spectate</a></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                         </table>
                    </div>
                    <div class="table-footer">
                        <button type="submit" name="clear_completed_games" class="danger-btn">Clear All Completed Games</button>
                        <button type="submit" name="delete_selected_games" class="danger-btn">Delete Selected</button>
                    </div>
                </form>
            </section>

            <section id="new-members" class="admin-section <?php if ($current_section === 'new-members') echo 'active'; ?>">
                <h2><?php echo $sections['new-members']; ?></h2>
                <p>Review users who have registered in the last 7 days. Use the checkboxes for bulk actions.</p>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="new-members">
                    <div class="table-container">
                        <table class="user-management-table">
                            <thead><tr><th><input type="checkbox" onclick="this.closest('table').querySelectorAll('.new_member_checkbox').forEach(c => c.checked = this.checked)"></th><th>Username</th><th>Message Count</th><th>Joined On</th><th>Last Login IP</th></tr></thead>
                            <tbody>
                            <?php
                                $new_members_stmt = $pdo->query("SELECT u.id, u.username, u.created_at, u.last_login_ip, (SELECT COUNT(*) FROM messages WHERE user_id = u.id) as message_count FROM users u WHERE u.created_at >= NOW() - INTERVAL 7 DAY ORDER BY u.created_at DESC");
                                $new_members = $new_members_stmt->fetchAll(PDO::FETCH_ASSOC);
                                if (empty($new_members)):
                            ?>
                                <tr><td colspan="5" style="text-align: center;">No new members in the last 7 days.</td></tr>
                            <?php else: foreach ($new_members as $member): ?>
                                <tr>
                                    <td><input type="checkbox" name="new_members_to_manage[]" value="<?php echo $member['id']; ?>" class="new_member_checkbox"></td>
                                    <td><a href="?section=user-management&view_user=<?php echo $member['id']; ?>"><?php echo htmlspecialchars($member['username']); ?></a></td>
                                    <td><?php echo $member['message_count']; ?></td>
                                    <td><?php echo date('Y-m-d H:i', strtotime($member['created_at'])); ?></td>
                                    <td><?php echo htmlspecialchars($member['last_login_ip'] ?? 'N/A'); ?></td>
                                </tr>
                            <?php endforeach; endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if (!empty($new_members)): ?>
                    <div class="table-footer">
                        <button type="submit" name="bulk_new_member_action" value="deactivate" class="danger-btn">Deactivate Selected</button>
                        <button type="submit" name="bulk_new_member_action" value="ban" class="nuke-btn">Ban Selected</button>
                    </div>
                    <?php endif; ?>
                </form>
            </section>


<section id="online-users" class="admin-section <?php if ($current_section === 'online-users') echo 'active'; ?>">
    <h2><?php echo $sections['online-users']; ?></h2>
    <p>Manage all users currently online. "Session FP" is the unique ID for a guest's login. "Browser ID" can be shared by multiple users (e.g., on Tor).</p>
    <form action="admin.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="source_section" value="online-users">
        <div class="table-container">
            <table class="user-management-table">
                <thead>
                    <tr>
                        <th><input type="checkbox" onclick="this.closest('table').querySelectorAll('.online_user_checkbox').forEach(c=>c.checked=this.checked)"></th>
                        <th>Username</th>
                        <th>Type</th>
                        <th>Session FP</th>
                        <th>Browser ID</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                        $online_users_stmt = $pdo->query("SELECT s.session_id, s.username, s.is_guest, s.user_id, s.guest_id, s.status, s.is_shadow_kicked, u.role as user_role, g.fingerprint FROM sessions s LEFT JOIN users u ON s.user_id = u.id LEFT JOIN guests g ON s.guest_id = g.id ORDER BY s.is_guest, u.role, s.username");
                        foreach($online_users_stmt as $online_user):
                            $is_other_admin = !$online_user['is_guest'] && strtolower($online_user['user_role'] ?? '') === 'admin' && $_SESSION['user_id'] != $online_user['user_id'];
                    ?>
                    <tr>
                        <td>
                            <?php if (!$is_other_admin): ?>
                            <input type="checkbox" name="online_users[]" value="<?php echo $online_user['session_id']; ?>" class="online_user_checkbox">
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if (!$online_user['is_guest'] && !$is_other_admin): ?>
                                <a href="admin.php?section=user-management&view_user=<?php echo $online_user['user_id']; ?>"><?php echo htmlspecialchars($online_user['username']); ?></a>
                            <?php else: ?>
                                <?php echo htmlspecialchars($online_user['username']); ?>
                            <?php endif; ?>
                        </td>
                        <td><?php echo $online_user['is_guest'] ? 'Guest' : 'Member'; ?></td>
                        <td><?php echo htmlspecialchars($online_user['guest_id'] ?? 'N/A'); ?></td>
                        <td style="word-break: break-all; font-size: 0.9em;"><?php echo htmlspecialchars($online_user['fingerprint'] ?? 'N/A'); ?></td>
                        <td>
                            <?php echo $online_user['is_shadow_kicked'] ? '<span style="color:#ff9999;">Ghosted</span>' : htmlspecialchars(ucfirst($online_user['status'])); ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="table-footer">
            <select name="bulk_online_action" style="width: auto;">
                <option value="">Bulk Actions...</option>
                <option value="kick">Kick Selected</option>
                <option value="ghost">Ghost Selected</option>
                <option value="unghost">Unghost Selected</option>
                <option value="deactivate">Deactivate Selected (Members)</option>
                <option value="ban">Ban Selected (Members)</option>
            </select>
            <button type="submit" name="bulk_online_action_submit" class="danger-btn" onclick="return confirm('Are you sure you want to apply this bulk action to the selected users?');">Apply</button>
        </div>
    </form>
</section>
<section id="guest-management" class="admin-section <?php if ($current_section === 'guest-management') echo 'active'; ?>">
    <h2><?php echo $sections['guest-management']; ?></h2>
    <h4>Historical Guest Data</h4>
    <p>Manage individual guest login sessions. Deleting a guest removes their messages. You can ban or delete multiple sessions at once.</p>
    
    <form action="admin.php" method="get" class="inline-form" style="margin-bottom: 20px;">
        <input type="hidden" name="section" value="guest-management">
        <input type="text" name="guest_search" placeholder="Search by Name, IP, or Fingerprint..." value="<?php echo htmlspecialchars($_GET['guest_search'] ?? ''); ?>" style="width: 250px;">
        <button type="submit" class="btn" style="padding: 8px 12px;">Search</button>
        <?php if (!empty($_GET['guest_search'])): ?>
            <a href="?section=guest-management" class="btn" style="background: #444;">Clear</a>
        <?php endif; ?>
    </form>
    
    <form action="admin.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="source_section" value="guest-management">
        <div class="table-container">
            <table class="user-management-table">
                <thead>
                    <tr>
                        <th>Select</th>
                        <th>Username</th>
                        <th>Session FP</th>
                        <th>Browser ID</th>
                        <th>Last IP</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                        $guest_search_sql = "SELECT id, username, fingerprint, last_login_ip FROM guests";
                        $params = [];
                        if (!empty($_GET['guest_search'])) {
                            $guest_search_sql .= " WHERE username LIKE ? OR fingerprint LIKE ? OR last_login_ip LIKE ?";
                            $searchTerm = '%' . htmlspecialchars($_GET['guest_search']) . '%';
                            $params = [$searchTerm, $searchTerm, $searchTerm];
                        }
                        $guest_search_sql .= " ORDER BY id DESC";
                        $guest_stmt = $pdo->prepare($guest_search_sql);
                        $guest_stmt->execute($params);
                        foreach($guest_stmt as $guest):
                    ?>
                    <tr>
                        <td><input type="checkbox" name="guests_to_delete[]" value="<?php echo $guest['id']; ?>"></td>
                        <td><?php echo htmlspecialchars($guest['username']); ?></td>
                        <td><?php echo htmlspecialchars($guest['id']); ?></td>
                        <td style="word-break: break-all; font-size: 0.9em;"><?php echo htmlspecialchars($guest['fingerprint'] ?? ''); ?></td>
                        <td><?php echo htmlspecialchars($guest['last_login_ip'] ?? 'N/A'); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="table-footer">
            <button type="submit" name="ban_selected_guests" class="nuke-btn" onclick="return confirm('This will PERMANENTLY BAN the selected guest usernames and DELETE their records. This cannot be undone. Are you sure?');">Ban Selected</button>
            <button type="submit" name="delete_selected_guests" class="danger-btn">Delete Selected</button>
        </div>
    </form>
</section>



<section id="guest-ban-management" class="admin-section <?php if ($current_section === 'guest-ban-management') echo 'active'; ?>">
    <h2><?php echo $sections['guest-ban-management']; ?></h2>
    <p>Manage temporary kick cooldowns and permanent bans for specific guest usernames.</p>

    <h4>Permanent Username Ban</h4>
    <p>Permanently prevent a specific username from being used by any guest. This will also kick the user if they are currently online.</p>
    <form action="admin.php" method="post" class="sub-section-form">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="source_section" value="guest-ban-management">
        <div class="form-group"><label>Username to Ban</label><input type="text" name="username_to_ban" required></div>
        <div class="form-group"><label>Reason (Optional, for logs)</label><input type="text" name="ban_reason"></div>
        <button type="submit" name="add_guest_name_ban" class="danger-btn">Ban Username Permanently</button>
    </form>
    <hr>
    
    <h4>Permanent Username Bans</h4>
    <div class="table-container">
        <table class="user-management-table">
            <thead><tr><th>Banned Username</th><th>Reason</th><th>Banned By</th><th>Actions</th></tr></thead>
            <tbody>
            <?php
                $perm_ban_query = "SELECT bgn.id, bgn.username, bgn.reason, u.username as banned_by_username FROM banned_guest_names bgn JOIN users u ON bgn.banned_by_user_id = u.id ORDER BY bgn.username ASC";
                foreach($pdo->query($perm_ban_query) as $perm_ban):
            ?>
                <tr>
                    <td><?php echo htmlspecialchars($perm_ban['username']); ?></td>
                    <td><?php echo htmlspecialchars($perm_ban['reason'] ?? 'N/A'); ?></td>
                    <td><?php echo htmlspecialchars($perm_ban['banned_by_username']); ?></td>
                    <td>
                        <form action="admin.php" method="post" class="inline-form" style="margin:0;"><input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="guest-ban-management"><input type="hidden" name="perm_ban_id" value="<?php echo $perm_ban['id']; ?>"><button type="submit" name="unban_perm_guest_name" class="btn">Remove</button></form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</section>
<section id="active-cooldowns" class="admin-section <?php if ($current_section === 'active-cooldowns') echo 'active'; ?>">
    <h2><?php echo $sections['active-cooldowns']; ?></h2>
    <p>This list shows all browser fingerprints that are on a temporary cooldown from being kicked. Cooldowns are removed automatically when they expire, or you can remove them manually.</p>
    <div class="table-container">
        <table class="user-management-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Fingerprint/IP Value</th>
                    <th>Reason</th>
                    <th>Cooldown Expires</th>
                    <th style="text-align: right;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php
                    // Fetch all temporary bans from the main ban_list table
                    $cooldowns_stmt = $pdo->query("SELECT id, ban_type, ban_value, reason, banned_until FROM ban_list WHERE banned_until IS NOT NULL AND banned_until > NOW() ORDER BY banned_until ASC");
                    foreach ($cooldowns_stmt as $row) {
                        echo "<tr>
                                <td>" . htmlspecialchars(ucfirst($row['ban_type'])) . "</td>
                                <td title='" . htmlspecialchars($row['ban_value']) . "'>" . htmlspecialchars(substr($row['ban_value'], 0, 24)) . "...</td>
                                <td>" . htmlspecialchars($row['reason']) . "</td>
                                <td>" . htmlspecialchars($row['banned_until']) . "</td>
                                <td style='text-align: right;'>
                                    <form method='post' action='admin.php' class='inline-form'>
                                        <input type='hidden' name='csrf_token' value='{$csrf_token}'>
                                        <input type='hidden' name='source_section' value='ban-management'>
                                        <input type='hidden' name='ban_id' value='{$row['id']}'>
                                        <button type='submit' name='unban_hard' class='btn'>Remove</button>
                                    </form>
                                </td>
                              </tr>";
                    }
                ?>
            </tbody>
        </table>
    </div>
</section>
<section id="user-management" class="admin-section <?php if ($current_section === 'user-management') echo 'active'; ?>">
    <h2>Registered Users Management</h2>

    <?php
    $view_user_id = $_GET['view_user'] ?? null;
    if ($view_user_id && ctype_digit($view_user_id)):
        // --- INDIVIDUAL USER MANAGEMENT VIEW ---
        $stmt = $pdo->prepare("SELECT u.*, (SELECT COUNT(*) FROM messages WHERE user_id = u.id) as message_count FROM users u WHERE u.id = ?");
        $stmt->execute([$view_user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user):
            $session_stmt = $pdo->prepare("SELECT session_id FROM sessions WHERE user_id = ? AND is_guest = 0");
            $session_stmt->execute([$view_user_id]);
            $is_online = (bool)($user_session_id = $session_stmt->fetchColumn());
            $is_self = ($_SESSION['user_id'] == $user['id']);
            $is_other_admin = (strtolower($user['role']) === 'admin' && !$is_self);
    ?>
        <h3>Managing: <?php echo htmlspecialchars($user['username']); ?> <a href="?section=user-management" style="font-size: 0.7em; vertical-align: middle;">(Back to List)</a></h3>
        <p>
            <strong>Role:</strong> <?php echo htmlspecialchars(ucfirst($user['role'])); ?> |
            <strong>Status:</strong> <?php echo $user['is_banned'] ? '<span style="color: #f77;">Banned</span>' : ($user['is_deactivated'] ? '<span style="color: #f90;">Deactivated</span>' : 'Active'); ?> |
            <strong>Online:</strong> <?php echo $is_online ? '<span style="color:#7f7;">Yes</span>' : "No"; ?> |
            <strong>Messages:</strong> <?php echo htmlspecialchars($user['message_count']); ?>
        </p>

        <?php if (!$is_other_admin): ?>
            <div class="individual-user-forms">
                <form action="admin.php" method="post" class="sub-section-form">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="user-management">
                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                    <h4>Role & Permissions</h4>
                    <div class="form-group">
                        <label>Role</label>
                        <select name="new_role" <?php if ($is_self && strtolower($_SESSION['user_role']) === 'admin') echo 'disabled'; ?>>
                            <option value="user" <?php if (strtolower($user['role']) == 'user') echo 'selected'; ?>>Member</option>
                            <option value="trusted" <?php if (strtolower($user['role']) == 'trusted') echo 'selected'; ?>>Trusted</option>
                            <option value="moderator" <?php if (strtolower($user['role']) == 'moderator') echo 'selected'; ?>>Moderator</option>
                            <?php if (strtolower($_SESSION['user_role']) === 'admin'): ?><option value="admin" <?php if (strtolower($user['role']) == 'admin') echo 'selected'; ?>>Admin</option><?php endif; ?>
                        </select>
                    </div>
                    <div class="form-group">
    <label>Custom Username CSS</label>
    <input type="text" name="custom_css" value="<?php echo htmlspecialchars($user['custom_css'] ?? ''); ?>" placeholder="class: username-aurora; color: #aaddff;">
    <small>
        Use `class:` to apply a special effect. You can add other CSS styles after it, separated by a semicolon.<br>
        <b>Gentle Effects:</b> `username-aurora`, `username-breathing-glow`, `username-slow-fade`, `username-spotlight-sweep`, `username-matrix-flow`<br>
        <b>Intense Effects:</b> `username-molten-core`, `username-static-shock`, `username-rainbow-wave`, `username-flame-glow`, `username-glitch-flicker`
    </small>
</div>
                    <div class="form-group"><label class="checkbox-label"><input type="checkbox" name="can_post_links" value="1" <?php if ($user['can_post_links']) echo 'checked'; ?>> Allow user to post links</label></div>
                    <button type="submit" name="update_user_details">Save Details</button>
                </form>

                <form action="admin.php" method="post" class="sub-section-form">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="user-management">
                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                    <h4>Change Username</h4>
                    <div class="form-group"><input type="text" name="new_username" required placeholder="Enter new username..."></div>
                    <button type="submit" name="change_username">Change Username</button>
                </form>

                <div class="sub-section-form">
                    <h4>Actions</h4>
                    <div class="log-actions">
                        <form action="admin.php" method="post" class="inline-form"><input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="user-management"><input type="hidden" name="user_id" value="<?php echo $user['id']; ?>"><button type="submit" name="manual_password_reset" class="danger-btn">Force Password Reset</button></form>
                        <form action="admin.php" method="post" class="inline-form"><input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="user-management"><input type="hidden" name="user_id" value="<?php echo $user['id']; ?>"><button type="submit" name="toggle_ban" class="danger-btn"><?php echo $user['is_banned'] ? 'Unban' : 'Ban'; ?></button></form>
                    </div>
                    <?php if ($is_online): ?>
                    <form action="admin.php" method="post" class="kick-form" style="margin-top: 15px; flex-direction: column; align-items: stretch;">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="source_section" value="user-management">
                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                        <input type="hidden" name="session_id" value="<?php echo $user_session_id; ?>">
                        <div class="form-group" style="display: flex; gap: 10px; margin-bottom: 0;">
                            <input type="number" name="kick_cooldown_minutes" placeholder="Cooldown (Mins)" style="flex-basis: 120px; flex-grow: 0;">
                            <button type="submit" name="kick_user" class="danger-btn" style="flex-grow: 1;">Kick Session</button>
                        </div>
                    </form>
                    <?php endif; ?>
                </div>
            </div>
        <?php else: ?>
            <p><em>No actions available for other administrators.</em></p>
        <?php endif; ?>
    <?php else: ?>
        <p class="error-message">User not found.</p>
    <?php endif; ?>

    <?php else: ?>
    <p>Manage all active (non-banned, non-deactivated) members. Use checkboxes for bulk actions.</p>

    <form action="admin.php" method="get" class="inline-form" style="margin-bottom: 20px;">
        <input type="hidden" name="section" value="user-management">
        <input type="text" name="user_search" placeholder="Search by username..." value="<?php echo htmlspecialchars($_GET['user_search'] ?? ''); ?>" style="width: 250px;">
        <button type="submit" class="btn" style="padding: 8px 12px;">Search</button>
        <?php if (!empty($_GET['user_search'])): ?>
            <a href="?section=user-management" class="btn" style="background: #444;">Clear</a>
        <?php endif; ?>
    </form>

    <form action="admin.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="source_section" value="user-management">
        <div class="table-container">
            <table class="user-management-table">
                <thead>
                    <tr>
                        <th><input type="checkbox" onclick="this.closest('table').querySelectorAll('.user_checkbox').forEach(c=>c.checked=this.checked)"></th>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Msg Count</th>
                        <th>Joined On</th>
                        <th>Last IP</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                        $search_sql = "SELECT id, username, role, message_count, created_at, last_login_ip FROM users WHERE is_banned = 0 AND is_deactivated = 0";
                        $search_params = [];
                        if (!empty($_GET['user_search'])) {
                            $search_sql .= " AND username LIKE ?";
                            $search_params[] = '%' . htmlspecialchars($_GET['user_search']) . '%';
                        }
                        $search_sql .= " ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'moderator' THEN 2 WHEN 'trusted' THEN 3 WHEN 'user' THEN 4 ELSE 5 END, username ASC";
                        $users_stmt = $pdo->prepare($search_sql);
                        $users_stmt->execute($search_params);
                        foreach($users_stmt as $user):
                    ?>
                    <tr>
                        <td><input type="checkbox" name="selected_users[]" value="<?php echo $user['id']; ?>" class="user_checkbox"></td>
                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                        <td><?php echo htmlspecialchars(ucfirst($user['role'])); ?></td>
                        <td><?php echo htmlspecialchars($user['message_count']); ?></td>
                        <td><?php echo date('Y-m-d', strtotime($user['created_at'])); ?></td>
                        <td><?php echo htmlspecialchars($user['last_login_ip'] ?? 'N/A'); ?></td>
                        <td style="text-align: right;">
                             <a href="admin.php?section=user-management&view_user=<?php echo $user['id']; ?>" class="btn" style="padding: 5px 10px;">Manage</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="table-footer">
            <select name="bulk_active_user_action" style="width: auto;">
                <option value="">Bulk Actions...</option>
                <option value="deactivate">Deactivate Selected</option>
                <option value="ban">Ban Selected</option>
            </select>
            <button type="submit" class="danger-btn" onclick="return confirm('Are you sure you want to apply this bulk action?');">Apply</button>
        </div>
    </form>
    <?php endif; ?>
</section>
<section id="banned-users" class="admin-section <?php if ($current_section === 'banned-users') echo 'active'; ?>">
    <h2><?php echo $sections['banned-users']; ?></h2>
    <p>Manage all member accounts that are currently banned. Banned users cannot log in.</p>

    <form action="admin.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="source_section" value="banned-users">
        <div class="table-container">
            <table class="user-management-table">
                <thead>
                    <tr>
                        <th><input type="checkbox" onclick="this.closest('table').querySelectorAll('.banned_user_checkbox').forEach(c=>c.checked=this.checked)"></th>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Last IP</th>
                        <th style="text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                        $banned_stmt = $pdo->query("SELECT id, username, role, last_login_ip FROM users WHERE is_banned = 1 ORDER BY username ASC");
                        foreach ($banned_stmt as $b_user):
                    ?>
                    <tr>
                        <td><input type="checkbox" name="selected_banned_users[]" value="<?php echo $b_user['id']; ?>" class="banned_user_checkbox"></td>
                        <td><?php echo htmlspecialchars($b_user['username']); ?></td>
                        <td><?php echo htmlspecialchars(ucfirst($b_user['role'])); ?></td>
                        <td><?php echo htmlspecialchars($b_user['last_login_ip'] ?? 'N/A'); ?></td>
                        <td style="text-align: right;">
                             <form action="admin.php" method="post" class="inline-form" style="margin:0;">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="source_section" value="banned-users">
                                <input type="hidden" name="user_id_to_unban" value="<?php echo $b_user['id']; ?>">
                                <button type="submit" name="unban_user" class="btn">Un-Ban</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="table-footer">
            <button type="submit" name="bulk_unban" class="btn" onclick="return confirm('Are you sure you want to un-ban the selected users?');">Un-Ban Selected</button>
        </div>
    </form>
</section>
<section id="deactivated-users" class="admin-section <?php if ($current_section === 'deactivated-users') echo 'active'; ?>">
                <h2><?php echo $sections['deactivated-users']; ?></h2>
                <p>Search for deactivated accounts to reactivate or permanently delete.</p>
                
                <form action="admin.php" method="get" class="inline-form" style="margin-bottom: 20px;">
                    <input type="hidden" name="section" value="deactivated-users">
                    <input type="text" name="deactivated_search" placeholder="Search Deactivated..." value="<?php echo htmlspecialchars($_GET['deactivated_search'] ?? ''); ?>" style="width: 250px;">
                    <button type="submit" class="btn" style="padding: 8px 12px;">Search</button>
                    <?php if (!empty($_GET['deactivated_search'])): ?>
                        <a href="?section=deactivated-users" class="btn" style="background: #444;">Clear</a>
                    <?php endif; ?>
                </form>

                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="deactivated-users">
                    <div class="table-container">
                        <table class="user-management-table">
                            <thead><tr><th><input type="checkbox" onclick="this.closest('table').querySelectorAll('.deactivated_checkbox').forEach(c=>c.checked=this.checked)"></th><th>Username</th><th>Role</th><th>Last IP</th></tr></thead>
                            <tbody>
                                <?php
                                    $deactivated_sql = "SELECT id, username, role, last_login_ip FROM users WHERE is_deactivated = 1";
                                    $deactivated_params = [];
                                    if (!empty($_GET['deactivated_search'])) {
                                        $deactivated_sql .= " AND username LIKE ?";
                                        $deactivated_params[] = '%' . htmlspecialchars($_GET['deactivated_search']) . '%';
                                    }
                                    $deactivated_sql .= " ORDER BY username ASC";
                                    $deactivated_stmt = $pdo->prepare($deactivated_sql);
                                    $deactivated_stmt->execute($deactivated_params);
                                    foreach ($deactivated_stmt as $d_user):
                                ?>
                                <tr>
                                    <td><input type="checkbox" name="deactivated_users_to_manage[]" value="<?php echo $d_user['id']; ?>" class="deactivated_checkbox"></td>
                                    <td><?php echo htmlspecialchars($d_user['username']); ?></td>
                                    <td><?php echo htmlspecialchars(ucfirst($d_user['role'])); ?></td>
                                    <td><?php echo htmlspecialchars($d_user['last_login_ip'] ?? 'N/A'); ?></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <div class="table-footer">
                        <button type="submit" name="reactivate_selected_users" class="btn">Reactivate Selected</button>
                        <button type="submit" name="delete_selected_users_perm" class="danger-btn nuke-btn" onclick="return confirm('PERMANENTLY DELETE selected users and all their data? This cannot be undone.')">Delete Selected Permanently</button>
                    </div>
                </form>
            </section>

<section id="ban-management" class="admin-section <?php if ($current_section === 'ban-management') echo 'active'; ?>">
                <h2><?php echo $sections['ban-management']; ?></h2>
                <p>Manage all permanent and temporary (cooldown) bans based on IP address or browser fingerprint.</p>
                
                <h4>Manually Add Ban</h4>
                <form action="admin.php" method="post" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="ban-management">
                    <select name="ban_type"><option value="fingerprint">Fingerprint</option><option value="ip">IP Address</option></select>
                    <input type="text" name="ban_value" placeholder="Value to ban..." required>
                    <input type="text" name="reason" placeholder="Reason (optional)...">
                    <button type="submit" name="add_hard_ban" class="danger-btn">Add Ban</button>
                </form>
                <hr>

                <h4>Active Bans (Permanent & Temporary)</h4>
                 <div class="table-container">
                    <table class="user-management-table">
                        <thead><tr><th>Type</th><th>Value</th><th>Reason</th><th>Banned By</th><th>Expires</th><th>Actions</th></tr></thead>
                        <tbody>
                        <?php
                            $hard_ban_query = "SELECT bl.id, bl.ban_type, bl.ban_value, bl.reason, bl.banned_until, u.username as banned_by FROM ban_list bl LEFT JOIN users u ON bl.banned_by_user_id = u.id ORDER BY bl.banned_until DESC, bl.created_at DESC";
                            foreach ($pdo->query($hard_ban_query) as $ban):
                        ?>
                            <tr>
                                <td><?php echo htmlspecialchars(ucfirst($ban['ban_type'])); ?></td>
                                <td title="<?php echo htmlspecialchars($ban['ban_value']); ?>"><?php echo htmlspecialchars(substr($ban['ban_value'], 0, 24)); ?>...</td>
                                <td><?php echo htmlspecialchars($ban['reason'] ?? 'N/A'); ?></td>
                                <td><?php echo htmlspecialchars($ban['banned_by'] ?? 'System'); ?></td>
                                <td>
                                    <?php if ($ban['banned_until'] && strtotime($ban['banned_until']) > time()): ?>
                                        <span style="color: #ffaa55;"><?php echo $ban['banned_until']; ?></span>
                                    <?php else: ?>
                                        <span style="color: #ff5555;">Permanent</span>
                                    <?php endif; ?>
                                </td>
                                <td><form action="admin.php" method="post" class="inline-form"><input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input type="hidden" name="source_section" value="ban-management"><input type="hidden" name="ban_id" value="<?php echo $ban['id']; ?>"><button type="submit" name="unban_hard" class="btn">Remove</button></form></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>

            <section id="kick-logs" class="admin-section <?php if ($current_section === 'kick-logs') echo 'active'; ?>">
                <h2><?php echo $sections['kick-logs']; ?></h2>
                <p>Review kick actions performed by moderators. Click on an entry to expand and view details including captured chat history.</p>
                <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="kick-logs">
                    <button type="submit" name="clear_all_kick_logs" class="danger-btn">Clear All Kick Logs</button>
                </form>
                <br>
                <?php
                    $kick_logs_stmt = $pdo->query("SELECT * FROM kick_logs ORDER BY created_at DESC LIMIT 100");
                    foreach ($kick_logs_stmt as $log):
                ?>
                <details class="kick-log-entry">
                    <summary class="kick-log-summary">
                        <div>Kicked: <strong><?php echo htmlspecialchars($log['kicked_username']); ?></strong> by <strong><?php echo htmlspecialchars($log['moderator_username']); ?></strong></div>
                        <small><?php echo $log['created_at']; ?></small>
                    </summary>
                    <div class="kick-log-details">
                        <h4>Log Details</h4>
                        <p><strong>Reason:</strong> <?php echo htmlspecialchars($log['kick_reason']); ?></p>
                        <p><strong>User IP:</strong> <?php echo htmlspecialchars($log['kicked_user_ip'] ?? 'N/A'); ?></p>
                        <h4>Captured Chat History</h4>
                        <div class="chat-history-box">
                            <?php
                            $history = json_decode($log['chat_history'], true);
                            if (is_array($history) && !empty($history)) {
                                foreach (array_reverse($history) as $msg) {
                                    echo "<div><small>[{$msg['created_at']}]</small> <strong>{$msg['username']}:</strong> {$msg['message']}</div>";
                                }
                            } else { echo "No chat history captured."; }
                            ?>
                        </div>
                    </div>
                </details>
                <?php endforeach; ?>
            </section>

            <section id="deletion-logs" class="admin-section <?php if ($current_section === 'deletion-logs') echo 'active'; ?>">
    <h2><?php echo $sections['deletion-logs']; ?></h2>
<form action="admin.php" method="post" style="margin-bottom: 20px;">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="source_section" value="deletion-logs">
        <button type="submit" name="clear_all_deletion_logs" class="danger-btn" onclick="return confirm('Are you sure you want to permanently delete all message deletion logs? This cannot be undone.')">
            Clear All Deletion Logs
        </button>
    </form>
    <?php
    // AUTH: only admins and moderators can view
    $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
    if (!in_array($actor_role, ['admin','moderator'], true)) {
        echo "<p class='notice'>You don’t have permission to view deletion logs.</p>";
    } else {
        try {
            // Ensure the table exists
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS message_deletions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    message_id INT NOT NULL,
                    original_user_id INT NULL,
                    original_guest_id INT NULL,
                    original_username VARCHAR(255) NULL,
                    original_message TEXT NULL,
                    original_created_at DATETIME NULL,
                    deleted_by_user_id INT NULL,
                    deleted_by_username VARCHAR(255) NULL,
                    deleted_by_role VARCHAR(32) NULL,
                    deleted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            ");

            $stmt = $pdo->query("
                SELECT id, message_id, original_user_id, original_guest_id, original_username,
                       LEFT(COALESCE(original_message,''), 500) AS original_message,
                       original_created_at, deleted_by_user_id, deleted_by_username, deleted_by_role, deleted_at
                FROM message_deletions
                ORDER BY deleted_at DESC
                LIMIT 200
            ");
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (!$rows) {
                echo "<p class='muted'>No deletions have been logged yet.</p>";
            } else {
                echo '<div class="table-scroll"><table class="admin-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Msg ID</th>
                                <th>Original User</th>
                                <th>Original Guest</th>
                                <th>Original Username</th>
                                <th>Snippet</th>
                                <th>Msg Created</th>
                                <th>Deleted By</th>
                                <th>Role</th>
                                <th>Deleted At</th>
                            </tr>
                        </thead>
                        <tbody>';
                foreach ($rows as $r) {
                    $origUser   = is_null($r['original_user_id']) ? '-' : (int)$r['original_user_id'];
                    $origGuest  = is_null($r['original_guest_id']) ? '-' : (int)$r['original_guest_id'];
                    $origName   = htmlspecialchars($r['original_username'] ?? '-', ENT_QUOTES, 'UTF-8');
                    $snippet    = htmlspecialchars($r['original_message'] ?? '', ENT_QUOTES, 'UTF-8');
                    $msgCreated = htmlspecialchars($r['original_created_at'] ?? '-', ENT_QUOTES, 'UTF-8');
                    $deleter    = is_null($r['deleted_by_user_id']) ? ($r['deleted_by_username'] ?? '-') : ((int)$r['deleted_by_user_id'] . ' / ' . htmlspecialchars($r['deleted_by_username'] ?? '-', ENT_QUOTES, 'UTF-8'));
                    $role       = htmlspecialchars($r['deleted_by_role'] ?? '-', ENT_QUOTES, 'UTF-8');
                    $deletedAt  = htmlspecialchars($r['deleted_at'] ?? '-', ENT_QUOTES, 'UTF-8');

                    echo '<tr>
                        <td>'.(int)$r['id'].'</td>
                        <td>'.(int)$r['message_id'].'</td>
                        <td>'.$origUser.'</td>
                        <td>'.$origGuest.'</td>
                        <td>'.$origName.'</td>
                        <td style="max-width:420px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">'.$snippet.'</td>
                        <td>'.$msgCreated.'</td>
                        <td>'.$deleter.'</td>
                        <td>'.$role.'</td>
                        <td>'.$deletedAt.'</td>
                    </tr>';
                }
                echo '</tbody></table></div>';
            }
        } catch (Throwable $e) {
            error_log('Deletion log render error: '.$e->getMessage());
            echo "<p class='error'>Failed to load deletion logs.</p>";
        }
    }
    ?>
</section>


<section id="feedback-viewer" class="admin-section <?php if ($current_section === 'feedback-viewer') echo 'active'; ?>">
                <h2><?php echo $sections['feedback-viewer']; ?></h2>
                <p>Review user suggestions and bug reports. Deleting an entry also removes it from the polls page.</p>
                 <form action="admin.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="source_section" value="feedback-viewer">
                    <div class="table-container">
                        <table class="user-management-table">
                            <thead><tr><th><input type="checkbox" onclick="this.closest('table').querySelectorAll('.feedback_checkbox').forEach(c => c.checked = this.checked)"></th><th>Subject</th><th>Submitter</th><th>Type</th><th>Date</th></tr></thead>
                            <tbody>
                            <?php
                                $feedback_stmt = $pdo->query("SELECT * FROM feedback ORDER BY created_at DESC");
                                foreach($feedback_stmt as $item):
                            ?>
                                <tr>
                                    <td><input type="checkbox" name="feedback_ids[]" value="<?php echo $item['id']; ?>" class="feedback_checkbox"></td>
                                    <td><a href="?section=feedback-viewer&view_feedback=<?php echo $item['id']; ?>"><?php echo htmlspecialchars($item['subject']); ?></a></td>
                                    <td><?php echo htmlspecialchars($item['submitter_id']); ?></td>
                                    <td><?php echo htmlspecialchars($item['submission_type']); ?></td>
                                    <td><?php echo $item['created_at']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <div class="table-footer">
                        <button type="submit" name="delete_selected_feedback" class="danger-btn">Delete Selected</button>
                    </div>
                 </form>
                 
                <?php if (isset($_GET['view_feedback'])):
                    $feedback_id = $_GET['view_feedback'];
                    $stmt = $pdo->prepare("SELECT f.*, u.username as admin_username FROM feedback f LEFT JOIN users u ON f.replied_by_user_id = u.id WHERE f.id = ?");
                    $stmt->execute([$feedback_id]);
                    if($item = $stmt->fetch(PDO::FETCH_ASSOC)):
                ?>
                <hr>
                <h3>Viewing Feedback: "<?php echo htmlspecialchars($item['subject']); ?>"</h3>
                <div class="kick-log-details">
                    <p><strong>Content:</strong></p>
                    <div class="chat-history-box"><?php echo nl2br(htmlspecialchars($item['content'])); ?></div>
                    
                    <?php if (!empty($item['admin_reply'])): ?>
                        <h4 style="margin-top: 20px;">Your Reply (by <?php echo htmlspecialchars($item['admin_username'] ?? 'Admin'); ?>):</h4>
                        <div class="chat-history-box" style="background: #003300; border-color: #006600;">
                            <?php echo nl2br(htmlspecialchars($item['admin_reply'])); ?>
                        </div>
                    <?php endif; ?>

                    <form action="admin.php" method="post" class="sub-section-form" style="margin-top: 20px;">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="source_section" value="feedback-viewer">
                        <input type="hidden" name="feedback_id" value="<?php echo $item['id']; ?>">
                        <h4><?php echo empty($item['admin_reply']) ? 'Post a Reply' : 'Update Your Reply'; ?></h4>
                        <div class="form-group">
                            <textarea name="admin_reply_content" rows="4" required><?php echo htmlspecialchars($item['admin_reply'] ?? ''); ?></textarea>
                        </div>
                        <button type="submit" name="submit_feedback_reply">Submit Reply</button>
                        <?php if ($item['is_poll'] == 0): // Only show button if not already a poll ?>
                            <button type="submit" name="promote_to_poll" class="btn" style="background: #004d4d; color: #c2ffff; border-color: #009999; margin-left: 10px;">Promote to Poll</button>
                        <?php endif; ?>
                    </form>
                </div>
                <?php endif; endif; ?>
            </section>

            <section id="archived-messages" class="admin-section <?php if ($current_section === 'archived-messages') echo 'active'; ?>">
                <h2><?php echo $sections['archived-messages'] ?? 'Archived Messages'; ?></h2>
                <p>Review messages that were archived by moderators.</p>
                 <div class="table-container">
                    <table class="user-management-table">
                        <thead><tr><th>Archived At</th><th>Original Poster</th><th>Message</th><th>Channel</th><th>Archived By</th><th>Reason</th></tr></thead>
                        <tbody>
                        <?php
                            $archived_messages_stmt = $pdo->query("SELECT am.*, u.username as archiver_name FROM archived_messages am JOIN users u ON am.archived_by_user_id = u.id ORDER BY am.archived_at DESC LIMIT 100");
                            foreach ($archived_messages_stmt as $msg):
                        ?>
                            <tr>
                                <td><?php echo $msg['archived_at']; ?></td>
                                <td><?php echo htmlspecialchars($msg['username']); ?></td>
                                <td style="word-break: break-all;"><?php echo htmlspecialchars($msg['message']); ?></td>
                                <td>#<?php echo htmlspecialchars($msg['channel']); ?></td>
                                <td><?php echo htmlspecialchars($msg['archiver_name']); ?></td>
                                <td><?php echo htmlspecialchars($msg['archive_reason']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>

            </main>
    </div>
</body>
</html>