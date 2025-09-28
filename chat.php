<?php
// SEC-FIX: Prevent Path Info attacks and incorrect relative paths.
// This MUST be the very first thing in the file before any output.
if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '.php/') !== false) {
    // This URL is invalid. Redirect to the correct script name to prevent exploits.
    // FINAL FIX: Use the SCRIPT_NAME server variable for a guaranteed correct path.
    header('Location: ' . $_SERVER['SCRIPT_NAME'], true, 301);
    exit;
}

session_start();

// --- NEW: Prevent Browser Caching ---
// This forces the browser to always fetch a fresh copy of the page,
// ensuring the server correctly decides whether to show the chat or the login form.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 26 Jul 1997 05:00:00 GMT'); // A date in the past


// --- CRITICAL INCLUDES AND CONFIGS ---
require_once 'config.php';
require_once 'functions.php'; // Moved here to be available for fingerprinting
// --- PRE-EMPTIVE BAN CHECK ---
// This block runs before any HTML is rendered to immediately stop banned users.
try {
    $pdo_ban_check = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo_ban_check->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Only check for bans if the user does not have an active, valid session.
    if (!isset($_SESSION['session_id'])) {
        $fingerprint = $_COOKIE['rotchat_fp'] ?? null;
        if ($fingerprint) {
            $ban_check_stmt = $pdo_ban_check->prepare("SELECT reason, banned_until FROM ban_list WHERE ban_type = 'fingerprint' AND ban_value = ?");
            $ban_check_stmt->execute([$fingerprint]);
            if ($ban_info = $ban_check_stmt->fetch(PDO::FETCH_ASSOC)) {
                if (!empty($ban_info['banned_until']) && strtotime($ban_info['banned_until']) > time()) {
                    $remaining_seconds = strtotime($ban_info['banned_until']) - time();
                    render_ban_page("You are on a cooldown. Please wait " . ceil($remaining_seconds / 60) . " more minute(s).");
                } elseif (empty($ban_info['banned_until'])) {
                    render_ban_page("Your device has been permanently banned. Reason: " . htmlspecialchars($ban_info['reason']));
                }
            }
        }
    }
} catch (PDOException $e) {
    // If the database is down, it's better to show a generic error than a broken page.
    die("Critical error: Could not perform security checks.");
}
// --- NEW: Server-Side Unique ID Generation ---
// Check if the unique ID cookie exists.
if (!isset($_COOKIE['rotchat_fp'])) {
    // If it doesn't exist, generate a new, cryptographically secure random ID.
    // This guarantees every new browser/user gets a unique identifier.
    $fingerprint = bin2hex(random_bytes(32)); // 64-character hex string
    
    // Set the cookie to last for 10 years, making it persistent.
    setcookie('rotchat_fp', $fingerprint, time() + (10 * 365 * 24 * 60 * 60), "/", "", false, true);
    
    // Make the new fingerprint immediately available to the rest of the script on this page load.
    $_COOKIE['rotchat_fp'] = $fingerprint;
}


// 1) ENSURE a CSRF token is in the session
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
// 2) PULL it into a local variable for your templates
$csrf_token = $_SESSION['csrf_token'];

// ── CHANNEL SWITCHER: catch clicks on ?switch_channel=1&channel=… ──
if (isset($_GET['switch_channel']) && isset($_GET['channel'])) {
    if (!isset($_GET['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_GET['csrf_token'])) {
        render_csrf_error_page();
    }

    // sanitize channel name and switch
    $_SESSION['current_channel'] = preg_replace(
        '/[^a-zA-Z0-9_-]/',
        '',
        $_GET['channel']
    );

    // bounce back into chat.php so the new channel is loaded
    header('Location: chat.php');
    exit;
}


// --- NEW: Security Headers ---
// A strict Content Security Policy (CSP) is a major defense against XSS attacks.
// This policy allows images, styles, and fonts from the same origin ('self') and one specific external domain for textures.
header("Content-Security-Policy: default-src 'self'; img-src 'self'  data: http://img.amoebafxkcbzjy66ypl2tsy53y2kfngffiesb4dy33mv5ixcgyu7zcqd.onion; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; frame-ancestors 'self';");
// Prevents the browser from trying to guess ('sniff') the MIME type of a file.
header("X-Content-Type-Options: nosniff");
// Prevents the page from being loaded in an iframe on other domains (mitigates clickjacking).
header("X-Frame-Options: SAMEORIGIN");
// Controls how much referrer information is sent.
header("Referrer-Policy: strict-origin-when-cross-origin");
date_default_timezone_set('UTC');
/**
 * Renders a full-page "You have been kicked" message.
 * This function should ONLY be called when chat.php is the top-level document.
 * @param string $reason The reason for the kick.
 */
function render_kick_page($reason) {
    // Explicitly set headers to prevent caching and ensure HTML content type
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: Sat, 26 Jul 1997 05:00:00 GMT'); // A date in the past

    // Securely destroy the session
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();

    

    // Start output buffering specifically for this page, then flush explicitly.
    ob_start();
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Session Terminated</title>
        <style>
            html, body {
                height: 100%;
                margin: 0;
                padding: 0;
                overflow: hidden;
                background-color: #111; /* Dark background */
                color: #e0e0e0; /* Light text for visibility */
                font-family: 'Roboto', sans-serif; /* Consistent font */
                display: flex;
                justify-content: center;
                align-items: center;
                text-align: center;
                background-image: url(''); /* Add background texture for consistency */
                box-sizing: border-box;
            }
            .kick-box {
                padding: 30px;
                background-color: rgba(0,0,0,0.7); /* Slightly transparent dark box */
                border: 2px solid #cc0000; /* Red border */
                border-radius: 8px;
                box-shadow: 0 0 25px rgba(204,0,0,0.8); /* Stronger red glow */
                max-width: 400px;
                width: 90%; /* Responsive width */
            }
            h2 {
                color: #ff3333; /* Bright red heading */
                font-family: 'Courier Prime', monospace; /* Specific font for heading */
                margin-top: 0;
                margin-bottom: 20px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            p {
                background-color: #4d0000; /* Darker red background for message */
                color: #ffc2c2; /* Lighter red text */
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #990000;
                font-size: 1.1em;
                line-height: 1.4;
                word-wrap: break-word; /* Ensure long reasons wrap */
            }
            a {
                color: #ff8888; /* Link color */
                text-decoration: none;
                font-weight: bold;
                display: inline-block; /* Make it a block for padding/margin */
                margin-top: 25px;
                padding: 10px 20px;
                background-color: #333;
                border: 1px solid #555;
                border-radius: 5px;
                transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease;
            }
            a:hover {
                background-color: #555;
                border-color: #ff5555;
                color: #fff;
            }
        </style>
    </head>
    <body>
        <div class="kick-box">
            <h2>SESSION TERMINATED</h2>
            <p><?php echo htmlspecialchars($reason); ?></p>
            <a href="chat.php" target="_top">Return to Login</a>
        </div>
    </body>
    </html>
    <?php
    $final_output = ob_get_clean(); // Get the buffered content
    echo $final_output; // Output it
    flush(); // Attempt to force sending of data
    if (function_exists('fastcgi_finish_request')) { // For PHP-FPM environments
        fastcgi_finish_request();
    }
    die(); // Forceful exit
}

/**
 * Renders a full-page "You have been promoted" message with a temporary password.
 * This function logs the user out and forces them to re-login as a member.
 * @param string $temp_password The temporary password to display.
 */
function render_promotion_page($temp_password) {
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

    // Securely destroy the session
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();

    ob_start();
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Account Promoted!</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="chat-container">
             <div class="auth-container">
                <div class="auth-form" style="border-color: #00cc66; box-shadow: 0 0 25px rgba(0, 204, 102, 0.7);">
                    <h2 style="color: #33ff99;">Account Promoted!</h2>
                    <p style="background-color:#004d26; color:#c2ffc2; border-color:#00994d;">
                        Congratulations! An administrator has promoted your guest account to a full member.
                    </p>
                    <p style="background-color:#004d26; color:#c2ffc2; border-color:#00994d;">
                        Your temporary password is: <br>
                        <strong style="font-size: 1.4em; color: #fff; letter-spacing: 2px;"><?php echo htmlspecialchars($temp_password); ?></strong>
                    </p>
                    <p style="background-color:#004d26; color:#c2ffc2; border-color:#00994d;">
                        Please log in as a member. It is highly recommended that you change your password in the Profile & Settings panel.
                    </p>
                    <a href="chat.php" style="background-color:#006633; border-color:#00994d; color: #c2ffc2;">Proceed to Login</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
    echo ob_get_clean();
    die();
}


// --- DB Connection and Critical Checks (Happens before any output) ---
require_once 'config.php';
require_once 'functions.php';

// --- (FIXED) Establish the main PDO connection early ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // Use this main connection for all subsequent checks
    $pdo_check = $pdo; 
} catch (PDOException $e) {
    die("Critical error: Could not connect to the database: " . $e->getMessage());
}


try {
    // --- Smart Kick/Ban Check (Revised for consistency) ---
    $kicked_info = null; // Variable to hold kick reason if kicked
    if (isset($_SESSION['session_id'])) {
        // This check now ONLY reads the kick message. It does NOT destroy the session here.
        // The session is destroyed later when the main kick page is rendered.
        // This ensures all iframes consistently see the kick status before the session is gone.
        $kick_check_stmt = $pdo_check->prepare("SELECT kick_message FROM sessions WHERE session_id = ? AND kick_message IS NOT NULL");
        $kick_check_stmt->execute([$_SESSION['session_id']]);
        $kick_reason = $kick_check_stmt->fetchColumn(); // fetchColumn returns the value or false

        if ($kick_reason) {
            $kicked_info = $kick_reason; // Set the info for all views to use
        }
    }

} catch (PDOException $e) {
    // Since the main connection is already established, this is unlikely to fail, but good practice.
    die("Critical error: Could not perform session checks.");
}
// --- Production-Safe Error Logging ---
// NEVER display errors in a live environment.
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Define a writable path for the error log file.
// IMPORTANT: This file should be placed outside of your public web root directory if possible.
// For this example, we'll place it one level above the current script's directory.
$log_file_path = __DIR__ . '/../php_error.log'; 
ini_set('error_log', $log_file_path);

// You can still report all errors for logging purposes.
error_reporting(E_ALL);



// --- NEW: Check for Promotion ---
// --- NEW: Check for Promotion (Banner Method) ---
try {
    if (isset($_SESSION['session_id']) && ($_SESSION['is_guest'] ?? false)) {
        $promo_check_stmt = $pdo_check->prepare("SELECT promoted_temp_pass FROM sessions WHERE session_id = ?");
        $promo_check_stmt->execute([$_SESSION['session_id']]);
        if ($temp_pass = $promo_check_stmt->fetchColumn()) {
            // Set session variable for the banner to display
            $_SESSION['promotion_details'] = ['temp_pass' => $temp_pass];
            // Clear the flag from the database so this check doesn't run again
            $pdo_check->prepare("UPDATE sessions SET promoted_temp_pass = NULL WHERE session_id = ?")->execute([$_SESSION['session_id']]);
        }
    }
} catch (PDOException $e) {
    // Ignore
}

// The database connection variables are now included from config.php
// --- REVISED: Promotion Check for Guests and Members ---
try {
    // Guest Promotion Check (from Session)
    if (isset($_SESSION['session_id']) && ($_SESSION['is_guest'] ?? false)) {
        $promo_check_stmt = $pdo_check->prepare("SELECT promoted_temp_pass FROM sessions WHERE session_id = ?");
        $promo_check_stmt->execute([$_SESSION['session_id']]);
        if ($temp_pass = $promo_check_stmt->fetchColumn()) {
            $_SESSION['promotion_details'] = ['temp_pass' => $temp_pass];
            $pdo_check->prepare("UPDATE sessions SET promoted_temp_pass = NULL WHERE session_id = ?")->execute([$_SESSION['session_id']]);
        }
    }
    // Member Promotion Check (from User record)
    elseif (isset($_SESSION['user_id'])) {
        $promo_check_stmt = $pdo_check->prepare("SELECT promoted_temp_pass FROM users WHERE id = ?");
        $promo_check_stmt->execute([$_SESSION['user_id']]);
        if ($new_role_name = $promo_check_stmt->fetchColumn()) {
            // Check if it's a role name (our signal) and not a password hash
            if (in_array($new_role_name, ['trusted', 'moderator', 'admin'])) {
                $_SESSION['promotion_details'] = ['new_role' => $new_role_name];
                // IMPORTANT: Refresh the user's role in the current session
                $_SESSION['user_role'] = $new_role_name; 
                // Clear the promotion signal from the database
                $pdo_check->prepare("UPDATE users SET promoted_temp_pass = NULL WHERE id = ?")->execute([$_SESSION['user_id']]);
            }
        }
    }
} catch (PDOException $e) {
    // Ignore any errors here, not critical if it fails
}

// The database connection variables are now included from config.php

// --- General Configuration ---
$refresh_rate = 5; // This is a user-specific setting, so it remains here. The global timeouts are in config.php


// --- Channel Configuration (NOW DYNAMIC) ---
$channels = [];
try {
    $stmt = $pdo->query("SELECT name, topic, min_role FROM channels ORDER BY name ASC");
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $channels[$row['name']] = [
            'display' => '#' . $row['name'],
            'topic' => $row['topic'],
            'min_role' => $row['min_role']
        ];
    }
} catch (PDOException $e) {
    // Fallback to a minimal channel list if the DB query fails
    $channels = ['general' => ['display' => '#general', 'topic' => 'General Chat', 'min_role' => 'guest']];
}
$role_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];


function getRandomColor() { return sprintf('#%02X%02X%02X', mt_rand(100, 240), mt_rand(100, 240), mt_rand(100, 240)); }
function hexToRgba($hex, $alpha = 0.2) {

    $hex = str_replace('#', '', $hex);
    if (strlen($hex) == 3) {
        $r = hexdec(substr($hex, 0, 1) . substr($hex, 0, 1));
        $g = hexdec(substr($hex, 1, 1) . substr($hex, 1, 1));
        $b = hexdec(substr($hex, 2, 1) . substr($hex, 2, 1));
    } else {
        $r = hexdec(substr($hex, 0, 2));
        $g = hexdec(substr($hex, 2, 2));
        $b = hexdec(substr($hex, 4, 2));
    }
    return "rgba($r, $g, $b, $alpha)";
}
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// --- NEW: Delete Expired Messages ---
// This runs on every page load, ensuring expired messages are removed.
try {
    $pdo->exec("DELETE FROM messages WHERE delete_at IS NOT NULL AND delete_at < NOW()");
} catch (PDOException $e) {
    // It's not critical if this fails, so we don't need to die.
    // You could log the error here if you have a logging system.
}


// --- CSRF Token Generation ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Pre-load settings and role hierarchy for use in the header ---
$settings_stmt = $pdo->query("SELECT setting_key, setting_value FROM settings");
$settings = $settings_stmt->fetchAll(PDO::FETCH_KEY_PAIR);
$role_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];

// Fetch upload-related settings and user's current uploads
$upload_allowed_role = $settings['upload_allowed_roles'] ?? 'admin';
$limit_user = (int)($settings['upload_limit_user'] ?? 5);
$limit_trusted = (int)($settings['upload_limit_trusted'] ?? 20);
$limit_moderator = (int)($settings['upload_limit_moderator'] ?? 50);

$user_role = strtolower($_SESSION['user_role'] ?? 'guest');
$current_user_id = (int)($_SESSION['user_id'] ?? 0);

$uploads_today = 0;
$daily_limit = 0;
$remaining_uploads = 'N/A';
$upload_message = '';

if ($user_role === 'admin') {
    $upload_message = "Admins have unlimited uploads.";
} elseif ($user_role === 'moderator') {
    $daily_limit = $limit_moderator;
} elseif ($user_role === 'trusted') {
    $daily_limit = $limit_trusted;
} elseif ($user_role === 'user') {
    $daily_limit = $limit_user;
}

if ($daily_limit > 0 && $current_user_id > 0) {
    $stmt_count = $pdo->prepare(
        "SELECT COUNT(*) FROM uploads WHERE user_id = ? AND created_at >= NOW() - INTERVAL 1 DAY"
    );
    $stmt_count->execute([$current_user_id]);
    $uploads_today = $stmt_count->fetchColumn();
    $remaining_uploads = $daily_limit - $uploads_today;
    $upload_message = "You have {$remaining_uploads} / {$daily_limit} uploads remaining today.";
} elseif ($daily_limit === 0 && $user_role !== 'admin') {
    $upload_message = "Your role has no daily upload limit.";
}

// Get the current view early for the kick check
$view = $_GET['view'] ?? 'main';


// --- GET Request Action Handlers ---
if (isset($_GET['action']) && $_GET['action'] === 'toggle_offline_list') {
    // Initialize the session variable if it doesn't exist
    if (!isset($_SESSION['offline_list_collapsed'])) {
        $_SESSION['offline_list_collapsed'] = false;
    }
    // Flip the boolean value
    $_SESSION['offline_list_collapsed'] = !$_SESSION['offline_list_collapsed'];
    
    // Redirect back to the chatters view to remove the action from the URL
    header('Location: ?view=chatters');
    exit;
}




// --- POST Request Handlers ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        render_csrf_error_page();
    }

// --- NEW: Handle Token Generation from Profile Panel ---
    if (isset($_POST['generate_token_from_profile'])) {
        $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
        if ($actor_role === 'admin' || $actor_role === 'moderator') {
            $token = bin2hex(random_bytes(16));
            $placeholder_username = 'unclaimed_' . bin2hex(random_bytes(4));
            $user_color = sprintf('#%02X%02X%02X', mt_rand(100, 240), mt_rand(100, 240), mt_rand(100, 240));
            try {
                $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, registration_token, role, color) VALUES (?, NULL, ?, 'user', ?)");
                $stmt->execute([$placeholder_username, $token, $user_color]);
                // Use a newline character \n for the session message
                $_SESSION['profile_feedback'] = ['type' => 'success', 'message' => "New Token:\n" . htmlspecialchars($token)];
            } catch (PDOException $e) {
                $_SESSION['profile_feedback'] = ['type' => 'error', 'message' => 'Error: Could not generate token.'];
            }
        }
        // Redirect back to the profile view to show the new token
        header("Location: ?view=profile");
        exit();
    }

// --- MODERATOR: Promote Guest to Member Handler ---
    if (isset($_POST['promote_guest'])) {
        // This action can be performed by moderators or admins
        $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
        if ($actor_role === 'admin' || $actor_role === 'moderator') {
            $guest_id = $_POST['guest_id_to_promote'] ?? null;
            $session_id = $_POST['session_id_to_promote'] ?? null;

            if ($guest_id && $session_id) {
                $pdo->beginTransaction();
                try {
                    // 1. Get guest data
                    $stmt = $pdo->prepare("SELECT * FROM guests WHERE id = ?");
                    $stmt->execute([$guest_id]);
                    if (!($guest = $stmt->fetch(PDO::FETCH_ASSOC))) {
                        throw new Exception("Guest not found.");
                    }

                    // 2. Check if username is already in users table
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                    $stmt->execute([$guest['username']]);
                    if ($stmt->fetch()) {
                        throw new Exception("A member with this username already exists.");
                    }

                    // 3. Generate a simple, random temporary password
                    $adjectives = ['Red', 'Blue', 'Green', 'Quick', 'Happy', 'Bright', 'Silent', 'Wise'];
                    $nouns = ['Fox', 'Wolf', 'Bear', 'Tree', 'River', 'Stone', 'Star', 'Moon'];
                    $temp_pass = $adjectives[array_rand($adjectives)] . $nouns[array_rand($nouns)] . rand(10, 99);
                    $password_hash = password_hash($temp_pass, PASSWORD_DEFAULT);

                    // 4. Create new user record
                    $sql = "INSERT INTO users (username, password_hash, color, show_login_msgs, show_system_msgs, refresh_rate, role) 
                            VALUES (?, ?, ?, ?, ?, ?, 'user')";
                    $pdo->prepare($sql)->execute([
                        $guest['username'], $password_hash, $guest['color'],
                        $guest['show_login_msgs'], $guest['show_system_msgs'], $guest['refresh_rate']
                    ]);
                    
                    // 5. Flag the user's session with the temporary password for the notification banner
                    $pdo->prepare("UPDATE sessions SET promoted_temp_pass = ? WHERE session_id = ?")
                        ->execute([$temp_pass, $session_id]);
                    
                    // STEP 6 IS REMOVED. DO NOT DELETE THE GUEST RECORD HERE.
                    
                    $pdo->commit();
                    $_SESSION['moderation_feedback'] = "Guest '".htmlspecialchars($guest['username'])."' promoted! They will be notified on their next action.";

                } catch (Exception $e) {
                    $pdo->rollBack();
                    $_SESSION['moderation_feedback'] = "Error promoting guest: " . $e->getMessage();
                }
            }
        }
        // Redirect back to the main chat page to show the feedback and refresh the user list
        header("Location: chat.php");
        exit();
    }

// Handler for Toggling AFK Status
    if (isset($_POST['toggle_afk'])) {
        if (isset($_SESSION['session_id'])) {
            // Get current status from DB
            $stmt = $pdo->prepare("SELECT status FROM sessions WHERE session_id = ?");
            $stmt->execute([$_SESSION['session_id']]);
            $current_status = $stmt->fetchColumn() ?: 'online';

            // Toggle status and set/clear the default message
            if ($current_status === 'afk') {
                $new_status = 'online';
                $afk_message = null; // Clear the message when returning
            } else {
                $new_status = 'afk';
                $afk_message = 'AFK'; // Set a default message
            }

            // Update the DB in a single query
            $pdo->prepare("UPDATE sessions SET status = ?, afk_message = ? WHERE session_id = ?")
                ->execute([$new_status, $afk_message, $_SESSION['session_id']]);
        }
        // Redirect back to the chatters frame to show the change
        header('Location: ?view=chatters');
        exit;
    }



    // Handler for claiming a promoted account
    if (isset($_POST['claim_account'])) {
        $username = trim($_POST['username'] ?? '');
        $token = trim($_POST['token'] ?? '');
        $password = $_POST['password'] ?? '';
        $view = 'claim_account'; // Ensure we stay on this view on error

        if (empty($username) || empty($token) || empty($password)) {
            $error_message = "All fields are required.";
        } else {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? AND registration_token = ? AND password_hash IS NULL");
            $stmt->execute([$username, $token]);
            if ($user = $stmt->fetch()) {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $update_stmt = $pdo->prepare("UPDATE users SET password_hash = ?, registration_token = NULL WHERE id = ?");
                $update_stmt->execute([$password_hash, $user['id']]);
                
                header("Location: ?view=login&claimed=1");
                exit;
            } else {
                $error_message = "Invalid username or token, or account has already been claimed.";
            }
        }
    }



// Handler for Sending a Private Message
    if (isset($_POST['send_private_message'])) {
        // Validation: Ensure user is a logged-in member
        if (isset($_SESSION['user_id']) && !($_SESSION['is_guest'] ?? true)) {
            $from_user_id = (int)$_SESSION['user_id'];
            $to_user_id = (int)($_POST['to_user_id'] ?? 0);
            $raw_message = trim($_POST['private_message'] ?? '');
            $message_to_send = '';

// Check for /pgp command
if (strpos($raw_message, '/pgp') === 0) {
    $args = trim(substr($raw_message, 4));
    if (!empty($args)) {
        $full_block = $args; // Use the raw arguments
        $header = '-----BEGIN PGP MESSAGE-----';
        $footer = '-----END PGP MESSAGE-----';

        // Find the start and end of the actual encrypted body
        $body_start_pos = strpos($full_block, $header);
        $body_end_pos = strpos($full_block, $footer);

        // Check if both header and footer are present
        if ($body_start_pos !== false && $body_end_pos !== false) {
            $body_start = $body_start_pos + strlen($header);
            $body = substr($full_block, $body_start, $body_end_pos - $body_start);

            // Clean and format ONLY the body
            $clean_body = trim(preg_replace('/\s+/', '', $body)); // Remove all whitespace/newlines from body
            $formatted_body = wordwrap($clean_body, 64, "\n", true);

            // Reassemble the block with guaranteed blank lines
            $final_block = $header . "\n\n" . $formatted_body . "\n\n" . $footer;
        } else {
            // Fallback if header/footer are missing: just format the whole thing
            $final_block = wordwrap($full_block, 64, "\n", true);
        }

        $message_to_send = "[PGP]" . $final_block . "[/PGP]";
    }
} else {
                // Apply basic text formatting (BBCode-like) for regular messages
                $processed_message = $raw_message;
                $processed_message = preg_replace('/\[b\](.*?)\[\/b\]/is', '[B]$1[/B]', $processed_message);
                $processed_message = preg_replace('/\[i\](.*?)\[\/i\]/is', '[I]$1[/I]', $processed_message);
                $processed_message = preg_replace('/\[u\](.*?)\[\/u\]/is', '[U]$1[/U]', $processed_message);
                $processed_message = preg_replace_callback('/\[color=([a-fA-F0-9]{3,6})\](.*?)\[\/color\]/is', function($matches) {
                    $color_code = $matches[1];
                    $content = $matches[2];
                    return "[COLOR={$color_code}]{$content}[/COLOR]";
                }, $processed_message);
                $message_to_send = $processed_message;
            }

            // Ensure the message is not empty and the recipient is valid
            if (!empty($message_to_send) && $to_user_id > 0 && $from_user_id !== $to_user_id) {
                $stmt = $pdo->prepare(
                    "INSERT INTO private_messages (from_user_id, to_user_id, message) VALUES (?, ?, ?)"
                );
                $stmt->execute([$from_user_id, $to_user_id, $message_to_send]);
            }
        }
        // NO JAVASCRIPT: Redirect the input iframe to itself to clear text.
        header('Location: ?view=pm_input&with_user_id=' . $to_user_id);
        exit;
    }

    // Handler for channel switching
    if (isset($_POST['switch_channel'])) {
        $new_channel = $_POST['channel'];
        $user_role_name = $_SESSION['is_guest'] ? 'guest' : strtolower($_SESSION['user_role']);
        $user_role_level = $role_hierarchy[$user_role_name] ?? 0;
        if (isset($channels[$new_channel]) && $user_role_level >= $role_hierarchy[$channels[$new_channel]['min_role']]) {
            $_SESSION['current_channel'] = $new_channel;
        }
        // No redirect needed as the form targets _top and reloads the page
    }

// NEW COUNTER-BASED DESTROY PM CHAT HANDLER (Simplified & Final Attempt for Non-JS)
    if (isset($_POST['destroy_pm_action'])) {
        if (isset($_SESSION['user_id']) && !($_SESSION['is_guest'] ?? true)) {
            $my_id = (int)$_SESSION['user_id'];
            $their_id = (int)$_POST['target_user_id'];

            if ($my_id === $their_id) {
                // Should not happen, but prevent self-destruction
                header('Location: chat.php');
                exit;
            }

            // Step 1: Get the current GLOBAL destroy status for this conversation.
            // Fetch the maximum pm_destroy_status from any message in the conversation.
            $stmt_get_global_status = $pdo->prepare(
                "SELECT MAX(pm_destroy_status) FROM private_messages
                 WHERE (from_user_id = ? AND to_user_id = ?)
                    OR (from_user_id = ? AND to_user_id = ?)"
            );
            $stmt_get_global_status->execute([$my_id, $their_id, $their_id, $my_id]);
            $current_global_status = (int)($stmt_get_global_status->fetchColumn() ?: 0);

            // Step 2: Determine the new status.
            $new_status_after_my_click = $current_global_status;
            if ($new_status_after_my_click < 2) {
                $new_status_after_my_click++;
            }

            // Step 3: Perform actions based on the new status.
            if ($new_status_after_my_click >= 2) {
                // Status has reached 2, delete all messages between them.
                $pdo->prepare("DELETE FROM private_messages WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)")
                    ->execute([$my_id, $their_id, $their_id, $my_id]);
                
                // Announce to general chat. Usernames are encoded on final display, not here.
                $my_username_display = $_SESSION['username'];
                $their_username_stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
                $their_username_stmt->execute([$their_id]);
                $their_username_display = $their_username_stmt->fetchColumn() ?: 'User';
                
                $system_message_content = "The private chat between {$my_username_display} and {$their_username_display} has been cleared by mutual consent.";
                $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ffaa55', $system_message_content, 1, 'general']);
                
                header('Location: chat.php');
                exit;

            } else { // new_status_after_my_click is 1
                // Update the pm_destroy_status for ALL messages in the conversation.
                $pdo->prepare(
                    "UPDATE private_messages SET pm_destroy_status = ? 
                     WHERE (from_user_id = ? AND to_user_id = ?) 
                        OR (from_user_id = ? AND to_user_id = ?)"
                )->execute([$new_status_after_my_click, $my_id, $their_id, $their_id, $my_id]);

                // Prepare usernames without encoding them first.
                $my_username_display = $_SESSION['username'];
                $their_username_stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
                $their_username_stmt->execute([$their_id]);
                $their_username_display = $their_username_stmt->fetchColumn() ?: 'User';

                // Message for the other user.
                $confirm_msg_for_other = "{$my_username_display} wants to clear this private chat. Status: {$new_status_after_my_click}/2. The other user needs to click 'Destroy Chat' as well.";
                $pdo->prepare("INSERT INTO private_messages (from_user_id, to_user_id, message, is_system_message, pm_destroy_status, is_read) VALUES (?, ?, ?, ?, ?, ?)")
                    ->execute([$my_id, $their_id, $confirm_msg_for_other, 1, $new_status_after_my_click, 0]);
                
                // Message for myself.
                $confirm_msg_for_self = "You have requested to clear this private chat. Waiting for {$their_username_display}'s confirmation. Status: {$new_status_after_my_click}/2.";
                $pdo->prepare("INSERT INTO private_messages (from_user_id, to_user_id, message, is_system_message, pm_destroy_status, is_read) VALUES (?, ?, ?, ?, ?, ?)")
                    ->execute([$my_id, $my_id, $confirm_msg_for_self, 1, $new_status_after_my_click, 1]);
            }
        }
        header('Location: chat.php?view=pm&with_user_id=' . $their_id);
        exit;
    }



// THIS IS THE NEW REPLACEMENT BLOCK
if (isset($_POST['send_message'])) {
    if (isset($_SESSION['session_id']) && isset($_SESSION['username'])) {
        // Check which input was used. The unused one will be empty.
        $raw_message = trim($_POST['message_multi'] ?: $_POST['message_single']);
        $channel = $_SESSION['current_channel'] ?? 'general';
        $replying_to_id = isset($_POST['replying_to_id']) && ctype_digit($_POST['replying_to_id']) ? (int)$_POST['replying_to_id'] : null;
        
        // --- NEW: Expiring Message Logic ---
        $delete_at = null; // Default to NULL for non-expiring messages
        if (preg_match('/^\/del-(\d+)\s+(.*)/s', $raw_message, $matches)) {
            $minutes_to_delete = (int)$matches[1];
            $actual_message_content = trim($matches[2]);

            // Ensure minutes are positive and there's content left
            if ($minutes_to_delete > 0 && !empty($actual_message_content)) {
                $raw_message = $actual_message_content; // The message is now the text after the command
                $delete_at = date('Y-m-d H:i:s', time() + ($minutes_to_delete * 60));
            }
        }
        // --- End of New Logic ---

        $message_is_blocked = false;
        $block_reason = '';
        $is_admin_check = !($_SESSION['is_guest'] ?? true) && strtolower($_SESSION['user_role'] ?? 'user') === 'admin';
        $is_regular_message_flow = false;
        $message_to_send = null;

        // --- Preventative Link Blocking & Spam Control ---
        $link_check_string = preg_replace('/\s+/', '', $raw_message);
        $link_check_string = preg_replace('/\[(dot|dt)\]/i', '.', $link_check_string);
        $is_link = preg_match('/(https?:\/\/|www\.)|(\b[a-zA-Z0-9-]+\.(com|org|net|io|co|us|info|xyz|online|shop)\b)/i', $link_check_string);

        if ($is_link && !$is_admin_check) {
            $can_post_links = false;
            // Check guest permissions
            if ($_SESSION['is_guest'] ?? true) {
                $stmt = $pdo->prepare("SELECT can_post_links FROM guests WHERE id = ?");
                $stmt->execute([$_SESSION['guest_id']]);
                $can_post_links = (bool)$stmt->fetchColumn();
                if (!$can_post_links) {
                    $message_is_blocked = true;
                    $block_reason = 'Guests cannot post links without moderator permission.';
                }
            } else { // Check member permissions
                $stmt = $pdo->prepare("SELECT can_post_links, created_at FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user_data = $stmt->fetch(PDO::FETCH_ASSOC);
                $can_post_links = (bool)$user_data['can_post_links'];
                if (!$can_post_links && (time() - strtotime($user_data['created_at'])) < 86400) {
                    $message_is_blocked = true;
                    $block_reason = 'New members must wait 24 hours to post links.';
                }
            }
            
            // Check forbidden domains if user has permission but message isn't already blocked
            if ($can_post_links && !$message_is_blocked) {
                if(preg_match('/https?:\/\/[^\s<>()]+/i', $raw_message, $matches)) {
                    $domain = parse_url($matches[0], PHP_URL_HOST);
                    if($domain) {
                        $domain = str_ireplace('www.', '', $domain);
                        $forbidden_domains_str = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'forbidden_domains'")->fetchColumn() ?: '';
                        if ($forbidden_domains_str) {
                            $forbidden_domains = explode(',', $forbidden_domains_str);
                            foreach ($forbidden_domains as $forbidden_domain) {
                                if (trim($forbidden_domain) !== '' && strcasecmp($domain, trim($forbidden_domain)) === 0) {
                                    $message_is_blocked = true;
                                    $block_reason = 'That domain is not allowed.';
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- Final Decision: Block or Send ---
        if ($message_is_blocked) {
            $_SESSION['input_error'] = $block_reason; // Set the error for the input frame
        } else {
            $message_to_send = $raw_message; 
            
            // Check for other commands ONLY if it's not an expiring message
            if (!empty($raw_message) && strpos($raw_message, '/') === 0 && $delete_at === null) {
                $parts = explode(' ', $raw_message, 2);
                $command = strtolower(ltrim($parts[0], '/'));
                $args = $parts[1] ?? '';
                
                // THIS IS THE FIX: Define the user role variable for all command checks.
                $user_role_for_commands = strtolower($_SESSION['user_role'] ?? 'guest');

                switch ($command) {
                    case 'whisper':
                case 'w':
                    // Admins only command
                    if ($user_role_for_commands === 'admin') {
                        // Extract target username and message
                        if (preg_match('/^(\S+)\s+(.*)/s', $args, $matches)) {
                            $target_username = $matches[1];
                            $whisper_message = trim($matches[2]);

                            if (!empty($whisper_message)) {
                                // Check if target user is online
                                $stmt = $pdo->prepare("SELECT session_id FROM sessions WHERE username = ?");
                                $stmt->execute([$target_username]);
                                if ($stmt->fetch()) {
                                    // Tag the message for special handling
                                    $message_to_send = "[WHISPER to:{$target_username}]{$whisper_message}[/WHISPER]";
                                    $is_regular_message_flow = true;
                                } else {
                                    // Send error message to the admin's session
                                    $_SESSION['system_feedback'] = "User '" . htmlspecialchars($target_username) . "' is not online.";
                                }
                            } else {
                                $_SESSION['system_feedback'] = "Usage: /whisper [username] [message]";
                            }
                        } else {
                            $_SESSION['system_feedback'] = "Usage: /whisper [username] [message]";
                        }
                    } else {
                        // Deny permission for non-admins
                        $_SESSION['system_feedback'] = "You do not have permission to use the /whisper command.";
                    }
                    break;
                case 'away':
                case 'afk':
                    $afk_message = !empty($args) ? substr($args, 0, 100) : 'Away'; // Set message or default, limit length
                    $pdo->prepare("UPDATE sessions SET status = 'afk', afk_message = ? WHERE session_id = ?")->execute([$afk_message, $_SESSION['session_id']]);
                    // No message is sent to chat, the user list will just update.
                    break;

                case 'back':
                    $pdo->prepare("UPDATE sessions SET status = 'online', afk_message = NULL WHERE session_id = ?")->execute([$_SESSION['session_id']]);
                    // No message is sent to chat.
                    break;

    case 'img':
                    // Check for admin or moderator role
                    $user_role_for_commands = strtolower($_SESSION['user_role'] ?? 'guest');
                    if ($user_role_for_commands === 'admin' || $user_role_for_commands === 'moderator') {
                        if (!empty($args)) {
                            // Basic validation to ensure it looks like a URL
                            if (filter_var($args, FILTER_VALIDATE_URL)) {
                                // Create a special tag for the renderer to find
                                $message_to_send = "[IMG]" . $args . "[/IMG]";
                                $is_regular_message_flow = true;
                            } else {
                                $system_message = "Invalid URL provided for /img command.";
                                $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                            }
                        } else {
                            $system_message = "Usage: /img [image URL]";
                            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                        }
                    } else {
                        // Deny permission for users who are not mods or admins
                        $system_message = "You do not have permission to use the /img command.";
                        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                    }
                    break;
  case 'cointoss':
                    $result = (rand(0, 1) === 0) ? 'Heads' : 'Tails';
                    $color = ($result === 'Heads') ? '#cc0000' : '#2E8B57';

                    // Create a structured message instead of raw HTML. We use a special prefix to identify it later.
                    // This is much safer as the renderer will handle the HTML creation.
                    $message_to_send = "COINFLIP::{$result}::{$color}::flipped a coin and it landed on: ";
                    $is_regular_message_flow = true;
                    break;

                case 'spoiler':
                    if (!empty($args)) {
                        $message_to_send = "[SPOILER]" . $args . "[/SPOILER]";
                        $is_regular_message_flow = true;
                    } else {
                        // This part is for showing an error, it can still post as system
                        $system_message = "Usage: /spoiler [your hidden text]";
                        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                    }
                    break;

                case 'me':
                    if (!empty($args)) {
                        $message_to_send = "[ME]" . $args . "[/ME]";
                        $is_regular_message_flow = true;
                    } else {
                        $system_message = "Usage: /me [action]";
                        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                    }
                    break;

                case 'roll':
                    $max_roll = (int)$args;
                    if ($max_roll > 0 && $max_roll <= 1000) {
                        $roll_result = mt_rand(1, $max_roll);
                        // Prepare the message to be sent through the regular flow
                        $message_to_send = "rolled a " . htmlspecialchars($roll_result) . " (1-" . htmlspecialchars($max_roll) . ").";
                        $is_regular_message_flow = true;
                    } else {
                        $system_message = "Usage: /roll [number] (Max 1000)";
                        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                    }
                    break;



                    case 'pgp':
    if (!empty($args)) {
        $full_block = $args; // Use the raw arguments
        $header = '-----BEGIN PGP MESSAGE-----';
        $footer = '-----END PGP MESSAGE-----';

        // Find the start and end of the actual encrypted body
        $body_start_pos = strpos($full_block, $header);
        $body_end_pos = strpos($full_block, $footer);

        // Check if both header and footer are present
        if ($body_start_pos !== false && $body_end_pos !== false) {
            $body_start = $body_start_pos + strlen($header);
            $body = substr($full_block, $body_start, $body_end_pos - $body_start);

            // Clean and format ONLY the body
            $clean_body = trim(preg_replace('/\s+/', '', $body)); // Remove all whitespace/newlines from body
            $formatted_body = wordwrap($clean_body, 64, "\n", true);

            // Reassemble the block with guaranteed blank lines
            $final_block = $header . "\n\n" . $formatted_body . "\n\n" . $footer;
        } else {
            // Fallback if header/footer are missing: just format the whole thing
            $final_block = wordwrap($full_block, 64, "\n", true);
        }

        $message_to_send = "[PGP]" . $final_block . "[/PGP]";
        $is_regular_message_flow = true;
    } else {
        $system_message = "Usage: /pgp [paste PGP block]";
        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
    }
    break;


case 'view_pgp':
    if (!isset($_SESSION['user_id'])) { // Security check: ensure viewer is logged in
        die("Access Denied. You must be logged in to view PGP keys.");
    }
    if (!isset($_GET['user_id']) || !ctype_digit($_GET['user_id'])) {
        die("Invalid user.");
    }
    $user_id_to_view = (int)$_GET['user_id'];
    $stmt = $pdo->prepare("SELECT username, pgp_public_key FROM users WHERE id = ?");
    $stmt->execute([$user_id_to_view]);
    $key_data = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$key_data || empty($key_data['pgp_public_key'])) {
        die("This user does not have a public key set.");
    }
    ?>
    <!DOCTYPE html><html><head><title>PGP Key</title><link rel="stylesheet" href="style.css?v=1.1"></head><body>
        <div class="pgp-modal-overlay">
            <div class="pgp-modal-content">
                <a href="chat.php" class="close-pgp-button" title="Close">×</a>
                <h2>PGP Public Key for <?php echo htmlspecialchars($key_data['username']); ?></h2>
                <textarea readonly class="pgp-key-display"><?php echo htmlspecialchars($key_data['pgp_public_key']); ?></textarea>
                <a href="chat.php" target="_top" class="pgp-modal-close-link">Close</a>
            </div>
        </div>
    </body></html>
    <?php
    break;

                case 'help':
                    $help_message = "Available commands: ";
                    $commands_list = [
                        '/cointoss',
                        '/spoiler [text]',
                        '/me [action]',
                        '/roll [number]',
                        '/pgp [PGP block]',
                        '/help'
                    ];
                    if ($user_role_for_commands === 'admin' || $user_role_for_commands === 'moderator') {
                        $commands_list[] = '/lockchat [guest|user|all|unlocked]';
                    }
                    if ($user_role_for_commands === 'admin') {
                        $commands_list[] = '/clearchat [all|channel]';
                    }
                    $help_message .= implode(', ', $commands_list) . ".";
                    
                    // NEW: Store the help text in the session instead of the database
                    $_SESSION['system_feedback'] = $help_message;
                    break;

                case 'lockchat':
                    if ($user_role_for_commands === 'admin' || $user_role_for_commands === 'moderator') {
                        $lock_level = strtolower(trim($args));
                        $allowed_lock_levels = ['guest', 'user', 'all', 'unlocked'];
                        if (in_array($lock_level, $allowed_lock_levels)) {
                            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'chat_locked'")->execute([$lock_level]);
                            $lock_message = "unlocked the chat.";
                            if ($lock_level === 'guest') { $lock_message = "locked the chat for Guests."; }
                            elseif ($lock_level === 'user') { $lock_message = "locked the chat for Members and below."; }
                            elseif ($lock_level === 'all') { $lock_message = "locked the chat for everyone."; }
                            $system_message_text = htmlspecialchars($_SESSION['username']) . " " . $lock_message;
                            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ffaa55', $system_message_text, 1, $channel]);
                        } else {
                            $system_message = "Usage: /lockchat [guest|user|all|unlocked]";
                            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                        }
                    } else {
                        $system_message = "Permission denied.";
                        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                    }
                    break;

                case 'clearchat':
                    if ($user_role_for_commands === 'admin') {
                        $channel_to_clear = strtolower(trim($args));
                        $channels_for_tools = ['general', 'members', 'moderators', 'admin'];
                        if ($channel_to_clear === 'all') {
                            $pdo->exec("TRUNCATE TABLE messages");
                            $system_message = htmlspecialchars($_SESSION['username']) . " cleared all messages.";
                            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, 'general']);
                        } elseif (in_array($channel_to_clear, $channels_for_tools)) {
                            $stmt = $pdo->prepare("DELETE FROM messages WHERE channel = ?");
                            $stmt->execute([$channel_to_clear]);
                            $system_message = htmlspecialchars($_SESSION['username']) . " cleared #" . htmlspecialchars($channel_to_clear) . ".";
                            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel_to_clear]);
                        } else {
                            $system_message = "Usage: /clearchat [all|general|members|moderators|admin]";
                            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                        }
                    } else {
                        $system_message = "Permission denied.";
                        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                    }
                    break;
                        default:
                            $system_message = "Unknown command: " . htmlspecialchars($command);
                            $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute(['System', '#ff5555', $system_message, 1, $channel]);
                            break;
                    }
                } else {
                    // It's not a command, or it's a /del command, so process it as a regular message.
                    if (!empty($raw_message)) {
                        $processed_message = $raw_message;

                        // Simple BBCode-like tag conversion
                        $processed_message = preg_replace('/\[b\](.*?)\[\/b\]/is', '[B]$1[/B]', $processed_message);
                        $processed_message = preg_replace('/\[i\](.*?)\[\/i\]/is', '[I]$1[/I]', $processed_message);
                        $processed_message = preg_replace('/\[u\](.*?)\[\/u\]/is', '[U]$1[/U]', $processed_message);
                        $processed_message = preg_replace_callback('/\[color=([a-fA-F0-9]{3,6})\](.*?)\[\/color\]/is', function($matches) {
                            $color_code = $matches[1];
                            $content = $matches[2];
                            return "[COLOR={$color_code}]{$content}[/COLOR]";
                        }, $processed_message);
                        
                        $message_to_send = $processed_message;
                        $is_regular_message_flow = true;
                    }
                }

                
// --- 2. REGULAR MESSAGE PROCESSING (if applicable) ---
            if ($is_regular_message_flow && !empty($message_to_send)) {
                
                // --- Auto-Moderation Checks ---
                if (strpos(trim($raw_message), '/pgp') !== 0) {
                    $auto_kick_reason = '';
                    $message_for_check = strip_tags($raw_message);
                    $is_admin_check = !($_SESSION['is_guest'] ?? true) && strtolower($_SESSION['user_role'] ?? 'user') === 'admin';
                    $link_cost = 10;

                    // Check if the message contains a link
                    if (preg_match('/https?:\/\/[^\s<>()]+/i', $message_for_check, $matches)) {
                        $found_link = $matches[0];
                        $domain = parse_url($found_link, PHP_URL_HOST);
                        $domain = str_ireplace('www.', '', $domain);

                        // 1. Check against Forbidden Domains
                        $forbidden_domains_str = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'forbidden_domains'")->fetchColumn() ?: '';
                        if ($forbidden_domains_str && !$is_admin_check) {
                            $forbidden_domains = explode(',', $forbidden_domains_str);
                            foreach ($forbidden_domains as $forbidden_domain) {
                                if (trim($forbidden_domain) !== '' && strcasecmp($domain, trim($forbidden_domain)) === 0) {
                                    $auto_kick_reason = 'Posting links from that domain is not allowed.';
                                    break;
                                }
                            }
                        }

                        // 2. Check User-Specific Link Permissions
                        if (empty($auto_kick_reason) && !$is_admin_check) {
                            $can_post_links = false;
                            $is_new_member = false;

                            if (!($_SESSION['is_guest'] ?? true)) { // Is a Member
                                $stmt = $pdo->prepare("SELECT can_post_links, created_at FROM users WHERE id = ?");
                                $stmt->execute([$_SESSION['user_id']]);
                                $user_data = $stmt->fetch(PDO::FETCH_ASSOC);
                                $can_post_links = (bool)$user_data['can_post_links'];
                                if ((time() - strtotime($user_data['created_at'])) < 86400) {
                                    $is_new_member = true;
                                }
                            } else { // Is a Guest
                                $stmt = $pdo->prepare("SELECT can_post_links FROM guests WHERE id = ?");
                                $stmt->execute([$_SESSION['guest_id']]);
                                $can_post_links = (bool)$stmt->fetchColumn();
                            }

                            if (!$can_post_links) {
                                if ($_SESSION['is_guest'] ?? true) {
                                    $auto_kick_reason = 'Guests cannot post links unless granted permission.';
                                } elseif ($is_new_member) {
                                    $auto_kick_reason = 'New members must wait 24 hours before posting links.';
                                }
                            }
                        }
                        
                        // 3. Guest Link Token Cost
                        if (empty($auto_kick_reason) && ($_SESSION['is_guest'] ?? true)) {
                            $guest_id = $_SESSION['guest_id'];
                            $stmt = $pdo->prepare("SELECT message_count, message_limit FROM guests WHERE id = ?");
                            $stmt->execute([$guest_id]);
                            if (($guest_data = $stmt->fetch(PDO::FETCH_ASSOC))) {
                                if (($guest_data['message_count'] + $link_cost) > $guest_data['message_limit']) {
                                    $auto_kick_reason = "You don't have enough tokens to post a link (costs {$link_cost}).";
                                } else {
                                    $pdo->prepare("UPDATE guests SET message_count = message_count + ? WHERE id = ?")->execute([($link_cost - 1), $guest_id]);
                                }
                            }
                        }
                    }

                    // Check for message repetition (spam)
                    if (empty($auto_kick_reason)) {
                        if (!isset($_SESSION['last_messages'])) { $_SESSION['last_messages'] = []; }
                        if (count($_SESSION['last_messages']) === 2 && $_SESSION['last_messages'][0] === $message_for_check && $_SESSION['last_messages'][1] === $message_for_check) {
                            $auto_kick_reason = 'You have been kicked for message repetition.';
                        }
                    }

                    // Check for banned words
                    if (empty($auto_kick_reason)) {
                        $banned_words_string = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'banned_words_list'")->fetchColumn();
                        if ($banned_words_string) {
                            $banned_words = explode(',', $banned_words_string);
                            foreach ($banned_words as $word) {
                                if (trim($word) !== '' && stripos($message_for_check, trim($word)) !== false) {
                                    $auto_kick_reason = 'Your message contains a forbidden word.';
                                    break;
                                }
                            }
                        }
                    }

                    if (!empty($auto_kick_reason) && !$is_admin_check) {
                        // Gather details for the kick log
                        $kicked_user_id_log = null;
                        $kicked_guest_id_log = null;
                        $kicked_username_log = $_SESSION['username'];
                        $kicked_ip_log = get_client_ip();
                        $kicked_fingerprint_log = $_COOKIE['rotchat_fp'] ?? null;

                        // Dynamically fetch chat history for the kicked user/guest from the database
                        $history_stmt = null;
                        if (isset($_SESSION['user_id'])) {
                            $history_stmt = $pdo->prepare("SELECT username, message, created_at FROM messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 50");
                            $history_stmt->execute([$_SESSION['user_id']]);
                        } elseif (isset($_SESSION['guest_id'])) {
                            $history_stmt = $pdo->prepare("SELECT username, message, created_at FROM messages WHERE guest_id = ? ORDER BY created_at DESC LIMIT 50");
                            $history_stmt->execute([$_SESSION['guest_id']]);
                        }
                        // Encode the fetched history as JSON; if no history is found, it will be an empty array
                        $chat_history_log = json_encode($history_stmt ? $history_stmt->fetchAll(PDO::FETCH_ASSOC) : []);

                        if (isset($_SESSION['user_id'])) {
                            $kicked_user_id_log = $_SESSION['user_id'];
                        } elseif (isset($_SESSION['guest_id'])) {
                            $kicked_guest_id_log = $_SESSION['guest_id'];
                        }

                        // Insert into kick_logs table
                        $log_stmt = $pdo->prepare("INSERT INTO kick_logs (kicked_user_id, kicked_guest_id, kicked_username, kicked_user_ip, kicked_user_fingerprint, moderator_user_id, moderator_username, kick_reason, chat_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                        $log_stmt->execute([
                            $kicked_user_id_log,
                            $kicked_guest_id_log,
                            $kicked_username_log,
                            $kicked_ip_log,
                            $kicked_fingerprint_log,
                            null, // moderator_user_id: NULL for system/auto kick
                            'System', // moderator_username: 'System' for auto kick
                            $auto_kick_reason,
                            $chat_history_log
                        ]);

                        // Apply a fingerprint-based cooldown, consistent with manual kicks.
                        $kick_cooldown_minutes_from_db = (int)($settings['kick_cooldown_minutes'] ?? 5);
                        if ($kick_cooldown_minutes_from_db > 0) {
                            $cooldown_until = date('Y-m-d H:i:s', time() + ($kick_cooldown_minutes_from_db * 60));
                            
                            // 1. Apply fingerprint ban (the primary enforcement)
                            if (!empty($kicked_fingerprint_log)) {
                                $temp_ban_reason = "Temporary ban from auto-kick: " . $auto_kick_reason;
                                $pdo->prepare("INSERT INTO ban_list (ban_type, ban_value, reason, banned_by_user_id, banned_until) VALUES ('fingerprint', ?, ?, ?, ?) ON DUPLICATE KEY UPDATE banned_until = VALUES(banned_until), reason = VALUES(reason)")
                                    ->execute([$kicked_fingerprint_log, $temp_ban_reason, null, $cooldown_until]); // Banned by System (NULL user_id)
                            }
                            
                            // 2. THIS IS THE FIX: Also update the user/guest record for consistency.
                            if (isset($_SESSION['user_id'])) {
                                $pdo->prepare("UPDATE users SET kick_cooldown_until = ? WHERE id = ?")->execute([$cooldown_until, $_SESSION['user_id']]);
                            } elseif (isset($_SESSION['guest_id'])) {
                                $pdo->prepare("UPDATE guests SET kick_cooldown_until = ? WHERE id = ?")->execute([$cooldown_until, $_SESSION['guest_id']]);
                            }
                        }

                        // Finally, set the kick message in the session and redirect
                        $pdo->prepare("UPDATE sessions SET kick_message = ? WHERE session_id = ?")->execute([$auto_kick_reason, $_SESSION['session_id']]);
                        header('Location: ?view=input'); exit;
                    }

                    $_SESSION['last_messages'][] = $message_for_check;
                    if (count($_SESSION['last_messages']) > 2) { array_shift($_SESSION['last_messages']); }
                }

                // --- Permission Checks (Ban & Chat Lock) ---
                $can_post = true;
                $is_admin = !($_SESSION['is_guest'] ?? true) && strtolower($_SESSION['user_role']) === 'admin';
                if (!($_SESSION['is_guest'] ?? true)) {
                    $stmt = $pdo->prepare("SELECT is_banned FROM users WHERE id = ?"); $stmt->execute([$_SESSION['user_id']]);
                    if ($stmt->fetchColumn() == '1') { $can_post = false; }
                }
                if ($can_post && !$is_admin) {
                    $lock_level_setting = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'chat_locked'")->fetchColumn() ?: 'unlocked';
                    if ($lock_level_setting !== 'unlocked') {
                        $user_role = ($_SESSION['is_guest'] ?? true) ? 'guest' : strtolower($_SESSION['user_role']);
                        // THIS IS THE FIX: The 'trusted' role was missing from this array.
                        // Using the complete hierarchy ensures all roles are checked correctly.
                        $lock_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];
                        $user_level = $lock_hierarchy[$user_role] ?? 0; // Default to 0 if role not found
                        if ($lock_level_setting === 'all') {
                            $can_post = false;
                        } elseif (isset($lock_hierarchy[$lock_level_setting])) {
                            $required_level = $lock_hierarchy[$lock_level_setting];
                            if ($user_level <= $required_level) { $can_post = false; }
                        }
                    }
                }
                
                // --- Database Insert ---
                if ($can_post) {
                    // AFK status is no longer changed upon sending a message.

                    $pdo->prepare(
                        "INSERT INTO messages (user_id, guest_id, username, color, message, channel, replying_to_message_id, delete_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    )->execute([
                        $_SESSION['user_id'] ?? null,
                        $_SESSION['guest_id'] ?? null,
                        $_SESSION['username'],
                        $_SESSION['color'],
                        $message_to_send,
                        $channel,
                        $replying_to_id,
                        $delete_at
                    ]);
                    
                    // --- Message Count Increment ---
                    if ($_SESSION['is_guest'] ?? false) {
                        $pdo->prepare("UPDATE guests SET message_count = message_count + 1 WHERE id = ?")->execute([$_SESSION['guest_id']]);
                    } else if (isset($_SESSION['user_id'])) {
                        $pdo->prepare("UPDATE users SET message_count = message_count + 1 WHERE id = ?")->execute([$_SESSION['user_id']]);
                    }
                }
            }
        }
    }
    // ALWAYS redirect ONLY the input frame.
    header('Location: ?view=input');
    exit;
}

    // --- ALL OTHER ORIGINAL POST HANDLERS ARE PRESERVED BELOW ---


    // Handler for Toggling Ignore on a User
if (isset($_POST['toggle_ignore'])) {
    $target_identifier = $_POST['target_identifier'] ?? null;

    if ($target_identifier) {
        // Initialize ignore list in session if it doesn't exist
        if (!isset($_SESSION['ignored_users'])) {
            $_SESSION['ignored_users'] = [];
        }

        // Check if user is already ignored
        $is_ignored = in_array($target_identifier, $_SESSION['ignored_users']);

        if ($is_ignored) {
            // Unignore: Remove the user from the array
            $_SESSION['ignored_users'] = array_diff($_SESSION['ignored_users'], [$target_identifier]);
        } else {
            // Ignore: Add the user to the array
            $_SESSION['ignored_users'][] = $target_identifier;
        }
    }

    // Redirect back to the chatters list to see the updated icon
    header('Location: ?view=chatters');
    exit;
}


    // Handler for updating notes
    if (isset($_POST['update_notes'])) {
        $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
        if ($actor_role === 'admin' || $actor_role === 'moderator') {
            $public_notes = $_POST['public_notes'] ?? '';
            $admin_notes = $_POST['admin_notes'] ?? '';
            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'public_notes'")->execute([$public_notes]);
            $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'admin_notes'")->execute([$admin_notes]);
            $_SESSION['notes_feedback'] = ['type' => 'success', 'message' => 'Notes have been updated successfully.'];
        } else {
            $_SESSION['notes_feedback'] = ['type' => 'error', 'message' => 'You do not have permission to edit notes.'];
        }
        header('Location: ' . $_SERVER['PHP_SELF']); exit;
    }

// Handler for deleting a single message (CSRF + role lists + audit log + no system delete)
    if (isset($_POST['delete_message']) && isset($_POST['message_id'])) {
        // CSRF check
        if (
            empty($_POST['csrf_token']) ||
            empty($_SESSION['csrf_token']) ||
            !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
        ) {
            http_response_code(400);
            exit('Bad Request: CSRF validation failed.');
        }

        $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
        $actor_id   = (int)($_SESSION['user_id'] ?? 0);
        $actor_name = $_SESSION['username'] ?? 'unknown';

        // Load settings locally in case $settings isn't global here
        $getSetting = function($key, $default = null) use ($pdo) {
            try {
                $s = $pdo->prepare("SELECT setting_value FROM settings WHERE setting_key = ? LIMIT 1");
                $s->execute([$key]);
                $v = $s->fetchColumn();
                return ($v === false) ? $default : $v;
            } catch (Throwable $e) {
                return $default;
            }
        };
        $trusted_mode = strtolower($getSetting('trusted_delete_mode', $settings['trusted_delete_mode'] ?? 'own'));
        $roles_any_csv = $getSetting('roles_delete_any', $settings['roles_delete_any'] ?? 'admin,moderator,supermod');
        $roles_own_csv = $getSetting('roles_delete_own', $settings['roles_delete_own'] ?? 'trusted,member');
        
        $roles_delete_any = array_filter(array_map('trim', array_map('strtolower', explode(',', (string)$roles_any_csv))));
        $roles_delete_own = array_filter(array_map('trim', array_map('strtolower', explode(',', (string)$roles_own_csv))));

        if (!empty($_SESSION['username'])) {
            $message_id_to_delete = (int)$_POST['message_id'];

            $meta_stmt = $pdo->prepare("SELECT m.id, m.user_id, m.guest_id, m.username, m.message, m.created_at, m.is_system_message, u.role as user_role FROM messages m LEFT JOIN users u ON m.user_id = u.id WHERE m.id = ?");
            $meta_stmt->execute([$message_id_to_delete]);
            $msgMeta = $meta_stmt->fetch(PDO::FETCH_ASSOC);

            if ($msgMeta) {
                $is_system = (int)$msgMeta['is_system_message'] === 1;
                $is_own_message = $actor_id && ((int)$msgMeta['user_id'] === $actor_id);
                $can_delete = false; // Start with no permission

                if (!$is_system) {
                    $target_role = !is_null($msgMeta['user_id']) ? strtolower($msgMeta['user_role'] ?? 'user') : 'guest';
                    $actor_level = $role_hierarchy[$actor_role] ?? 0;
                    $target_level = $role_hierarchy[$target_role] ?? 0;

                    // Permission check 1: General role for deleting ANY message (Mods, Admins)
                    if (in_array($actor_role, $roles_delete_any) && $actor_level > $target_level) {
                        $can_delete = true;
                    }
                    // Permission check 2: Special case for Trusted role
                    elseif ($actor_role === 'trusted' && $trusted_mode === 'all' && $actor_level > $target_level) {
                        $can_delete = true;
                    }
                    // Permission check 3: General role for deleting OWN messages
                    elseif ($is_own_message && in_array($actor_role, $roles_delete_own)) {
                        $can_delete = true;
                    }

                    if ($can_delete) {
                        // Ensure audit table exists
                        $pdo->exec("
                            CREATE TABLE IF NOT EXISTS message_deletions (
                                id INT AUTO_INCREMENT PRIMARY KEY, message_id INT NOT NULL, original_user_id INT NULL,
                                original_guest_id INT NULL, original_username VARCHAR(255) NULL, original_message TEXT NULL,
                                original_created_at DATETIME NULL, deleted_by_user_id INT NULL, deleted_by_username VARCHAR(255) NULL,
                                deleted_by_role VARCHAR(32) NULL, deleted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                        ");
                        // Log the deletion
                        $log = $pdo->prepare("INSERT INTO message_deletions (message_id, original_user_id, original_guest_id, original_username, original_message, original_created_at, deleted_by_user_id, deleted_by_username, deleted_by_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                        $log->execute([
                            (int)$msgMeta['id'],
                            isset($msgMeta['user_id']) ? (int)$msgMeta['user_id'] : null,
                            isset($msgMeta['guest_id']) ? (int)$msgMeta['guest_id'] : null,
                            $msgMeta['username'] ?? null, $msgMeta['message'] ?? null, $msgMeta['created_at'] ?? null,
                            $actor_id ?: null, $actor_name, $actor_role
                        ]);
                        // Perform the deletion
                        $pdo->prepare("DELETE FROM messages WHERE id = ?")->execute([$message_id_to_delete]);
                    }
                }
            }
        }
        header('Location: ?view=messages'); exit;
    }


// Handler for Moderation Actions
// --- THIS IS THE CORRECTED PHP BLOCK ---
if (isset($_POST['moderate_user'])) {
    $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
    if ($actor_role === 'admin' || $actor_role === 'moderator') {
        $action = $_POST['action'] ?? '';
        $target_user_id = !empty($_POST['target_user_id']) ? $_POST['target_user_id'] : null;
        $target_guest_id = !empty($_POST['target_guest_id']) ? $_POST['target_guest_id'] : null;
        $target_session_id = $_POST['target_session_id'] ?? null;
        $target_username = $_POST['target_username'] ?? 'User';
        
        $target_role = 'guest';
        if ($target_user_id) {
            $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?"); $stmt->execute([$target_user_id]);
            $target_role = strtolower($stmt->fetchColumn() ?: 'user');
        }

        $can_moderate = ($actor_role === 'admin' && $target_role !== 'admin') || ($actor_role === 'moderator' && !in_array($target_role, ['admin', 'moderator']));

        if ($can_moderate) {
            switch ($action) {
case 'kick':
    $reason = trim($_POST['kick_reason'] ?? '');
    $default_reason = "You have been kicked by a moderator.";
    if (empty($reason)) { $reason = $default_reason; }

    if ($target_session_id) {
        $kicked_ip = null;
        $kicked_fingerprint = null;
        $history_stmt = null;
        
        // --- Get Cooldown Duration from Settings ---
        $kick_cooldown_minutes_from_db = (int)($settings['kick_cooldown_minutes'] ?? 5);
        $banned_until_timestamp = date('Y-m-d H:i:s', time() + ($kick_cooldown_minutes_from_db * 60));

        if ($target_user_id) {
            $stmt = $pdo->prepare("SELECT last_login_ip FROM users WHERE id = ?");
            $stmt->execute([$target_user_id]);
            $kicked_ip = $stmt->fetchColumn();
            // Fetch user's fingerprint from their last session if available
            $fp_stmt = $pdo->prepare("SELECT g.fingerprint FROM sessions s LEFT JOIN guests g ON s.guest_id = g.id WHERE s.user_id = ? ORDER BY s.last_active DESC LIMIT 1");
            $fp_stmt->execute([$target_user_id]);
            $kicked_fingerprint = $fp_stmt->fetchColumn();
            
            $history_stmt = $pdo->prepare("SELECT username, message, created_at FROM messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 50");
            $history_stmt->execute([$target_user_id]);
            
            // Apply cooldown to user record (for display in admin panel)
            $pdo->prepare("UPDATE users SET kick_cooldown_until = ? WHERE id = ?")->execute([$banned_until_timestamp, $target_user_id]);

        } elseif ($target_guest_id) {
            // THIS IS THE FIX: Apply the same cooldown to the guest's record.
            $pdo->prepare("UPDATE guests SET kick_cooldown_until = ? WHERE id = ?")->execute([$banned_until_timestamp, $target_guest_id]);

            $stmt = $pdo->prepare("SELECT last_login_ip, fingerprint FROM guests WHERE id = ?");
            $stmt->execute([$target_guest_id]);
            $guest_details = $stmt->fetch(PDO::FETCH_ASSOC);
            $kicked_ip = $guest_details['last_login_ip'] ?? null;
            $kicked_fingerprint = $guest_details['fingerprint'] ?? null;
            
            $history_stmt = $pdo->prepare("SELECT username, message, created_at FROM messages WHERE guest_id = ? ORDER BY created_at DESC LIMIT 50");
            $history_stmt->execute([$target_guest_id]);
        }
        
        // --- Apply Fingerprint Cooldown for BOTH Guests and applicable Users ---
        if ($kick_cooldown_minutes_from_db > 0 && !empty($kicked_fingerprint)) {
            $temp_ban_reason = "Temporary ban from kick cooldown.";
            $pdo->prepare("INSERT INTO ban_list (ban_type, ban_value, reason, banned_by_user_id, banned_until) VALUES ('fingerprint', ?, ?, ?, ?) ON DUPLICATE KEY UPDATE banned_until = VALUES(banned_until), reason = VALUES(reason)")
                ->execute([$kicked_fingerprint, $temp_ban_reason, $_SESSION['user_id'], $banned_until_timestamp]);
        }

        // Create kick log
        $chat_history_json = json_encode($history_stmt ? $history_stmt->fetchAll(PDO::FETCH_ASSOC) : []);
        $log_stmt = $pdo->prepare("INSERT INTO kick_logs (kicked_user_id, kicked_guest_id, kicked_username, kicked_user_ip, kicked_user_fingerprint, moderator_user_id, moderator_username, kick_reason, chat_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $log_stmt->execute([$target_user_id ? (int)$target_user_id : null, $target_guest_id ? (int)$target_guest_id : null, $target_username, $kicked_ip, $kicked_fingerprint, $_SESSION['user_id'], $_SESSION['username'], $reason, $chat_history_json]);
        
        // Set kick message in session to terminate it
        $pdo->prepare("UPDATE sessions SET kick_message = ? WHERE session_id = ?")->execute([$reason, $target_session_id]);
        
        $kick_system_message = htmlspecialchars($target_username) . " has been kicked" . (($reason !== $default_reason) ? " for: " . htmlspecialchars($reason) : ".");
        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute([$_SESSION['username'], $_SESSION['color'] ?? '#FFFFFF', $kick_system_message, 1, $_SESSION['current_channel'] ?? 'general']);
        
        $_SESSION['moderation_feedback'] = "Successfully kicked '".htmlspecialchars($target_username)."' and applied a fingerprint cooldown.";
    }
    break;

                case 'adjust_tokens':
                    if ($target_guest_id) {
                        $can_post_links_value = isset($_POST['can_post_links']) ? 1 : 0;
                        $pdo->prepare("UPDATE guests SET can_post_links = ? WHERE id = ?")->execute([$can_post_links_value, $target_guest_id]);

                        if (isset($_POST['tokens_to_adjust'])) {
                             $tokens = (int)$_POST['tokens_to_adjust'];
                             if ($tokens !== 0) {
                                $pdo->prepare("UPDATE guests SET message_limit = GREATEST(0, message_limit + ?) WHERE id = ?")->execute([$tokens, $target_guest_id]);
                             }
                        }
                        $_SESSION['moderation_feedback'] = "Guest settings for '" . htmlspecialchars($target_username) . "' have been updated.";
                    }
                    break;
                
                case 'clear_messages':
                    $deleted_count = 0;
                    $archive_reason = "Messages cleared by moderator " . $_SESSION['username'];
                    $moderator_id = $_SESSION['user_id'];
                    $column = $target_guest_id ? 'guest_id' : 'user_id';
                    $id = $target_guest_id ?: $target_user_id;
                    
                    if (!$id) break;

                    $stmt_select = $pdo->prepare("SELECT * FROM messages WHERE $column = ?");
                    $stmt_select->execute([$id]);
                    $messages_to_archive = $stmt_select->fetchAll(PDO::FETCH_ASSOC);

                    if ($messages_to_archive) {
                        $stmt_archive = $pdo->prepare("INSERT INTO archived_messages (original_message_id, user_id, guest_id, username, color, message, channel, created_at, archived_by_user_id, archive_reason) VALUES (:orig_id, :user_id, :guest_id, :username, :color, :message, :channel, :created_at, :archived_by, :reason)");
                        foreach ($messages_to_archive as $msg) {
                            $stmt_archive->execute(['orig_id' => $msg['id'], 'user_id' => $msg['user_id'], 'guest_id' => $msg['guest_id'], 'username' => $msg['username'], 'color' => $msg['color'], 'message' => $msg['message'], 'channel' => $msg['channel'], 'created_at' => $msg['created_at'], 'archived_by' => $moderator_id, 'reason' => $archive_reason]);
                        }
                        $stmt_delete = $pdo->prepare("DELETE FROM messages WHERE $column = ?");
                        $stmt_delete->execute([$id]);
                        $deleted_count = $stmt_delete->rowCount();
                    }

                    if ($deleted_count > 0) {
                        $clear_system_message = "Cleared " . $deleted_count . " message(s) from " . htmlspecialchars($target_username) . ".";
                        $pdo->prepare("INSERT INTO messages (username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?)")->execute([$_SESSION['username'], $_SESSION['color'] ?? '#FFFFFF', $clear_system_message, 1, $_SESSION['current_channel'] ?? 'general']);
                    }
                    break;
            }
        }
    }
    header('Location: chat.php');
    exit;
}
    // Handler for updating user profile settings
// Handler for updating user profile settings
    if (isset($_POST['update_profile'])) {
        if (isset($_SESSION['username'])) {
            // --- Color Update ---
            if (isset($_POST['new_color']) && preg_match('/^#([a-f0-9]{6}|[a-f0-9]{3})$/i', $_POST['new_color'])) {
                $_SESSION['color'] = $_POST['new_color'];
            }

            // --- Refresh Rate Update ---
            $allowed_rates = [5, 10, 15, 30, 60, 120];
            if (isset($_POST['new_refresh_rate']) && in_array((int)$_POST['new_refresh_rate'], $allowed_rates)) {
                $_SESSION['refresh_rate'] = (int)$_POST['new_refresh_rate'];
            }

            // --- Checkbox Updates ---
            $_SESSION['show_login_msgs'] = isset($_POST['show_login_msgs']) ? 1 : 0;
            $_SESSION['show_system_msgs'] = isset($_POST['show_system_msgs']) ? 1 : 0;
            // Add the new offline PM setting
            if (!($_SESSION['is_guest'] ?? true)) {
                 $_SESSION['allow_offline_pm'] = isset($_POST['allow_offline_pm']) ? 1 : 0;
            }
            // New: Handle visual effects toggle
            $_SESSION['user_enable_visual_effects_preference'] = isset($_POST['enable_visual_effects']) ? 1 : 0;


            // --- Combined Database Update ---
            // --- Combined Database Update ---
            if ($_SESSION['is_guest'] ?? false) {
                $stmt = $pdo->prepare("UPDATE guests SET color = ?, show_login_msgs = ?, show_system_msgs = ?, refresh_rate = ?, enable_visual_effects = ? WHERE id = ?");
                $stmt->execute([$_SESSION['color'], $_SESSION['show_login_msgs'], $_SESSION['show_system_msgs'], $_SESSION['refresh_rate'], $_SESSION['user_enable_visual_effects_preference'], $_SESSION['guest_id']]);
            } else {
                // NEW: Handle 'is_hidden' for members
                $is_hidden_from_form = 0;
                if (in_array(strtolower($_SESSION['user_role']), ['moderator', 'admin'])) {
                    $is_hidden_from_form = isset($_POST['is_hidden']) ? 1 : 0;
                    $_SESSION['is_hidden'] = $is_hidden_from_form;
                }
                // --- PGP Key Update ---
            $pgp_key = trim($_POST['pgp_public_key']) ?: null;
            // Basic validation: if a key is provided, it must contain the standard header.
            if ($pgp_key && strpos($pgp_key, '-----BEGIN PGP PUBLIC KEY BLOCK-----') === false) {
                 $_SESSION['profile_feedback'] = ['type' => 'error', 'message' => 'Invalid PGP Public Key format.'];
                 $pgp_key = null; // Do not save the invalid key
            } else {
                 $_SESSION['profile_feedback'] = ['type' => 'success', 'message' => 'Settings updated successfully.'];
            }

                $stmt = $pdo->prepare("UPDATE users SET color = ?, show_login_msgs = ?, show_system_msgs = ?, refresh_rate = ?, enable_visual_effects = ?, allow_offline_pm = ?, is_hidden = ?, pgp_public_key = ? WHERE id = ?");
                $stmt->execute([$_SESSION['color'], $_SESSION['show_login_msgs'], $_SESSION['show_system_msgs'], $_SESSION['refresh_rate'], $_SESSION['user_enable_visual_effects_preference'], $_SESSION['allow_offline_pm'], $is_hidden_from_form, $pgp_key, $_SESSION['user_id']]);
            }
        }
        header('Location: ?view=profile'); exit;
    }

    // Handler for changing password
    if (isset($_POST['change_password'])) {
        if (!($_SESSION['is_guest'] ?? true) && isset($_SESSION['user_id'])) {
            $current_pass = $_POST['current_password'] ?? '';
            $new_pass = $_POST['new_password'] ?? '';
            $confirm_pass = $_POST['confirm_password'] ?? '';

            if ($new_pass !== $confirm_pass) {
                $error_message = "New passwords do not match.";
            } elseif (empty($current_pass) || empty($new_pass)) {
                $error_message = "All password fields are required.";
            } else {
                $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user_hash = $stmt->fetchColumn();

                if ($user_hash && password_verify($current_pass, $user_hash)) {
                    // Current password is correct, proceed to update
                    $new_password_hash = password_hash($new_pass, PASSWORD_DEFAULT);
                    $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$new_password_hash, $_SESSION['user_id']]);
                    $_SESSION['profile_feedback'] = ['type' => 'success', 'message' => 'Password changed successfully.'];
                } else {
                    $_SESSION['profile_feedback'] = ['type' => 'error', 'message' => 'Incorrect current password.'];
                }
            }
        }
        if (!empty($error_message)) {
             $_SESSION['profile_feedback'] = ['type' => 'error', 'message' => $error_message];
        }
        header('Location: ?view=profile');
        exit;
    }

// Handler for guest joining
if (isset($_POST['join_guest'])) {
    $error_message = '';
    $user_ip = get_client_ip();
    $fingerprint = $_COOKIE['rotchat_fp'] ?? null;
    $username_from_form = trim($_POST['username']);
    
    // --- CAPTCHA VALIDATION ---
    $enable_login_captcha = ($settings['enable_login_captcha'] ?? '0') === '1';
    if ($enable_login_captcha) {
        $captcha_input = $_POST['captcha'] ?? '';
        $captcha_correct = $_SESSION['captcha_string'] ?? 'INVALID_CAPTCHA_STRING';
        unset($_SESSION['captcha_string']);
        if (strcasecmp($captcha_input, $captcha_correct) !== 0) {
            $error_message = "The text from the image was entered incorrectly.";
        }
    }

    if (empty($error_message)) {
        // --- 1. PRE-LOGIN CHECKS (Bans, Cooldowns, etc.) ---
        if (empty($username_from_form)) {
            $error_message = "A username is required.";
        } elseif (strlen($username_from_form) > 20) {
            $error_message = "Guest name cannot exceed 20 characters.";
        } else {
            // Check for banned words in the name
            $banned_name_words_str = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'banned_name_words_list'")->fetchColumn() ?: '';
            if ($banned_name_words_str) {
                $normalized_username = preg_replace('/[^a-zA-Z0-9]/', '', $username_from_form);
                foreach (explode(',', $banned_name_words_str) as $word) {
                    if (trim($word) !== '' && stripos($normalized_username, trim($word)) !== false) {
                        $error_message = "This username contains a forbidden word.";
                        break;
                    }
                }
            }

            // Check if it's a registered member's name
            if (empty($error_message)) {
                $stmt_user = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                $stmt_user->execute([$username_from_form]);
                if ($stmt_user->fetch()) {
                    $error_message = "This name is registered. Please <a href='?view=login'>log in</a>.";
                }
            }

            // Check if it's a permanently banned guest name
            if (empty($error_message)) {
                $stmt_banned_name = $pdo->prepare("SELECT id FROM banned_guest_names WHERE username = ?");
                $stmt_banned_name->execute([$username_from_form]);
                if ($stmt_banned_name->fetch()) {
                    $error_message = "That username has been permanently banned.";
                }
            }

            // *** NEW FIX ***: Check if a historical guest record with this name already exists
            if (empty($error_message)) {
                $stmt_guest_exists = $pdo->prepare("SELECT id FROM guests WHERE username = ?");
                $stmt_guest_exists->execute([$username_from_form]);
                if ($stmt_guest_exists->fetch()) {
                    $error_message = "That guest name has been used before. Please choose another.";
                }
            }
        }

        // --- 2. IF USERNAME IS VALID, CHECK LOCKS AND ATTEMPT LOGIN/CREATION ---
        if (empty($error_message)) {
            $lock_level_setting = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'chat_locked'")->fetchColumn() ?: 'unlocked';
            $lock_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];
            $is_locked_for_guests = false;
            if ($lock_level_setting !== 'unlocked') {
                if ($lock_level_setting === 'all' || (isset($lock_hierarchy[$lock_level_setting]) && $lock_hierarchy['guest'] <= $lock_hierarchy[$lock_level_setting])) {
                    $is_locked_for_guests = true;
                }
            }
            if ($is_locked_for_guests) {
                $error_message = 'The chat is currently locked for guests. Please try again later.';
            } else {
                $stmt_session = $pdo->prepare("SELECT session_id FROM sessions WHERE username = ? AND is_guest = 1");
                $stmt_session->execute([$username_from_form]);
                if ($stmt_session->fetch()) {
                    $error_message = "That guest name is currently in use by an active session.";
                } else {
                    $token_setting_stmt = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'guest_default_tokens'");
                    $default_tokens = (int)($token_setting_stmt->fetchColumn() ?: 50);
                    $guest_color = getRandomColor();
                    $pdo->prepare("INSERT INTO guests (username, color, fingerprint, last_login_ip, message_limit) VALUES (?, ?, ?, ?, ?)")->execute([$username_from_form, $guest_color, $fingerprint, $user_ip, $default_tokens]);
                    $guest_id = $pdo->lastInsertId();
                    $_SESSION['is_guest'] = true;
                    $_SESSION['guest_id'] = $guest_id;
                    $_SESSION['username'] = $username_from_form;
                    $_SESSION['session_id'] = session_id();
                    $_SESSION['current_channel'] = 'general';
                    $_SESSION['color'] = $guest_color;
                    $_SESSION['show_login_msgs'] = 0;
                    $_SESSION['show_system_msgs'] = 1;
                    $_SESSION['refresh_rate'] = 5;
                    header('Location: ' . $_SERVER['PHP_SELF']);
                    exit;
                }
            }
        }
    }
    if (!empty($error_message)) { $_SESSION['login_cooldown_until'] = time() + 5; }
}


// Handler for member login
if (isset($_POST['login'])) {
    $enable_login_captcha = ($settings['enable_login_captcha'] ?? '0') === '1';
    $fingerprint = $_COOKIE['rotchat_fp'] ?? null;
    $error_message = '';
    $view = 'login'; // Default view on error

    if ($enable_login_captcha) {
        $captcha_input = $_POST['captcha'] ?? '';
        $captcha_correct = $_SESSION['captcha_string'] ?? 'INVALID_CAPTCHA_TOKEN';
        unset($_SESSION['captcha_string']);
        if (strcasecmp($captcha_input, $captcha_correct) !== 0) {
            $error_message = "The text from the image was entered incorrectly.";
        }
    }

    // --- FINGERPRINT BAN CHECK ---
    if (empty($error_message) && $fingerprint) {
        $ban_check_stmt = $pdo->prepare("SELECT reason FROM ban_list WHERE ban_type = 'fingerprint' AND ban_value = ?");
        $ban_check_stmt->execute([$fingerprint]);
        if ($ban_reason = $ban_check_stmt->fetchColumn()) {
            $error_message = "Your device has been banned. Reason: " . htmlspecialchars($ban_reason);
        }
    }

    if (empty($error_message)) {
        $username = trim($_POST['username']);
        $password = $_POST['password'];
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);

        if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $login_success = false;
            if ($user['password_hash'] && password_verify($password, $user['password_hash'])) {
                $login_success = true;
            } elseif (!empty($user['promoted_temp_pass']) && $password === $user['promoted_temp_pass']) {
                $login_success = true;
                $new_password_hash = password_hash($password, PASSWORD_DEFAULT);
                $pdo->prepare("UPDATE users SET password_hash = ?, promoted_temp_pass = NULL WHERE id = ?")->execute([$new_password_hash, $user['id']]);
            }

            if ($login_success) {
                if ($user['is_banned']) {
                    render_kick_page('This account has been banned.');
                    exit;
                }
                $lock_level_setting = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'chat_locked'")->fetchColumn() ?: 'unlocked';
                $user_role_for_lock_check = strtolower($user['role']);
                $is_locked_for_user = false;
                if ($lock_level_setting !== 'unlocked' && $user_role_for_lock_check !== 'admin') {
                    $lock_hierarchy = ['guest' => 0, 'user' => 1, 'trusted' => 2, 'moderator' => 3, 'admin' => 4];
                    $user_level = $lock_hierarchy[$user_role_for_lock_check];
                    if ($lock_level_setting === 'all' || (isset($lock_hierarchy[$lock_level_setting]) && $user_level <= $lock_hierarchy[$lock_level_setting])) {
                        $is_locked_for_user = true;
                    }
                }
                if ($is_locked_for_user) {
                    $error_message = "The chat is currently locked for your user role. Please try again later.";
                } elseif (!empty($user['kick_cooldown_until']) && strtotime($user['kick_cooldown_until']) > time()) {
                    $remaining_seconds = strtotime($user['kick_cooldown_until']) - time();
                    $error_message = "Your account is on a cooldown. Please wait " . ceil($remaining_seconds / 60) . " more minute(s).";
                } elseif ($user['is_deactivated']) {
                    $error_message = "This account has been deactivated.";
                } else {
                    $stmt_session = $pdo->prepare("SELECT session_id FROM sessions WHERE username = ?");
                    $stmt_session->execute([$user['username']]);
                    if ($stmt_session->fetch()) {
                        $error_message = "This account is already logged in.";
                    } else {
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['user_role'] = $user['role'];
                        $_SESSION['is_guest'] = false;
                        $_SESSION['current_channel'] = 'general';
                        $_SESSION['session_id'] = session_id();
                        $_SESSION['show_login_msgs'] = $user['show_login_msgs'];
                        $_SESSION['show_system_msgs'] = $user['show_system_msgs'];
                        $_SESSION['color'] = $user['color'];
                        $_SESSION['refresh_rate'] = $user['refresh_rate'] ?? 5;
                        $user_ip = get_client_ip();
                        $pdo->prepare("UPDATE users SET last_login_ip = ? WHERE id = ?")->execute([$user_ip, $user['id']]);
                        if ($user['show_login_msgs']) {
                           $pdo->prepare("INSERT INTO messages (user_id, username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?, ?)")->execute([$user['id'], $user['username'], $_SESSION['color'], "has logged in.", 1, 'general']);
                        }
                        
                        // Set the "last seen" time for all channels to now, preventing old notifications
                        $_SESSION['last_channel_activity_messages_frame'] = [];
                        $all_channels_stmt = $pdo->query("SELECT name FROM channels");
                        foreach ($all_channels_stmt->fetchAll(PDO::FETCH_COLUMN) as $channel_name) {
                            $_SESSION['last_channel_activity_messages_frame'][$channel_name] = time();
                        }

                        header('Location: ' . $_SERVER['PHP_SELF']);
                        exit;
                    }
                }
            }
        }
    }
    if (empty($error_message)) {
        $error_message = "Invalid username or password.";
    }
}
// Handler for logout
if (isset($_POST['logout'])) {
    $redirect_target = $_POST['redirect_target'] ?? null;

    // --- NEW: Guest Promotion Cleanup ---
    if (($_SESSION['is_guest'] ?? false) && isset($_SESSION['guest_id'])) {
        $promo_check_stmt = $pdo->prepare("SELECT promoted_temp_pass FROM sessions WHERE session_id = ?");
        $promo_check_stmt->execute([session_id()]);
        if ($promo_check_stmt->fetchColumn()) {
            $pdo->prepare("DELETE FROM guests WHERE id = ?")->execute([$_SESSION['guest_id']]);
        }
    }
    // --- END OF NEW LOGIC ---

    if (!($_SESSION['is_guest'] ?? true)) {
        // --- NEW: Update last_seen timestamp on logout ---
        $pdo->prepare("UPDATE users SET last_seen = NOW() WHERE id = ?")->execute([$_SESSION['user_id']]);
        
        $stmt = $pdo->prepare("SELECT color, show_login_msgs FROM users WHERE id = ?"); $stmt->execute([$_SESSION['user_id']]);
        if (($user_data = $stmt->fetch(PDO::FETCH_ASSOC)) && $user_data['show_login_msgs']) {
            $pdo->prepare("INSERT INTO messages (user_id, username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?, ?)")->execute([$_SESSION['user_id'], $_SESSION['username'], $user_data['color'], "has left the chat.", 1, $_SESSION['current_channel'] ?? 'general']);
        }
    } else {
        $stmt = $pdo->prepare("SELECT color, show_login_msgs FROM guests WHERE id = ?"); $stmt->execute([$_SESSION['guest_id']]);
        if (($guest_data = $stmt->fetch(PDO::FETCH_ASSOC)) && ($guest_data['show_login_msgs'] ?? 0)) {
            $pdo->prepare("INSERT INTO messages (guest_id, username, color, message, is_system_message, channel) VALUES (?, ?, ?, ?, ?, ?)")->execute([$_SESSION['guest_id'], $_SESSION['username'], $guest_data['color'], "has left the chat.", 1, $_SESSION['current_channel'] ?? 'general']);
        }
    }
    $pdo->prepare("DELETE FROM sessions WHERE session_id = ?")->execute([session_id()]);
    session_destroy();

    if ($redirect_target === 'login') {
        header('Location: chat.php?view=login');
    } else {
        header('Location: ' . $_SERVER['PHP_SELF']);
    }
    exit;
}
    

// Handler for registration
if (isset($_POST['register'])) {
    // Check if registration is locked (token mode)
    $registration_lock_stmt = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'registration_locked'");
    $is_registration_locked = $registration_lock_stmt->fetchColumn() === '1';

    // --- Captcha Validation ---
    $enable_login_captcha = ($settings['enable_login_captcha'] ?? '0') === '1';
    if ($enable_login_captcha) {
        $captcha_input = $_POST['captcha'] ?? '';
        $captcha_correct = $_SESSION['captcha_string'] ?? 'INVALID';
        unset($_SESSION['captcha_string']);
        if (strcasecmp($captcha_input, $captcha_correct) !== 0) {
            $error_message = "The text from the image was entered incorrectly.";
            $view = 'register';
        }
    }
    
    if (empty($error_message)) {
        // --- TOKEN-BASED REGISTRATION LOGIC ---
        if ($is_registration_locked) {
            $username = trim($_POST['username']);
            $password = $_POST['password'];
            $token = trim($_POST['token']);

            if (empty($username) || empty($password) || empty($token)) {
                $error_message = "Username, password, and token are required.";
                $view = 'register';
            } else {
                // Check if the chosen username is already taken by an active user
                $stmt_user_check = $pdo->prepare("SELECT id FROM users WHERE username = ? AND password_hash IS NOT NULL");
                $stmt_user_check->execute([$username]);
                if ($stmt_user_check->fetch()) {
                    $error_message = "That username is already taken.";
                    $view = 'register';
                } else {
                    // Find the unclaimed account record by its token
                    $stmt_token = $pdo->prepare("SELECT id FROM users WHERE registration_token = ? AND password_hash IS NULL");
                    $stmt_token->execute([$token]);
                    if ($unclaimed_user = $stmt_token->fetch()) {
                        // Token is valid, claim the account
                        $password_hash = password_hash($password, PASSWORD_DEFAULT);
                        $user_color = getRandomColor();
                        // Update the placeholder record with the new user's details
                        $update_stmt = $pdo->prepare("UPDATE users SET username = ?, password_hash = ?, color = ?, registration_token = NULL WHERE id = ?");
                        $update_stmt->execute([$username, $password_hash, $user_color, $unclaimed_user['id']]);
                        
                        header('Location: ?view=login&registered=1');
                        exit;
                    } else {
                        $error_message = "The registration token is invalid or has already been used.";
                        $view = 'register';
                    }
                }
            }
        } 
        // --- OPEN REGISTRATION LOGIC ---
        else {
            $username = trim($_POST['username']);
            $password = $_POST['password'];
            if (!empty($username) && !empty($password)) {
                if (strlen($username) > 20) {
                    $error_message = "Username cannot exceed 20 characters."; $view = 'register';
                } else {
                    $banned_name_words_str = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'banned_name_words_list'")->fetchColumn() ?: '';
                    if ($banned_name_words_str) {
                        $normalized_username = preg_replace('/[^a-zA-Z0-9]/', '', $username);
                        foreach (explode(',', $banned_name_words_str) as $word) {
                            if (trim($word) !== '' && stripos($normalized_username, trim($word)) !== false) {
                                $error_message = "This username contains a forbidden word.";
                                $view = 'register';
                                break;
                            }
                        }
                    }
                    if (empty($error_message)) {
                        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                        $stmt->execute([$username]);
                        if ($stmt->fetch()) {
                            $error_message = "Username is already taken."; $view = 'register';
                        } else {
                            $password_hash = password_hash($password, PASSWORD_DEFAULT);
                            $user_color = getRandomColor();
                            $pdo->prepare("INSERT INTO users (username, password_hash, role, color) VALUES (?, ?, ?, ?)")->execute([$username, $password_hash, 'user', $user_color]);
                            header('Location: ?view=login&registered=1'); exit;
                        }
                    }
                }
            } else {
                $error_message = "Username and password are required."; $view = 'register';
            }
        }
    }
}
}

// --- Session Persistence & Activity Update ---
if (isset($_SESSION['session_id'])) {
    // --- NEW: Session Validation Check ---
    // Before updating a session, we must verify the user/guest still exists in the database.
    $is_session_valid = false;
    if (isset($_SESSION['is_guest']) && $_SESSION['is_guest'] === true) {
        // For guests, check if their record still exists in the guests table.
        $stmt = $pdo->prepare("SELECT id FROM guests WHERE id = ?");
        $stmt->execute([$_SESSION['guest_id'] ?? 0]);
        if ($stmt->fetch()) {
            $is_session_valid = true;
        }
    } else {
        // For members, check if their record still exists in the users table.
        $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id'] ?? 0]);
        if ($stmt->fetch()) {
            $is_session_valid = true;
        }
    }

    if ($is_session_valid) {
        // Session is valid, proceed with updating or inserting it.
        // THIS IS THE CORRECTED SQL QUERY BLOCK
        $sql = "INSERT INTO sessions (session_id, user_id, guest_id, username, is_guest, last_active)
                VALUES (?, ?, ?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE 
                    last_active = NOW(),
                    user_id = VALUES(user_id),
                    guest_id = VALUES(guest_id),
                    username = VALUES(username),
                    is_guest = VALUES(is_guest)";
        
        $pdo->prepare($sql)->execute([
            $_SESSION['session_id'],
            $_SESSION['user_id'] ?? null,
            $_SESSION['guest_id'] ?? null,
            $_SESSION['username'],
            (int)($_SESSION['is_guest'] ?? 0)
        ]);
        // END OF CORRECTED BLOCK
    } else {
        // Session is INVALID (user/guest was deleted). Destroy it and force a reload.
        session_destroy();
        header("Location: chat.php");
        exit();
    }
}

// Efficiently clear expired sessions on every run.
// --- NEW: Update last_seen for members before clearing their session ---
$stmt_expired = $pdo->prepare("SELECT user_id FROM sessions WHERE is_guest = 0 AND last_active < NOW() - INTERVAL ? SECOND");
$stmt_expired->execute([$session_timeout]);
$expired_user_ids = $stmt_expired->fetchAll(PDO::FETCH_COLUMN);
if (!empty($expired_user_ids)) {
    $placeholders = implode(',', array_fill(0, count($expired_user_ids), '?'));
    $pdo->prepare("UPDATE users SET last_seen = NOW() WHERE id IN ($placeholders)")->execute($expired_user_ids);
}
$pdo->prepare("DELETE FROM sessions WHERE last_active < NOW() - INTERVAL ? SECOND")->execute([$session_timeout]);

$error_message = $error_message ?? '';

// --- View Router ---
switch ($view) {
    // The 'terminated' view is now handled by render_kick_page directly.

case 'messages':
    // --- CRITICAL: Session Validation ---
    // This is the primary fix for the security flaw. If there is no active session,
    // immediately stop rendering the frame. This prevents unauthenticated viewing.
    if (!isset($_SESSION['session_id'])) {
        // Output a blank page to prevent iframe errors.
        echo '<!DOCTYPE html><html><body style="background-color: transparent;"></body></html>';
        exit;
    }

    // --- Shadow Kick Enforcement ---
    // This check now correctly runs only if a session is confirmed to exist.
    $shadow_stmt = $pdo->prepare("SELECT is_shadow_kicked FROM sessions WHERE session_id = ?");
    $shadow_stmt->execute([$_SESSION['session_id']]);
    if ($shadow_stmt->fetchColumn() == 1) {
        exit; // Silently stop rendering messages for this user
    }

    // --- Build a comprehensive list of ALL known users and their colors (FIXED ORDER) ---
    // This is placed at the top of the case to ensure the variable exists before the function is defined.
    $all_known_user_colors = [];
    // 1. Get all registered users and their colors
    $users_stmt = $pdo->query("SELECT LOWER(username) as username, color FROM users");
    foreach ($users_stmt as $user_row) {
        $all_known_user_colors[$user_row['username']] = $user_row['color'];
    }
    // 2. Get all guests and their colors, overriding only if the name isn't already a registered user
    $guests_stmt = $pdo->query("SELECT LOWER(username) as username, color FROM guests");
    foreach ($guests_stmt as $guest_row) {
        if (!isset($all_known_user_colors[$guest_row['username']])) {
            $all_known_user_colors[$guest_row['username']] = $guest_row['color'];
        }
    }

    // If kicked_info is set, output a prominent session termination message
    // within this iframe, hiding the chat content.
    if ($kicked_info !== null) {
        echo '<!DOCTYPE html><html><head><style>
            body { background-color: #1a1a1a; margin:0; display:flex; flex-direction: column; justify-content:center; align-items:center; height: 100vh; color:#ffc2c2; font-family: \'Roboto\', sans-serif; font-size: 1.1em; text-align: center; padding: 20px; box-sizing: border-box; }
            h2 { color: #ff3333; font-family: \'Courier Prime\', monospace; margin-top: 0; margin-bottom: 15px; text-transform: uppercase; letter-spacing: 1px; }
            p { background-color: #4d0000; color: #ffc2c2; padding: 15px; border-radius: 5px; border: 1px solid #990000; font-size: 1em; line-height: 1.4; word-wrap: break-word; margin-bottom: 20px; }
            a { color: #ff8888; text-decoration: none; font-weight: bold; padding: 8px 15px; background-color: #333; border: 1px solid #555; border-radius: 5px; transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease; }
            a:hover { background-color: #555; border-color: #ff5555; color: #fff; }
        </style></head><body>
            <h2>SESSION TERMINATED</h2>
            <p>' . htmlspecialchars($kicked_info) . '</p>
            <a href="chat.php" target="_top">Return to Login</a>
        </body></html>';
        exit; // Stop further rendering for this iframe
    }


    /**
 * Turn "#foo" or [channel]foo[/channel] into a safe <a> link.
 */


// THIS ENTIRE BLOCK REPLACES BOTH the renderChannelLink helper and process_all_bbcode functions.
if (!function_exists('process_all_bbcode')) {
    function process_all_bbcode($text, $all_known_user_colors, $user_role_level, $role_hierarchy, $csrf_token) {
        global $pdo;

        // 1. Fetch all channels, keying by lowercase name
        $available_channels = [];
        try {
            $stmt = $pdo->query("SELECT name, topic, min_role FROM channels");
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $key = strtolower($row['name']);
                $available_channels[$key] = [
                    'name'     => $row['name'],   // preserve original case for display
                    'topic'    => $row['topic'],
                    'min_role' => $row['min_role']
                ];
            }
        } catch (PDOException $e) {
            // fallback to at least general
            $available_channels['general'] = [
                'name'     => 'general',
                'topic'    => '',
                'min_role' => 'guest'
            ];
        }

        // === BBCode: [list]…[/list] and [*] item tags ===
// 1) wrap the whole list in <ul>…</ul>
$text = preg_replace(
  '/\[list\](.*?)\[\/list\]/is',
  '<ul>$1</ul>',
  $text
);

// 2) turn each [*]… into <li>…</li>
//    (we use lookahead so that consecutive [*]s each become list items)
$text = preg_replace(
  '/\[\*\](.*?)((?=\[\*)|(?=<\/ul>))/is',
  '<li>$1</li>',
  $text
);


        // 2. Auto-wrap raw #channel into a BB-tag for processing (avoid double-wrapping)
        $text = preg_replace(
            '/(?<!\[channel\]|\[#channel\]|href="|src=")#([A-Za-z0-9_-]+)/',
            '[channel]$1[/channel]',
            $text
        );

        // 3. Process the [channel] BBCode tag
        $text = preg_replace_callback(
            '/\[channel\]([A-Za-z0-9_-]+)\[\/channel\]/i',
            function (array $matches) use ($available_channels, $user_role_level, $role_hierarchy, $csrf_token) {
                $chanKey = strtolower($matches[1]);

                // A. If channel doesn't exist, render plain text
                if (!isset($available_channels[$chanKey])) {
                    return htmlspecialchars('#'.$matches[1], ENT_QUOTES, 'UTF-8');
                }

                $channel = $available_channels[$chanKey];
                $required_level = $role_hierarchy[$channel['min_role']] ?? PHP_INT_MAX;

                // B. If user lacks permission, render plain text
                if ($user_role_level < $required_level) {
                    return htmlspecialchars('#'.$channel['name'], ENT_QUOTES, 'UTF-8');
                }

                // C. Otherwise build the clickable link (always, even for current channel)
                $href = 'chat.php?switch_channel=1'
                      . '&channel='    . urlencode($chanKey)
                      . '&csrf_token=' . urlencode($csrf_token);

                return '<a href="' . $href . '" class="inline-channel-link" target="_top">'
                     . '#' . htmlspecialchars($channel['name'], ENT_QUOTES, 'UTF-8')
                     . '</a>';
            },
            $text
        );

        // 4. Process standalone URLs (unchanged)
        $text = preg_replace_callback(
            '/(?<!href="|src="|channel\])\b((https?:\/\/|www\.)[^\s<>()]+)/i',
            function ($matches) {
                $url = $matches[1];
                $href = stripos($url, 'www.') === 0 ? 'http://' . $url : $url;
                return '<a href="' . htmlspecialchars($href, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener noreferrer" class="bblink">'
                     . htmlspecialchars($url, ENT_QUOTES, 'UTF-8')
                     . '</a>';
            },
            $text
        );

        // 5. Process @mentions (unchanged)
        $text = preg_replace_callback(
            '/@([\w.]+)/',
            function ($matches) use ($all_known_user_colors) {
                $user = strtolower($matches[1]);
                if (isset($all_known_user_colors[$user]) && function_exists('hexToRgba')) {
                    $color   = $all_known_user_colors[$user];
                    $rgba_bg = hexToRgba($color, 0.2);
                    return '<span class="mention" style="color: '.$color.'; background-color: '.$rgba_bg.'; font-weight:bold; padding:1px 3px; border-radius:3px;">'
                         . htmlspecialchars($matches[0], ENT_QUOTES, 'UTF-8')
                         . '</span>';
                }
                return htmlspecialchars($matches[0], ENT_QUOTES, 'UTF-8');
            },
            $text
        );

        return $text;
    }
}

    ?>
    <!DOCTYPE html><html><head><meta http-equiv="refresh" content="<?php echo (int)($_SESSION['refresh_rate'] ?? 5); ?>"><link rel="stylesheet" href="style.css"></head><body class="frame-body">
        <?php
        // --- Channel Activity Tracking for messages iframe ---
        // Initialize the tracking array if it doesn't exist.
        if (!isset($_SESSION['last_channel_activity_messages_frame'])) {
            $_SESSION['last_channel_activity_messages_frame'] = [];
        }
        // Only update the timestamp for the channel we are CURRENTLY viewing.
        $current_channel_for_tracking = $_SESSION['current_channel'] ?? 'general';
        $_SESSION['last_channel_activity_messages_frame'][$current_channel_for_tracking] = time();

        $unread_channels_info_in_messages_frame = [];
        if (isset($_SESSION['username'])) {
            $user_role_name_for_check = ($_SESSION['is_guest'] ?? true) ? 'guest' : strtolower($_SESSION['user_role'] ?? 'user');
            $user_role_level_for_check = $role_hierarchy[$user_role_name_for_check] ?? 0;
            foreach ($channels as $channel_key => $channel_data) {
                if ($user_role_level_for_check >= $role_hierarchy[$channel_data['min_role']]) {
                    if (($channel_key !== ($_SESSION['current_channel'] ?? 'general'))) {
                        $latest_msg_stmt = $pdo->prepare("SELECT MAX(created_at) FROM messages WHERE channel = ?");
                        $latest_msg_stmt->execute([$channel_key]);
                        $latest_message_timestamp_str = $latest_msg_stmt->fetchColumn();
                        $latest_message_timestamp = $latest_message_timestamp_str ? strtotime($latest_message_timestamp_str) : 0;
                        $last_seen_channel_timestamp_for_messages_frame = $_SESSION['last_channel_activity_messages_frame'][$channel_key] ?? 0;
                        if ($latest_message_timestamp > $last_seen_channel_timestamp_for_messages_frame) {
                            $unread_channels_info_in_messages_frame[$channel_key] = $channel_data['display'];
                        }
                    }
                }
            }
        }
        ?>

        <?php
        // Fetch the current channel's topic
        $current_channel_name_for_topic = $_SESSION['current_channel'] ?? 'general';
        $current_channel_topic = $channels[$current_channel_name_for_topic]['topic'] ?? '';
        ?>

        <?php if (!empty($current_channel_topic)): ?>
            <div class="channel-topic-bar">
                Topic: <span class="topic-text"><?php echo htmlspecialchars($current_channel_topic); ?></span>
            </div>
        <?php endif; ?>

        <?php if (isset($_SESSION['username']) && !empty($unread_channels_info_in_messages_frame)): ?>
            <div class="notification-bar messages-frame-notification">
                New messages in:
                <?php foreach ($unread_channels_info_in_messages_frame as $ch_key => $ch_display): ?>
                    <form method="post" action="chat.php" target="_top" class="inline-notification-form">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="hidden" name="channel" value="<?php echo htmlspecialchars($ch_key); ?>">
                        <button type="submit" name="switch_channel" class="notification-link">
                            <?php echo htmlspecialchars($ch_display); ?>
                        </button>
                    </form>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <div class="chat-messages">
            <?php
            $system_message_level_stmt = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'system_message_level'");
            $system_message_level = $system_message_level_stmt->fetchColumn() ?: 'all';
            $current_user_show_system_msgs_setting = $_SESSION['show_system_msgs'] ?? 0;
            $ignored_list = $_SESSION['ignored_users'] ?? [];

            // --- FIX: Define user role level variable to prevent warnings ---
            $user_role_name_for_check = ($_SESSION['is_guest'] ?? true) ? 'guest' : strtolower($_SESSION['user_role'] ?? 'guest');
            $user_role_level_for_check = $role_hierarchy[$user_role_name_for_check] ?? 0;
            // --- END OF FIX ---

            $sql_conditions = [];
            $sql_params = [':channel' => $_SESSION['current_channel'] ?? 'general'];
            $sql_conditions[] = "m.channel = :channel";
            if (!($current_user_show_system_msgs_setting)) { $sql_conditions[] = "m.is_system_message = 0"; }
            else { if ($system_message_level == 'none') { $sql_conditions[] = "m.is_system_message = 0"; } elseif ($system_message_level == 'members') { $sql_conditions[] = "(m.is_system_message = 0 OR m.user_id IS NOT NULL)"; } elseif ($system_message_level == 'mods') { $sql_conditions[] = "(m.is_system_message = 0 OR (m.user_id IS NOT NULL AND u.role IN ('moderator', 'admin')))"; } }

            // Fetch the chat history limit from the database settings
            $history_limit_stmt = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'chat_history_limit'");
            $chat_history_limit = (int)($history_limit_stmt->fetchColumn() ?: 150); // Fallback to 150 if not set

            $sql = "SELECT m.*, s.is_guest, s.user_id AS session_user_id, s.guest_id AS session_guest_id, s.session_id, u.role AS user_role, u.custom_css, m.created_at, u.message_count FROM messages m LEFT JOIN sessions s ON ((m.guest_id IS NOT NULL AND m.guest_id = s.guest_id AND s.is_guest = 1) OR (m.user_id IS NOT NULL AND m.user_id = s.user_id AND s.is_guest = 0)) LEFT JOIN users u ON m.user_id = u.id " . (count($sql_conditions) > 0 ? "WHERE " . implode(" AND ", $sql_conditions) : "") . " ORDER BY m.created_at DESC LIMIT " . $chat_history_limit;

            $stmt = $pdo->prepare($sql); $stmt->execute($sql_params); $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
            $image_modals_to_render = []; // Array to hold modal HTML


foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $msg) {
    // --- FIXED WHISPER DISPLAY LOGIC ---
    // This logic now correctly parses the message content for the [WHISPER] tag.
    if (preg_match('/\[WHISPER to:(.*?)\](.*)\[\/WHISPER\]/s', $msg['message'], $matches)) {
        $recipient_username = $matches[1];
        $whisper_content = trim($matches[2]);
        $current_user = $_SESSION['username'];
        $sender_username = $msg['username'];

        // If the current user is NEITHER the sender NOR the recipient, skip this message entirely.
        // THIS IS THE FIX: Use case-insensitive comparison to match usernames like "Guest" and "guest".
        if (strcasecmp($current_user, $sender_username) != 0 && strcasecmp($current_user, $recipient_username) != 0) {
            continue;
        }

        // The user is involved, so format the message for display.
        $msg['is_system_message'] = true; // Use system message styling for whispers.
        $msg['color'] = '#e0b0ff'; // A distinct color for whispers.
        
        if ($current_user === $sender_username) {
            // Format for the sender: "To [Recipient]: message"
            $msg['username'] = "Whisper";
            $msg['message'] = "(to " . htmlspecialchars($recipient_username) . "): " . htmlspecialchars($whisper_content);
        } else {
            // Format for the recipient: "From [Sender]: message"
            $msg['username'] = "Whisper";
            $msg['message'] = "(from " . htmlspecialchars($sender_username) . "): " . htmlspecialchars($whisper_content);
        }
    }
    // --- END OF WHISPER LOGIC ---

    // Determine the unique identifier for the message author (for ignoring)
    $author_identifier = !is_null($msg['guest_id']) ? 'g_' . $msg['guest_id'] : 'u_' . $msg['user_id'];
    if (!$msg['is_system_message'] && in_array($author_identifier, $ignored_list)) {
        continue; // Skip rendering ignored users' messages
    }

    echo "<div class='msg-line" . ($msg['is_system_message'] ? " system" : "") . "'>";
    echo "<small>" . date('H:i', strtotime($msg['created_at'])) . "</small>";

    // --- NEW, UNIFIED DELETE BUTTON LOGIC ---
    $can_delete_message = false;
    $is_own_message = isset($_SESSION['user_id']) && !is_null($msg['user_id']) && (int)$msg['user_id'] === (int)$_SESSION['user_id'];

    if (!$msg['is_system_message']) {
        $target_role = !is_null($msg['user_id']) ? strtolower($msg['user_role'] ?? 'user') : 'guest';
        $actor_level = $role_hierarchy[$actor_role] ?? 0;
        $target_level = $role_hierarchy[$target_role] ?? 0;
        
        $roles_delete_any = array_filter(array_map('trim', explode(',', $settings['roles_delete_any'] ?? '')));
        $roles_delete_own = array_filter(array_map('trim', explode(',', $settings['roles_delete_own'] ?? '')));
        $trusted_delete_mode = $settings['trusted_delete_mode'] ?? 'own';

        // Check permissions with hierarchy
        if (in_array($actor_role, $roles_delete_any) && $actor_level > $target_level) {
            $can_delete_message = true;
        } elseif ($actor_role === 'trusted' && $trusted_delete_mode === 'all' && $actor_level > $target_level) {
            $can_delete_message = true;
        } elseif ($is_own_message && in_array($actor_role, $roles_delete_own)) {
            $can_delete_message = true;
        }
    }

    if ($can_delete_message) {
        echo "<form method='post' action='?view=messages' class='delete-msg-form'><input type='hidden' name='delete_message' value='1'><input type='hidden' name='message_id' value='{$msg['id']}'><input type='hidden' name='csrf_token' value='{$_SESSION['csrf_token']}'><button type='submit' title='Delete'>❌</button></form>";
    }

    // Reply button
    if (!$msg['is_system_message']) {
        echo "<a href='?view=input&reply_to_id={$msg['id']}' target='input' class='reply-link' title='Reply'>↩️</a>";
    }

    // --- Message Content Rendering ---
    if ($msg['is_system_message']) {
        echo "<em><strong style='color:{$msg['color']}'>" . htmlspecialchars($msg['username'], ENT_QUOTES, 'UTF-8') . "</strong> " . $msg['message'] . "</em>";
    } else {
        // --- START: UNIFIED ROLE AND RANK ICON LOGIC ---
        $rank_icon_html = ''; // Initialize as empty string
        $role_icon = '';

        if (!is_null($msg['user_id'])) { // It's a Member
            // First, determine the rank icon based on message count
            $count = (int)($msg['message_count'] ?? 0);
            $rank_icon = '·'; // Default icon
            $rank_title = 'Rank 1'; // Default title
            if ($count >= 5000) { $rank_icon = '🂡'; $rank_title = 'Rank 10: Ace of Spades'; }
            elseif ($count >= 2500) { $rank_icon = '♠'; $rank_title = 'Rank 9: Spade'; }
            elseif ($count >= 1500) { $rank_icon = '♤'; $rank_title = 'Rank 8: Open Spade'; }
            elseif ($count >= 1000) { $rank_icon = '♥'; $rank_title = 'Rank 7: Heart'; }
            elseif ($count >= 750) { $rank_icon = '♡'; $rank_title = 'Rank 6: Open Heart'; }
            elseif ($count >= 500) { $rank_icon = '♦'; $rank_title = 'Rank 5: Diamond'; }
            elseif ($count >= 250) { $rank_icon = '♢'; $rank_title = 'Rank 4: Open Diamond'; }
            elseif ($count >= 100) { $rank_icon = '♣'; $rank_title = 'Rank 3: Club'; }
            elseif ($count >= 50) { $rank_icon = '♧'; $rank_title = 'Rank 2: Open Club'; }
            
            // *** NEW: Create the rank icon HTML with the message count in the title attribute ***
            $rank_icon_html = "<span title='{$rank_title} | Messages: {$count}'>{$rank_icon}</span>";

            // Second, determine the role icon
            $user_role = strtolower($msg['user_role'] ?? 'user');
            switch ($user_role) {
                case 'admin':     $role_icon = '🧛'; break;
                case 'moderator': $role_icon = '🛡️'; break;
                case 'trusted':   $role_icon = '💎'; break;
                case 'user':      $role_icon = '⚡'; break;
            }
        } else { // It's a Guest
            $role_icon = '👹';
        }
        // Combine the rank and role icons
        $combined_icon = $rank_icon_html . $role_icon;
        // --- END: UNIFIED ROLE AND RANK ICON LOGIC ---

// Style and moderation link for username
$raw_custom_style = !is_null($msg['user_id']) && !empty($msg['custom_css']) ? $msg['custom_css'] : '';
$class_str = '';
$inline_style_str = '';

if (!empty($raw_custom_style)) {
    // --- NEW: Robustly parse class and inline styles ---
    $style_parts = explode(';', $raw_custom_style);
    $other_styles = [];

    foreach ($style_parts as $part) {
        $part = trim($part);
        if (stripos($part, 'class:') === 0) {
            // This is the class definition
            $class_str = htmlspecialchars(trim(substr($part, 6)));
        } elseif (!empty($part)) {
            // This is another inline style
            $other_styles[] = $part;
        }
    }
    
    // Reassemble the remaining inline styles
    if (!empty($other_styles)) {
        $inline_style_str = htmlspecialchars(implode('; ', $other_styles) . ';');
    }
}
// --- NEW: Conditionally apply color to prevent breaking gradient effects ---
$gradient_effects = [
    'username-aurora', 'username-matrix-flow', 'username-rainbow-wave', 
    'username-spotlight-sweep', 'username-gradient-scroll', 'username-cosmic-nebula',
    'username-char-rainbow', 'username-gradient-wipe', 'username-shockwave'
];

$final_style_str = $inline_style_str;
if (!in_array($class_str, $gradient_effects)) {
    // Only add the user's color if it's NOT a gradient effect class
    $final_style_str = "color:{$msg['color']}; " . $final_style_str;
}

$username_html_content = "<strong class='{$class_str}' style='{$final_style_str}' data-text='" . htmlspecialchars($msg['username'], ENT_QUOTES, 'UTF-8') . "'>{$combined_icon} " . htmlspecialchars($msg['username'], ENT_QUOTES, 'UTF-8') . "</strong>";

// Logic to make username clickable for moderators
$can_moderate_target = false;
if (($actor_role === 'admin' || $actor_role === 'moderator') && ($_SESSION['username'] !== $msg['username'])) {
    $target_role_for_check = !is_null($msg['user_id']) ? strtolower($msg['user_role'] ?? 'user') : 'guest';
    $can_moderate_target = ($actor_role === 'admin' && $target_role_for_check !== 'admin') || ($actor_role === 'moderator' && !in_array($target_role_for_check, ['admin', 'moderator']));
}

if ($can_moderate_target) {
    $link_param = !is_null($msg['user_id']) ? "open_profile_for_user_id={$msg['user_id']}" : "open_profile_for_guest_id={$msg['guest_id']}";
    $link_href = "?view=moderate&{$link_param}";
    if (!is_null($msg['session_id'])) { $link_href .= "&sid={$msg['session_id']}"; }
    echo "<a href='{$link_href}' target='profile' class='username-clickable' title='Moderate " . htmlspecialchars($msg['username']) . "'>{$username_html_content}</a>";
} else {
    echo $username_html_content;
}

    $display_message_content = $msg['message'];
    $is_special_format = false;

// --- Special Block Parsers ---
    if (strpos($display_message_content, '[PGP]') === 0 && strpos($display_message_content, '[/PGP]') !== false) {
        $is_special_format = true;
        $display_message_content = preg_replace_callback('/\[PGP\](.*?)\[\/PGP\]/is', function($matches) {
            return '<div class="pgp-block">' . htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8') . '</div>';
        }, $display_message_content);
    } elseif (strpos($display_message_content, 'COINFLIP::') === 0) {
        $is_special_format = true;
        $parts = explode('::', $display_message_content, 4);
        $result_text = htmlspecialchars($parts[1] ?? '', ENT_QUOTES, 'UTF-8');
        $result_color = htmlspecialchars($parts[2] ?? '#ffffff', ENT_QUOTES, 'UTF-8');
        $leading_text = htmlspecialchars($parts[3] ?? '', ENT_QUOTES, 'UTF-8');
        $display_message_content = $leading_text . ' <strong style="color:' . $result_color . ';">' . $result_text . '</strong>';
    } elseif (preg_match('/\[IMG url="(.*?)"\](.*?)\[\/IMG\]/is', $display_message_content)) {
        $is_special_format = true;
        $display_message_content = preg_replace_callback('/\[IMG url="(.*?)"\](.*?)\[\/IMG\]/is', function($matches) use ($msg, &$image_modals_to_render, $all_known_user_colors, $channels, $user_role_level_for_check, $role_hierarchy, $csrf_token) {
            $url = trim($matches[1]);
            $link_text = trim($matches[2]);
            if (!empty($url)) {
                $modal_id = "image-modal-" . $msg['id'];
                $image_modals_to_render[] = '<div id="' . htmlspecialchars($modal_id) . '" class="image-modal-overlay"><div class="image-modal-content"><a href="#_" class="image-modal-close-button" title="Close">×</a><img src="' . htmlspecialchars($url) . '" alt="' . htmlspecialchars($link_text) . '"></div></div>';
                
                // Process the link_text for BBCode, including channel tags
                $processed_link_text = process_all_bbcode($link_text, $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $csrf_token);

                return '<a href="#' . htmlspecialchars($modal_id) . '" class="bblink">' . $processed_link_text . '</a>';
            }
            return '[Invalid Image]';
        }, $display_message_content);
    
    } elseif (strpos($display_message_content, '[ascii]') !== false) {
        $is_special_format = true;
        $display_message_content = preg_replace_callback('/\[ascii\](.*?)\[\/ascii\]/is', function($matches) {
            // Sanitize the content for safety, then wrap in the preformatted ASCII block
            $ascii_content = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
            return '<pre class="ascii-block">' . $ascii_content . '</pre>';
        }, $display_message_content);
    } elseif (strpos($display_message_content, '[code]') !== false) {
        $is_special_format = true;
        $display_message_content = preg_replace_callback('/\[code\](.*?)\[\/code\]/is', function($matches) {
            $code_content = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
            return '<pre><code>' . $code_content . '</code></pre>';
        }, $display_message_content);
    } elseif (preg_match('/\[accordion=(.*?)\](.*?)\[\/accordion\]/is', $display_message_content)) { // Corrected: Removed extra comma here
        $is_special_format = true;
        $display_message_content = preg_replace_callback('/\[accordion=(.*?)\](.*?)\[\/accordion\]/is', function($matches) use ($all_known_user_colors, $channels, $user_role_level_for_check, $role_hierarchy, $csrf_token) {
            $title = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
            $content = process_all_bbcode($matches[2], $all_known_user_colors, $channels, $user_role_level_for_check, $role_hierarchy, $csrf_token);
            return '<details class="bb-accordion"><summary>' . $title . '</summary><div class="accordion-content">' . $content . '</div></details>';
        }, $display_message_content);
    } elseif (preg_match('/\[progress=(\d+)\](.*?)\[\/progress\]/is', $display_message_content)) {
        $is_special_format = true;
        $display_message_content = preg_replace_callback('/\[progress=(\d+)\](.*?)\[\/progress\]/is', function($matches) {
            $percentage = min(100, max(0, (int)$matches[1]));
            $text = htmlspecialchars($matches[2], ENT_QUOTES, 'UTF-8');
            return '<div class="progress-bar-container"><div class="progress-bar-text">' . $text . ' (' . $percentage . '%)</div><div class="progress-bar-fill" style="width: ' . $percentage . '%;"></div></div>';
        }, $display_message_content);
    } elseif (preg_match('/\[countdown=(\d+)\](.*?)\[\/countdown\]/is', $display_message_content)) {
        $is_special_format = true;
        $display_message_content = preg_replace_callback('/\[countdown=(\d+)\](.*?)\[\/countdown\]/is', function($matches) use ($msg) {
            $duration = max(1, (int)$matches[1]);
            $text = htmlspecialchars($matches[2], ENT_QUOTES, 'UTF-8');
            
            // --- NEW Stateful Logic ---
            $post_time = strtotime($msg['created_at']);
            $current_time = time();
            $elapsed_time = $current_time - $post_time;
            
            // If the countdown is already over, just show an empty bar.
            if ($elapsed_time >= $duration) {
                return '<div class="progress-bar-container"><div class="progress-bar-text">' . $text . ' (Ended)</div><div class="progress-bar-fill" style="width: 0%;"></div></div>';
            }
            
            // Otherwise, calculate the negative delay to resume the animation.
            $animation_delay = -$elapsed_time;
            
            return '<div class="progress-bar-container"><div class="progress-bar-text">' . $text . '</div><div class="progress-bar-fill countdown-bar-fill" style="animation-duration: ' . $duration . 's; animation-delay: ' . $animation_delay . 's;"></div></div>';
        }, $display_message_content);
    }

    // --- Regular BBCode Parsers ---
    if (!$is_special_format) {
        $display_message_content = preg_replace_callback('/\[url=(https?:\/\/[^\]]+)\](.*?)\[\/url\]/si', function ($matches) {
            return '<a href="' . htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener noreferrer" class="bblink">' . htmlspecialchars($matches[2], ENT_QUOTES, 'UTF-8') . '</a>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[notice\](.*?)\[\/notice\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<div class="notice-box">' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</div>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[quote=(.*?)\](.*?)\[\/quote\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<div class="quote-box"><span class="quote-box-author">' . htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8') . ' wrote:</span>' . process_all_bbcode($matches[2], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</div>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[quote\](.*?)\[\/quote\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<div class="quote-box">' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</div>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[highlight\](.*?)\[\/highlight\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<span class="highlight-text">' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</span>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[s\](.*?)\[\/s\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<s>' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</s>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[animate=(pulse|shake|ghost)\](.*?)\[\/animate\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<span class="animate-' . htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8') . '">' . process_all_bbcode($matches[2], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</span>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[COLOR=([a-fA-F0-9#]{3,7})\](.*?)\[\/COLOR\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return "<span style=\"color:" . htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8') . ';">' . process_all_bbcode($matches[2], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . "</span>";
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[B\](.*?)\[\/B\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<strong>' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</strong>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[I\](.*?)\[\/I\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<em>' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</em>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[U\](.*?)\[\/U\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<u>' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</u>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[SPOILER\](.*?)\[\/SPOILER\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return '<span class="spoiler-text">' . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . '</span>';
        }, $display_message_content);
        $display_message_content = preg_replace_callback('/\[ME\](.*?)\[\/ME\]/is', function($matches) use ($all_known_user_colors, $user_role_level_for_check, $role_hierarchy) {
            return "<em class='me-action'>" . process_all_bbcode($matches[1], $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']) . "</em>";
        }, $display_message_content);
        
        $display_message_content = process_all_bbcode($display_message_content, $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']);
    }
    
// --- NEW: Render [IMAGE], [DOC], [ZIP], [AUDIO] BBCode for re-sharing files (LINK ONLY) ---
    $display_message_content = preg_replace_callback(
        '/\[(IMAGE|DOC|ZIP|AUDIO) id=(\d+)\]/is',
        function ($matches) use ($pdo) {
            $type = strtoupper($matches[1]);
            $upload_id = (int)$matches[2];

            $stmt = $pdo->prepare("SELECT link_text, original_filename FROM uploads WHERE id = ?");
            $stmt->execute([$upload_id]);
            $file_data = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($file_data) {
                $display_text = htmlspecialchars($file_data['link_text'] ?: $file_data['original_filename'], ENT_QUOTES, 'UTF-8');
                $viewer_url = '#';
                $icon = '❓';

                switch ($type) {
                    case 'IMAGE':
                        $viewer_url = 'gallery.php?view_image_id=' . $upload_id;
                        $icon = '🖼️';
                        break;
                    case 'DOC':
                        $viewer_url = 'docs.php?view_doc_id=' . $upload_id;
                        $icon = '📄';
                        break;
                    case 'ZIP':
                        $viewer_url = 'zips.php?view_zip_id=' . $upload_id;
                        $icon = '🗜️';
                        break;
                    case 'AUDIO':
                        $viewer_url = 'audio.php?view_audio_id=' . $upload_id;
                        $icon = '🎵';
                        break;
                }
                
                return '<a href="' . $viewer_url . '" target="_blank" class="bblink file-link" title="' . $display_text . '">' . $icon . ' ' . $display_text . '</a>';
            } else {
                return '[' . ucfirst(strtolower($type)) . ' Not Found: ID ' . $upload_id . ']';
            }
        },
        $display_message_content
    );

// --- Render [VIEWFILE] BBCode (Legacy Support) ---
    $display_message_content = preg_replace_callback(
        '/\[VIEWFILE page=(.*?) param=(.*?) id=(\d+)\](.*?)\[\/VIEWFILE\]/is',
        function ($matches) {
            $page = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
            $param = htmlspecialchars($matches[2], ENT_QUOTES, 'UTF-8');
            $upload_id = $matches[3];
            $link_text = htmlspecialchars($matches[4], ENT_QUOTES, 'UTF-8');
            
            $icon = '❓'; // Default icon
            if ($page === 'gallery.php') {
                $icon = '🖼️';
            } elseif ($page === 'docs.php') {
                $icon = '📄';
            } elseif ($page === 'zips.php') {
                $icon = '🗜️';
            }
            
            $viewer_url = "{$page}?{$param}=" . $upload_id;

            return '<a href="' . $viewer_url . '" target="_blank" class="bblink file-link" title="' . $link_text . '">' . $icon . ' ' . $link_text . '</a>';
        },
        $display_message_content
    );

    echo ": <span style='color:{$msg['color']}; opacity: 0.9;'>" . $display_message_content . "</span>";
}
    
// For quoted messages, we also need to apply BBCode processing before displaying.
    if (!$msg['is_system_message'] && !empty($msg['replying_to_message_id'])) {
        // Fetch the original message along with the original poster's color
        $quote_stmt = $pdo->prepare("SELECT username, message, color FROM messages WHERE id = ?");
        $quote_stmt->execute([$msg['replying_to_message_id']]);
        if ($original_msg = $quote_stmt->fetch(PDO::FETCH_ASSOC)) {
            $quoted_message_raw_stripped = preg_replace('/\[.*?\]/s', '', $original_msg['message']);
            $quoted_message_content = process_all_bbcode($quoted_message_raw_stripped, $all_known_user_colors, $user_role_level_for_check, $role_hierarchy, $_SESSION['csrf_token']);
            
            // Get the original poster's color and generate a transparent version for the background
            $op_color = htmlspecialchars($original_msg['color'], ENT_QUOTES, 'UTF-8');
            $op_rgba_bg = hexToRgba($op_color, 0.15); // Use the existing hexToRgba function
            
            // Apply inline styles for the colors
            echo "<div class='reply-quote-box' style='background-color: {$op_rgba_bg}; border-left-color: {$op_color}; color: {$op_color}; opacity: 0.8;'>";
            echo "<strong style='color: {$op_color};'>" . htmlspecialchars($original_msg['username'], ENT_QUOTES, 'UTF-8') . ":</strong> ";
            echo "<span style='opacity: 0.9;'>" . $quoted_message_content . "</span>";
            echo "</div>";
        }
    }
    echo "</div>"; // Closes .msg-line
}

?>
        </div>
        
        <div id="modal-container">
            <?php echo implode('', $image_modals_to_render); ?>
        </div>
    </body></html>

        <?php
        break;

case 'chatters':
    // If kicked_info is set, output a minimal page indicating session termination
    if ($kicked_info !== null) {
        echo '<!DOCTYPE html><html><head><style>body { background-color: #1a1a1a; margin:0; display:flex; justify-content:center; align-items:center; color:#ffc2c2; font-family: \'Roboto\', sans-serif; font-size: 0.9em; text-align: center; padding: 10px; }</style></head><body>SESSION TERMINATED.<br>Please refresh the main page.</body></html>';
        exit;
    }

    // Stop if the session is invalid
    if (!isset($_SESSION['username']) || !isset($_SESSION['session_id'])) {
        echo '<!DOCTYPE html><html><body style="background-color: transparent;"></body></html>';
        die();
    }
    
    // --- Ghosting Enforcement: If the current viewer is ghosted, show a blank panel ---
    $am_i_ghosted_stmt = $pdo->prepare("SELECT is_shadow_kicked FROM sessions WHERE session_id = ?");
    $am_i_ghosted_stmt->execute([$_SESSION['session_id']]);
    if ($am_i_ghosted_stmt->fetchColumn() == 1) {
        echo '<!DOCTYPE html><html><head><link rel="stylesheet" href="style.css"></head><body class="frame-body"></body></html>';
        exit; // Exit here to show the ghosted user a blank chatters list
    }

    // --- Standard variable setup ---
    $my_id = (int)($_SESSION['user_id'] ?? 0);
    $my_username = $_SESSION['username'] ?? null;
    $is_viewer_member = !($_SESSION['is_guest'] ?? true);
    $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
    $ignored_list = $_SESSION['ignored_users'] ?? [];

    // Fetch current user's AFK status for the button label
    $my_status_stmt = $pdo->prepare("SELECT status FROM sessions WHERE session_id = ?");
    $my_status_stmt->execute([$_SESSION['session_id']]);
    $my_status = $my_status_stmt->fetchColumn() ?: 'online';
    $afk_button_text = ($my_status === 'afk') ? 'I am back' : 'Go AFK';

    // --- PM Notification Logic ---
    $unread_pm_senders = [];
    if ($is_viewer_member) {
        $unread_stmt = $pdo->prepare("SELECT DISTINCT from_user_id FROM private_messages WHERE to_user_id = ? AND is_read = 0");
        $unread_stmt->execute([$my_id]);
        $unread_pm_senders = $unread_stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    }

    // --- GET USER LISTS AND COUNTS ---
    $offline_search_term = trim($_GET['offline_search'] ?? '');

    // 1. Get online users.
    $online_users_sql = "SELECT s.username, s.is_guest, s.user_id, s.guest_id, s.session_id, s.status, s.afk_message, u.role as user_role, u.custom_css, u.pgp_public_key, g.color as guest_color, u.color as user_color, u.message_count 
                         FROM sessions s 
                         LEFT JOIN users u ON s.user_id = u.id 
                         LEFT JOIN guests g ON s.guest_id = g.id 
                         WHERE s.kick_message IS NULL 
                         AND s.last_active >= NOW() - INTERVAL " . (int)$session_timeout . " SECOND
                         AND (u.is_hidden IS NULL OR u.is_hidden = 0)
                         ORDER BY s.is_guest ASC, u.role DESC, s.username ASC";
    $online_users = $pdo->query($online_users_sql)->fetchAll(PDO::FETCH_ASSOC);
    $online_count = count($online_users);

    // 2. Populate a list of online member IDs to exclude them from the offline list
    $online_member_ids = [];
    foreach ($online_users as $chatter) {
        if (!$chatter['is_guest']) {
            $online_member_ids[] = $chatter['user_id'];
        }
    }
    
    // 3. Get the offline user list, applying the search filter if present
    $offline_users = [];
    $offline_count = 0;
    if ($is_viewer_member) {
        $offline_sql = "SELECT id, username, role, color, custom_css, last_seen FROM users WHERE is_banned = 0 AND is_deactivated = 0 AND allow_offline_pm = 1";
        $offline_params = [];
        if (!empty($online_member_ids)) {
            $placeholders = implode(',', array_fill(0, count($online_member_ids), '?'));
            $offline_sql .= " AND id NOT IN ($placeholders)";
            $offline_params = $online_member_ids;
        }
        if (!empty($offline_search_term)) {
            $offline_sql .= " AND username LIKE ?";
            $offline_params[] = '%' . $offline_search_term . '%';
        }
        $offline_sql .= " ORDER BY username ASC";
        
        $offline_stmt = $pdo->prepare($offline_sql);
        $offline_stmt->execute($offline_params);
        $offline_users = $offline_stmt->fetchAll(PDO::FETCH_ASSOC);
        $offline_count = count($offline_users);
    }
    ?>
    <!DOCTYPE html><html><head><meta http-equiv="refresh" content="<?php echo (int)($_SESSION['refresh_rate'] ?? 5); ?>"><link rel="stylesheet" href="style.css"></head><body class="frame-body"><div class="chatters-list">
        <div class="chatters-header">
            <h3>Online Now (<?php echo $online_count; ?>)</h3>
            <form method="post" action="chat.php" class="afk-form">
                 <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                 <button type="submit" name="toggle_afk" class="afk-button"><?php echo $afk_button_text; ?></button>
            </form>
        </div>

        <h4 class="logged-in-as">You are: <strong><?php echo htmlspecialchars($my_username); ?></strong></h4>
        <ul>
    <?php foreach ($online_users as $chatter): ?>
        <?php
        echo "<li>";
        
        // --- This is the new DIV for the username, with the 'chatter-info' class ---
        echo "<div class='chatter-info'>";
        
        $color = $chatter['is_guest'] ? $chatter['guest_color'] : $chatter['user_color'];
        $role_icon = '⚡';
        
        if ($chatter['is_guest']) {
            $role_icon = '👹';
        } else {
            $role = strtolower($chatter['user_role'] ?? 'user');
            switch ($role) {
                case 'admin':     $role_icon = '🧛'; break;
                case 'moderator': $role_icon = '🛡️'; break;
                case 'trusted':   $role_icon = '💎'; break;
                case 'user':      $role_icon = '⚡'; break;
            }
        }

        $raw_custom_style = !($chatter['is_guest']) && !empty($chatter['custom_css']) ? $chatter['custom_css'] : '';
        $class_str = '';
        $inline_style_str = '';

        if (!empty($raw_custom_style)) {
            // --- NEW: Robustly parse class and inline styles (consistent with messages view) ---
            $style_parts = explode(';', $raw_custom_style);
            $other_styles = [];

            foreach ($style_parts as $part) {
                $part = trim($part);
                if (stripos($part, 'class:') === 0) {
                    $class_str = htmlspecialchars(trim(substr($part, 6)));
                } elseif (!empty($part)) {
                    $other_styles[] = $part;
                }
            }
            
            if (!empty($other_styles)) {
                $inline_style_str = htmlspecialchars(implode('; ', $other_styles) . ';');
            }
        }
        
        // --- NEW: Conditionally apply color for gradient effects (consistent with messages view) ---
        $gradient_effects = [
            'username-aurora', 'username-matrix-flow', 'username-rainbow-wave', 
            'username-spotlight-sweep', 'username-gradient-scroll', 'username-cosmic-nebula',
            'username-char-rainbow', 'username-gradient-wipe', 'username-shockwave'
        ];

        $final_style_str = $inline_style_str;
        if (!in_array($class_str, $gradient_effects)) {
            $final_style_str = "color:{$color}; " . $final_style_str;
        }

$username_html_content = "<strong class='{$class_str}' style='{$final_style_str}' data-text='" . htmlspecialchars($chatter['username']) . "' title='" . htmlspecialchars($chatter['username']) . "'>{$role_icon} " . htmlspecialchars($chatter['username']) . "</strong>";
        $afk_status_html = '';
        if ($chatter['status'] === 'afk') {
            $afk_message = !empty($chatter['afk_message']) ? htmlspecialchars($chatter['afk_message']) : 'AFK';
            $afk_status_html = ' <span class="afk-status">(' . $afk_message . ')</span>';
        }

        $pm_notification_html = in_array($chatter['user_id'], $unread_pm_senders) ? "<span class='pm-notification-icon'>📨</span>" : '';
        
        $can_moderate_chatter = ($actor_role === 'admin' || $actor_role === 'moderator') && ($my_username !== $chatter['username']);
        $target_chatter_role = $chatter['is_guest'] ? 'guest' : strtolower($chatter['user_role'] ?? 'user');
        $can_moderate_chatter &= ($actor_role === 'admin' && $target_chatter_role !== 'admin') || ($actor_role === 'moderator' && !in_array($target_chatter_role, ['admin', 'moderator']));

        // Display the notification icon first
        echo $pm_notification_html;

        if ($can_moderate_chatter) {
            $link_param = $chatter['is_guest'] ? "open_profile_for_guest_id={$chatter['guest_id']}" : "open_profile_for_user_id={$chatter['user_id']}";
            echo "<a href='?view=moderate&{$link_param}&sid={$chatter['session_id']}' target='profile' class='username-clickable' title='Moderate'>{$username_html_content}</a>";
        } else {
            echo $username_html_content;
        }
        echo "{$afk_status_html}</div>"; // End of chatter-info div
        
        // --- This is the new DIV for the action buttons, with the 'chatter-actions' class ---
        $buttons_html = "<div class='chatter-actions'>";
        if ($is_viewer_member && !$chatter['is_guest'] && $my_username !== $chatter['username']) {
            if (!empty($chatter['pgp_public_key'])) {
                $buttons_html .= "<a href='view_key.php?user_id={$chatter['user_id']}' target='_top' class='pm-link pgp-link' title='View PGP Key'>🔒</a>";
            }
            $buttons_html .= "<a href='?view=pm&with_user_id={$chatter['user_id']}' target='_top' class='pm-link' title='Private Message'>📧</a>";
        }
        if ($my_username !== $chatter['username']) {
            $target_identifier = $chatter['is_guest'] ? 'g_' . $chatter['guest_id'] : 'u_' . $chatter['user_id'];
            $is_ignored = in_array($target_identifier, $ignored_list);
            $ignore_icon = $is_ignored ? '🔇' : '🔉';
            $ignore_title = $is_ignored ? 'Unignore User' : 'Ignore User';
            $buttons_html .= "<form method='post' action='chat.php' style='margin:0;'><input type='hidden' name='csrf_token' value='{$_SESSION['csrf_token']}'><input type='hidden' name='target_identifier' value='{$target_identifier}'><button type='submit' name='toggle_ignore' title='{$ignore_title}' style='background:none; border:none; cursor:pointer; padding:0 5px; font-size: 1.1em;'>{$ignore_icon}</button></form>";
        }
        $buttons_html .= "</div>"; // End of chatter-actions div
        echo $buttons_html;

        echo "</li>";
        ?>
    <?php endforeach; ?>
</ul>

        <?php if ($is_viewer_member): ?>
        <input type="checkbox" id="toggle-offline-checkbox" class="toggle-checkbox-offline" <?php if(($_SESSION['offline_list_collapsed'] ?? false)) echo 'checked'; ?>>
        <div class="chatters-header offline-header" style="margin-top: 20px;">
            <a href="?view=chatters&action=toggle_offline_list" class="offline-header-toggle">
                <h3>Offline (<?php echo $offline_count; ?>)</h3>
            </a>
        </div>
        <form action="chat.php" method="get" target="_self" class="offline-search-form">
            <input type="hidden" name="view" value="chatters">
            <input type="text" name="offline_search" class="offline-search-input" placeholder="Search offline..." value="<?php echo htmlspecialchars($offline_search_term); ?>" autocomplete="off">
            <?php if (!empty($offline_search_term)): ?>
                <a href="?view=chatters" class="clear-search-btn">Clear</a>
            <?php endif; ?>
        </form>
        <div class="offline-users-list">
            <ul>
<ul>
                <?php
                if ($offline_count > 0) {
                    foreach ($offline_users as $offline_user) {
                        if ($offline_user['id'] == $my_id) continue;

                        $role = strtolower($offline_user['role']);
                        $role_icon = ($role === 'admin') ? '🧛' : (($role === 'moderator') ? '🛡️' : (($role === 'trusted') ? '💎' : '⚡'));
                        $raw_custom_style = $offline_user['custom_css'] ?? '';
                        $inline_style_str = (strpos($raw_custom_style, 'class:') !== 0) ? htmlspecialchars($raw_custom_style) : '';
                        $class_str = (strpos($raw_custom_style, 'class:') === 0) ? htmlspecialchars(trim(substr($raw_custom_style, 6))) : '';
                        
                        $last_seen_title = '';
                        if (($actor_role === 'admin' || $actor_role === 'moderator') && !empty($offline_user['last_seen'])) {
                            $last_seen_title = ' title="Last Seen: ' . htmlspecialchars($offline_user['last_seen']) . '"';
                        }
                        
                        echo "<li style='opacity: 0.7;'>";
                        
                        // Div with the new 'chatter-info' class for truncation and tooltip
                        echo "<div class='chatter-info'{$last_seen_title}>";

                        // --- NEW: Conditionally apply color for gradient effects (consistent with messages view) ---
                        $gradient_effects = [
                            'username-aurora', 'username-matrix-flow', 'username-rainbow-wave', 
                            'username-spotlight-sweep', 'username-gradient-scroll', 'username-cosmic-nebula',
                            'username-char-rainbow', 'username-gradient-wipe', 'username-shockwave'
                        ];
                
                        $final_style_str = $inline_style_str;
                        if (!in_array($class_str, $gradient_effects)) {
                            $final_style_str = "color:{$offline_user['color']}; " . $final_style_str;
                        }

                        $username_text = "<strong class='{$class_str}' style='{$final_style_str}' data-text='" . htmlspecialchars($offline_user['username']) . "'>{$role_icon} " . htmlspecialchars($offline_user['username']) . "</strong>";
                        
                        if ($actor_role === 'admin' || $actor_role === 'moderator') {
                            echo "<a href='?view=moderate&open_profile_for_user_id={$offline_user['id']}' target='profile' class='username-clickable' title='Manage Offline User'>{$username_text}</a>";
                        } else {
                            echo $username_text;
                        }

                        echo "</div>"; // End chatter-info

                        // Div with the new 'chatter-actions' class for buttons
                        echo "<div class='chatter-actions'><a href='?view=pm&with_user_id={$offline_user['id']}' target='_top' class='pm-link' title='Private Message (Offline)'>📧</a></div>";
                        echo "</li>";
                    }
                } else {
                    echo "<li style='opacity: 0.5; font-size: 0.9em;'>No members available.</li>";
                }
                ?>
            </ul>
        </div>
        <?php endif; ?>

    </div></body></html>
    <?php
    break;
case 'input':
    if ($kicked_info !== null) {
        echo '<!DOCTYPE html><html><head><style>body { background-color: #1a1a1a; margin:0; display:flex; justify-content:center; align-items:center; color:#ffc2c2; font-family: \'Roboto\', sans-serif; font-size: 0.9em; text-align: center; padding: 10px; }</style></head><body>SESSION TERMINATED.</body></html>';
        exit;
    }
    if (!isset($_SESSION['session_id'])) {
        echo '<!DOCTYPE html><html><body style="background-color: #1a1a1a;"></body></html>';
        die();
    }
    
    $user_role_name = ($_SESSION['is_guest'] ?? true) ? 'guest' : strtolower($_SESSION['user_role'] ?? 'user');
    $user_role_level = $role_hierarchy[$user_role_name] ?? 0;

    $is_disabled = false;
    $placeholder_text = 'Type message...';
    $replying_to_id = null;

    // --- THIS IS THE FIX: Check for the input error in the session ---
    if (isset($_SESSION['input_error'])) {
        $placeholder_text = $_SESSION['input_error']; // Display the error as the placeholder
        unset($_SESSION['input_error']); // Clear the error so it only shows once
    } elseif (isset($_GET['reply_to_id']) && ctype_digit($_GET['reply_to_id'])) {
        // Handle reply logic only if there isn't a more important error to show
        $replying_to_id = (int)$_GET['reply_to_id'];
        $stmt = $pdo->prepare("SELECT username, message FROM messages WHERE id = ?");
        $stmt->execute([$replying_to_id]);
        if ($original_msg = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $snippet_raw = preg_replace('/\[.*?\]/s', '', $original_msg['message']);
            $snippet = substr($snippet_raw, 0, 40);
            if (strlen($snippet_raw) > 40) { $snippet .= '...'; }
            $placeholder_text = "Re: " . htmlspecialchars($original_msg['username']) . ": \"" . htmlspecialchars($snippet) . "\"";
        } else {
            $replying_to_id = null;
        }
    } elseif ($_SESSION['is_guest'] ?? false) {
        $stmt = $pdo->prepare("SELECT message_count, message_limit FROM guests WHERE id = ?");
        $stmt->execute([$_SESSION['guest_id']]);
        $guest_data = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($guest_data && $guest_data['message_count'] >= $guest_data['message_limit']) {
            $is_disabled = true;
            $placeholder_text = 'Message limit reached.';
        } else {
            $remaining = ($guest_data['message_limit'] ?? 50) - ($guest_data['message_count'] ?? 0);
            $placeholder_text = "Guest mode: {$remaining} messages left...";
        }
    }
    ?>
<!DOCTYPE html><html><head><link rel="stylesheet" href="style.css"></head><body class="frame-body">
    <div class="input-bar-container">
        <form method="post" action="chat.php" target="_top" class="channel-form">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <select name="channel" class="channel-selector" <?php if($is_disabled) echo 'disabled'; ?>>
                <?php foreach($channels as $channel_key => $channel_data): ?>
                    <?php if($user_role_level >= $role_hierarchy[$channel_data['min_role']]): ?>
                        <option value="<?php echo htmlspecialchars($channel_key); ?>" <?php if (($_SESSION['current_channel'] ?? 'general') == $channel_key) echo 'selected'; ?>>
                            <?php echo htmlspecialchars($channel_data['display']); ?>
                        </option>
                    <?php endif; ?>
                <?php endforeach; ?>
            </select>
            <button type="submit" name="switch_channel" class="switch-channel-btn" <?php if($is_disabled) echo 'disabled'; ?>>Switch</button>
        </form>

<input type="checkbox" id="multiline-toggle" class="toggle-checkbox">
<form method="post" action="chat.php" class="message-form">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <?php
    if ($replying_to_id) {
        echo "<input type='hidden' name='replying_to_id' value='{$replying_to_id}'>";
    }
    ?>
    <div class="input-wrapper">
        <input type="text" name="message_single" class="message-input single-line-input" placeholder="<?php echo htmlspecialchars($placeholder_text); ?>" autocomplete="off" autofocus <?php if($is_disabled) echo 'disabled'; ?>>
        <textarea name="message_multi" class="message-input multi-line-input" placeholder="<?php echo htmlspecialchars($placeholder_text); ?>" autocomplete="off" <?php if($is_disabled) echo 'disabled'; ?> rows="3"></textarea>
    </div>
    <label for="multiline-toggle" class="toggle-multiline-btn" title="Toggle Multi-line Input">¶</label>
    <button type="submit" name="send_message" class="send-btn" <?php if($is_disabled) echo 'disabled'; ?>>Send</button>
</form>
    </div>
</body></html>
    <?php
    break;

// THIS IS THE NEW REPLACEMENT BLOCK
case 'moderate':
    if ($kicked_info !== null) {
        // ... (kick page rendering as before) ...
        exit;
    }

    $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
    if ($actor_role !== 'admin' && $actor_role !== 'moderator') { die("Access Denied."); }

    $target_user_id = $_GET['open_profile_for_user_id'] ?? null;
    $target_guest_id = $_GET['open_profile_for_guest_id'] ?? null;
    $target_session_id = $_GET['sid'] ?? null;

    $target_username = ''; 
    $is_guest = false; 
    $target_role = ''; 
    $remaining_tokens = 0;
    $can_guest_post_links = false; // Default value

    if ($target_user_id) { 
        $stmt = $pdo->prepare("SELECT username, role FROM users WHERE id = ?"); $stmt->execute([$target_user_id]); $data = $stmt->fetch(PDO::FETCH_ASSOC);
        $target_username = $data['username'] ?? ''; $target_role = strtolower($data['role'] ?? 'user');
    } elseif ($target_guest_id) { 
        $stmt = $pdo->prepare("SELECT username, message_limit, message_count, can_post_links FROM guests WHERE id = ?"); $stmt->execute([$target_guest_id]); $data = $stmt->fetch(PDO::FETCH_ASSOC);
        $target_username = $data['username'] ?? ''; $remaining_tokens = ($data['message_limit'] ?? 0) - ($data['message_count'] ?? 0);
        $is_guest = true; $target_role = 'guest';
        $can_guest_post_links = (bool)$data['can_post_links'];
    }

    if (!$target_username) { header('Location: ' . $_SERVER['PHP_SELF'] . '?view=profile'); exit; }

    $can_moderate = ($actor_role === 'admin' && $target_role !== 'admin') || ($actor_role === 'moderator' && !in_array($target_role, ['admin', 'moderator']));
    $display_role = ucfirst($target_role);
    if ($display_role === 'User') { $display_role = 'Member'; }
    ?>
    <!DOCTYPE html><html><head><title>Moderate User</title><link rel="stylesheet" href="style.css"></head><body class="frame-body">
        <div class="chatters-list">
            <h3>Moderate User</h3>
            <p class="moderate-target">Target: <strong><?php echo htmlspecialchars($target_username); ?></strong> (Role: <?php echo htmlspecialchars($display_role); ?>)</p>
            <hr>

<div class="moderate-actions">
    <?php if ($can_moderate): ?>
        
        <?php if ($target_session_id): ?>
            <form method="post" action="chat.php" target="_top">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="moderate_user" value="1">
                <input type="hidden" name="action" value="kick">
                <input type="hidden" name="target_user_id" value="<?php echo htmlspecialchars($target_user_id ?? ''); ?>">
                <input type="hidden" name="target_guest_id" value="<?php echo htmlspecialchars($target_guest_id ?? ''); ?>">
                <input type="hidden" name="target_session_id" value="<?php echo htmlspecialchars($target_session_id); ?>">
                <input type="hidden" name="target_username" value="<?php echo htmlspecialchars($target_username); ?>">
                <p class="form-group" style="margin-bottom: 8px; font-weight: bold;">Live Actions:</p>
                <div class="kick-form">
                    <input type="text" name="kick_reason" placeholder="Reason (optional)...">
                    <button type="submit" class="danger-btn">Kick</button>
                </div>
            </form>

            <?php if ($is_guest): ?>
                <hr>
                <form action="chat.php" method="post" target="_top">
                     <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                     <input type="hidden" name="promote_guest" value="1">
                     <input type="hidden" name="guest_id_to_promote" value="<?php echo htmlspecialchars($target_guest_id); ?>">
                     <input type="hidden" name="session_id_to_promote" value="<?php echo htmlspecialchars($target_session_id); ?>">
                     <button type="submit" class="full-width" style="background-color:#004d4d; color:#c2ffff; border-color:#009999;">Promote to Member</button>
                </form>
            <?php endif; ?>
        <?php endif; ?>

        <hr>
        <p class="form-group" style="margin-bottom: 8px; font-weight: bold;">Data Actions:</p>
        
        <form method="post" action="chat.php" target="_top" style="margin-bottom: 15px;">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="moderate_user" value="1">
            <input type="hidden" name="action" value="clear_messages">
            <input type="hidden" name="target_user_id" value="<?php echo htmlspecialchars($target_user_id ?? ''); ?>">
            <input type="hidden" name="target_guest_id" value="<?php echo htmlspecialchars($target_guest_id ?? ''); ?>">
            <input type="hidden" name="target_username" value="<?php echo htmlspecialchars($target_username); ?>">
            <button type="submit" class="danger-btn full-width">Clear All Messages</button>
        </form>

        <?php if ($is_guest): ?>
            <form method="post" action="chat.php" target="_top">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="moderate_user" value="1">
                <input type="hidden" name="action" value="adjust_tokens">
                <input type="hidden" name="target_guest_id" value="<?php echo htmlspecialchars($target_guest_id); ?>">
                <input type="hidden" name="target_username" value="<?php echo htmlspecialchars($target_username); ?>">
                
                <div class="token-grant-form">
                    <label>Guest Tokens Left: <?php echo $remaining_tokens; ?></label>
                    <input type="number" name="tokens_to_adjust" value="25" class="token-input">
                    <p class="form-hint">Use negative to remove.</p>
                </div>
                
                <div class="form-group" style="margin-top: 15px; margin-bottom: 15px;">
                    <label class="checkbox-label">
                        <input type="checkbox" name="can_post_links" value="1" <?php if ($can_guest_post_links) echo 'checked'; ?>>
                        Allow guest to post links
                    </label>
                </div>

                <button type="submit">Save Guest Settings</button>
            </form>
        <?php endif; ?>

    <?php else: ?>
        <p class="permission-denied">No permission to moderate this user.</p>
    <?php endif; ?>
    <hr>
    <a href="?view=profile" target="_self" class="close-link">Return to Profile</a>
</div>
        </div>
    </body></html>
<?php
    break;
    // If kicked_info is set, output a minimal page indicating session termination
    // within this iframe. This prevents the moderation panel from being accessible
    // and prompts the user to manually refresh the main page.
    if ($kicked_info !== null) {
        echo '<!DOCTYPE html><html><head><style>
            body {
                background-color: #1a1a1a;
                margin:0;
                display:flex;
                flex-direction: column;
                justify-content:center;
                align-items:center;
                height: 100vh;
                color:#ffc2c2;
                font-family: \'Roboto\', sans-serif;
                font-size: 0.9em;
                text-align: center;
                padding: 10px;
                box-sizing: border-box;
            }
            h2 {
                color: #ff3333;
                font-family: \'Courier Prime\', monospace;
                margin-top: 0;
                margin-bottom: 15px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            p {
                background-color: #4d0000;
                color: #ffc2c2;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #990000;
                font-size: 1em;
                line-height: 1.4;
                word-wrap: break-word;
                margin-bottom: 20px;
            }
            a {
                color: #ff8888;
                text-decoration: none;
                font-weight: bold;
                padding: 8px 15px;
                background-color: #333;
                border: 1px solid #555;
                border-radius: 5px;
                transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease;
            }
            a:hover {
                background-color: #555;
                border-color: #ff5555;
                color: #fff;
            }
        </style></head><body>
            <h2>SESSION TERMINATED</h2>
            <p>' . htmlspecialchars($kicked_info) . '</p>
            <a href="chat.php" target="_top">Return to Login</a>
        </body></html>';
        exit; // Stop further rendering for this iframe
    }

    $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
    if ($actor_role !== 'admin' && $actor_role !== 'moderator') { die("Access Denied."); }

    $target_user_id = $_GET['open_profile_for_user_id'] ?? null;
    $target_guest_id = $_GET['open_profile_for_guest_id'] ?? null;
    $target_session_id = $_GET['sid'] ?? null;

    $target_username = ''; 
    $is_guest = false; 
    $target_role = ''; 
    $remaining_tokens = 0;

    if ($target_user_id) { 
        $stmt = $pdo->prepare("SELECT username, role FROM users WHERE id = ?"); $stmt->execute([$target_user_id]); $data = $stmt->fetch(PDO::FETCH_ASSOC);
        $target_username = $data['username'] ?? ''; $target_role = strtolower($data['role'] ?? 'user');
    } elseif ($target_guest_id) { 
        $stmt = $pdo->prepare("SELECT username, message_limit, message_count FROM guests WHERE id = ?"); $stmt->execute([$target_guest_id]); $data = $stmt->fetch(PDO::FETCH_ASSOC);
        $target_username = $data['username'] ?? ''; $remaining_tokens = ($data['message_limit'] ?? 0) - ($data['message_count'] ?? 0);
        $is_guest = true; $target_role = 'guest'; 
    }

    if (!$target_username) { header('Location: ' . $_SERVER['PHP_SELF'] . '?view=profile'); exit; }

    $can_moderate = ($actor_role === 'admin' && $target_role !== 'admin') || ($actor_role === 'moderator' && !in_array($target_role, ['admin', 'moderator']));
    $display_role = ucfirst($target_role);
    if ($display_role === 'User') { $display_role = 'Member'; }
    ?>
<!DOCTYPE html><html><head><title>Moderate User</title><link rel="stylesheet" href="style.css"></head><body class="frame-body">
    <div class="chatters-list">
        <h3>Moderate User</h3>
        <p class="moderate-target">Target: <strong><?php echo htmlspecialchars($target_username); ?></strong> (Role: <?php echo htmlspecialchars($display_role); ?>)</p>
        <hr>
<div class="moderate-actions">
            <?php if ($can_moderate): ?>
                
                <?php if ($target_session_id): ?>
                    <form method="post" action="chat.php" target="_top">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="hidden" name="moderate_user" value="1">
                        <input type="hidden" name="target_user_id" value="<?php echo htmlspecialchars($target_user_id ?? ''); ?>">
                        <input type="hidden" name="target_guest_id" value="<?php echo htmlspecialchars($target_guest_id ?? ''); ?>">
                        <input type="hidden" name="target_session_id" value="<?php echo htmlspecialchars($target_session_id); ?>">
                        <input type="hidden" name="target_username" value="<?php echo htmlspecialchars($target_username); ?>">

                        <p class="form-group" style="margin-bottom: 8px; font-weight: bold;">Live Actions:</p>
                        <div class="kick-form">
                            <input type="text" name="kick_reason" placeholder="Reason (optional)...">
                            <button type="submit" name="action" value="kick" class="danger-btn">Kick</button>
                        </div>
                    </form>

                    <?php if ($is_guest): ?>
                        <hr>
                        <form action="chat.php" method="post" target="_top">
                             <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                             <input type="hidden" name="guest_id_to_promote" value="<?php echo htmlspecialchars($target_guest_id); ?>">
                             <input type="hidden" name="session_id_to_promote" value="<?php echo htmlspecialchars($target_session_id); ?>">
                             <button type="submit" name="promote_guest" class="full-width" style="background-color:#004d4d; color:#c2ffff; border-color:#009999;">Promote to Member</button>
                        </form>
                    <?php endif; ?>
                <?php endif; ?>

                <hr>
                <p class="form-group" style="margin-bottom: 8px; font-weight: bold;">Data Actions:</p>
                <form method="post" action="chat.php" target="_top">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" name="moderate_user" value="1">
                    <input type="hidden" name="target_user_id" value="<?php echo htmlspecialchars($target_user_id ?? ''); ?>">
                    <input type="hidden" name="target_guest_id" value="<?php echo htmlspecialchars($target_guest_id ?? ''); ?>">
                    <input type="hidden" name="target_username" value="<?php echo htmlspecialchars($target_username); ?>">

                    <button type="submit" name="action" value="clear_messages" class="danger-btn full-width" style="margin-bottom: 15px;">Clear All Messages</button>

                    <?php if ($is_guest): ?>

                        
                        <div class="token-grant-form">
                            <label>Guest Tokens Left: <?php echo $remaining_tokens; ?></label>
                            <input type="number" name="tokens_to_adjust" value="25" class="token-input">
                            <button type="submit" name="action" value="adjust_tokens">Adjust Tokens</button>
                            <p class="form-hint">Use negative to remove.</p>
                        </div>
                    <?php endif; ?>
                </form>

            <?php else: ?>
                <p class="permission-denied">No permission to moderate this user.</p>
            <?php endif; ?>
            <hr>
            <a href="?view=profile" target="_self" class="close-link">Return to Profile</a>
        </div>
    </div>
    </body></html>
<?php
    break;

    case 'profile':
    $show_login_msgs = 0; $show_system_msgs = 0; $color = '#ffffff'; $refresh_rate = 5; $allow_offline_pm = 1; // Default values
    $is_hidden = 0; // Default hidden status

    if($_SESSION['is_guest'] ?? true) {
        $stmt = $pdo->prepare("SELECT color, show_login_msgs, show_system_msgs, refresh_rate FROM guests WHERE id = ?");
        $stmt->execute([$_SESSION['guest_id']]);
        if($data = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $color = $data['color']; $show_login_msgs = $data['show_login_msgs']; $show_system_msgs = $data['show_system_msgs']; $refresh_rate = $data['refresh_rate'];
        }
    } else {
        $stmt = $pdo->prepare("SELECT color, show_login_msgs, show_system_msgs, refresh_rate, allow_offline_pm, is_hidden, pgp_public_key FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        if($data = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $color = $data['color']; $show_login_msgs = $data['show_login_msgs']; $show_system_msgs = $data['show_system_msgs']; $refresh_rate = $data['refresh_rate']; $allow_offline_pm = $data['allow_offline_pm']; $is_hidden = $data['is_hidden'];
        }
    }
    $display_role = ucfirst(strtolower($_SESSION['user_role'] ?? 'user'));
    if ($display_role === 'User') { $display_role = 'Member'; }
    $is_privileged_user = in_array(strtolower($_SESSION['user_role'] ?? 'user'), ['moderator', 'admin']);
    ?>
    <!DOCTYPE html><html><head><link rel="stylesheet" href="style.css"></head><body class="frame-body"><div class="chatters-list">
        <h3>Profile & Settings</h3>
        
        <?php
        if (isset($_SESSION['profile_feedback'])) {
            $feedback = $_SESSION['profile_feedback'];
            $message_class = ($feedback['type'] === 'success') ? 'success-message' : 'error-message';
            // Use nl2br() here to convert the \n into a <br> tag safely
            echo "<div class='{$message_class}' style='margin: 0 10px 15px;'>" . nl2br(htmlspecialchars($feedback['message'])) . "</div>";
            unset($_SESSION['profile_feedback']);
        }
        ?>

        <ul><li>User: <?php echo htmlspecialchars($_SESSION['username']); ?></li><li>Status: <?php echo $display_role; ?></li></ul>
        <hr>
        <div class="profile-settings">
            <form method="post" action="?view=profile"><input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>"><input type="hidden" name="update_profile" value="1">
                <label for="color-input">Username Color:</label>
                <input type="color" id="color-input" name="new_color" value="<?php echo htmlspecialchars($color); ?>">

                <label for="refresh-rate-select">Message Refresh Rate:</label>
                <select name="new_refresh_rate" id="refresh-rate-select" style="width: 100%; padding: 8px; background: #111; color: #e0e0e0; border: 1px solid #555;">
                    <?php
                    $rates = [5, 10, 15, 30, 60, 120];
                    foreach ($rates as $rate) {
                        $selected = ($refresh_rate == $rate) ? 'selected' : '';
                        echo "<option value='{$rate}' {$selected}>{$rate} seconds</option>";
                    }
                    ?>
                </select>

                <label class="checkbox-label"><input type="checkbox" name="show_login_msgs" value="1" <?php echo ($show_login_msgs ? 'checked' : ''); ?>> Show my join/leave messages</label>
                <label class="checkbox-label"><input type="checkbox" name="show_system_msgs" value="1" <?php echo ($show_system_msgs ? 'checked' : ''); ?>> Show all system messages</label>
                <?php if (!($_SESSION['is_guest'] ?? true)): ?>
                <label class="checkbox-label"><input type="checkbox" name="allow_offline_pm" value="1" <?php echo ($allow_offline_pm ? 'checked' : ''); ?>> Allow members to PM me when offline</label>
                <?php endif; ?>
                <label class="checkbox-label">
                    <?php 
                        // Determine the checkbox's checked state.
                        // If user_enable_visual_effects in DB is NULL, it means global default applies.
                        // In this case, reflect the global default_enable_visual_effects from settings.
                        // Otherwise, use the user's specific setting from DB.
                        $db_user_visual_effect_setting = null;
                        if (!($_SESSION['is_guest'] ?? true)) {
                            $stmt_get_user_setting = $pdo->prepare("SELECT enable_visual_effects FROM users WHERE id = ?");
                            $stmt_get_user_setting->execute([$_SESSION['user_id']]);
                            $db_user_visual_effect_setting = $stmt_get_user_setting->fetchColumn();
                        } else { // For guests
                            $stmt_get_guest_setting = $pdo->prepare("SELECT enable_visual_effects FROM guests WHERE id = ?");
                            $stmt_get_guest_setting->execute([$_SESSION['guest_id']]);
                            $db_user_visual_effect_setting = $stmt_get_guest_setting->fetchColumn();
                        }

                        $is_visual_effects_checked = false;
                        if ($db_user_visual_effect_setting === null) {
                            // If user/guest setting is NULL, use the global default
                            $is_visual_effects_checked = ($visuals['default_enable_visual_effects'] ?? '1') == '1';
                        } else {
                            // Otherwise, use the user/guest's specific setting
                            $is_visual_effects_checked = (bool)$db_user_visual_effect_setting;
                        }
                    ?>
                    <input type="checkbox" name="enable_visual_effects" value="1" <?php echo ($is_visual_effects_checked ? 'checked' : ''); ?>>
                    Enable Visual Effects (Glows, Animations)
                </label>
                <small style="color: #888; margin-top: -10px; margin-left: 30px;">Uncheck to disable chat border glow, molten title animation, and page load effects for a lighter experience.</small>

                <?php if ($is_privileged_user): ?>
                <hr style="border-color: #444;">
                <label class="checkbox-label"><input type="checkbox" name="is_hidden" value="1" <?php echo ($is_hidden ? 'checked' : ''); ?>> Hide my online status</label>
                <?php endif; ?>

                <?php if (!($_SESSION['is_guest'] ?? true)): ?>
                    <label for="pgp-key-input" style="margin-top:10px;">Your PGP Public Key:</label>
                    <textarea id="pgp-key-input" name="pgp_public_key" rows="6" placeholder="Paste your full PGP public key block here..."><?php echo htmlspecialchars($data['pgp_public_key'] ?? ''); ?></textarea>
                <?php endif; ?>

                <button type="submit">Save Settings</button>
            </form>

            <?php if (!($_SESSION['is_guest'] ?? true)): ?>
            <hr>
            <form method="post" action="chat.php?view=profile">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <label for="current_password" style="margin-top: 10px;">Change Password:</label>
                <input type="password" id="current_password" name="current_password" placeholder="Current Password" required style="margin-bottom: 10px;">
                <input type="password" name="new_password" placeholder="New Password" required style="margin-bottom: 10px;">
                <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
                <button type="submit" name="change_password">Change Password</button>
            </form>
            <?php endif; ?>

            <?php // --- NEW: TOKEN MANAGEMENT SECTION FOR MODS/ADMINS ---
            if ($is_privileged_user): ?>
            <hr>
            <div class="token-management-section">
                <h4>Registration Tokens</h4>
                <p style="font-size: 0.9em; color: #999; margin-top: -10px; margin-bottom: 15px;">Generate single-use tokens to allow new users to register when registration is locked.</p>
                <form method="post" action="?view=profile" style="margin-bottom: 15px;">
                     <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                     <button type="submit" name="generate_token_from_profile">Generate New Token</button>
                </form>
                <div style="max-height: 150px; overflow-y: auto; display: flex; flex-direction: column; gap: 5px;">
                    <?php
                    $tokens_stmt = $pdo->query("SELECT registration_token FROM users WHERE password_hash IS NULL AND registration_token IS NOT NULL ORDER BY created_at DESC");
                    if ($tokens_stmt->rowCount() > 0):
                        foreach($tokens_stmt as $token_row):
                    ?>
                        <input type="text" class="copyable-token-input" value="<?php echo htmlspecialchars($token_row['registration_token']); ?>" readonly>
                    <?php 
                        endforeach;
                    else: 
                    ?>
                         <div style="padding: 8px 10px; color: #888; text-align: center;">No active tokens.</div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

        </div>
    </div></body></html>
    <?php
    break;


case 'pm':
    // --- SECURITY & VALIDATION ---
    if ($_SESSION['is_guest'] ?? true) { header('Location: chat.php'); exit; }
    if (!isset($_GET['with_user_id']) || !ctype_digit($_GET['with_user_id'])) { header('Location: chat.php'); exit; }
    $my_id = (int)$_SESSION['user_id'];
    $their_id = (int)$_GET['with_user_id'];
    if ($my_id === $their_id) { header('Location: chat.php'); exit; }
    $user_stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
    $user_stmt->execute([$their_id]);
    $their_username = $user_stmt->fetchColumn();
    if (!$their_username) { header('Location: chat.php'); exit; }

    // --- RENDER THE PM IFRAME CONTAINER ---
    ?>
    <!DOCTYPE html><html><head><title>PM with <?php echo htmlspecialchars($their_username); ?></title><link rel="stylesheet" href="style.css"></head><body>
        <div class="chat-container pm-container">
            <div class="chat-header">
                <h1>PM with <?php echo htmlspecialchars($their_username); ?></h1>
                <div class="header-buttons-right">
                    <form method="post" action="chat.php" class="inline-form" target="_top">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="hidden" name="target_user_id" value="<?php echo $their_id; ?>">
                        <button type="submit" name="destroy_pm_action" class="pm-destroy-button">Destroy Chat</button>
                    </form>
                    <a href="chat.php" class="pm-back-button">Back to Chat</a>
                </div>
            </div>
            
            <iframe name="pm_messages" src="?view=pm_messages&with_user_id=<?php echo $their_id; ?>" class="pm-messages-frame"></iframe>
            <iframe name="pm_input" src="?view=pm_input&with_user_id=<?php echo $their_id; ?>" class="pm-input-frame"></iframe>

        </div>
    </body></html>
    <?php
    break;
        
    case 'pm_messages':
    // --- SECURITY & VALIDATION (Repeated for direct iframe access) ---
    // Added debug to help diagnose iframes not loading
    if (!isset($_SESSION['username'])) { /* debug_log("PM_MESSAGES: Session Username NOT SET. Dying."); */ die("Session Error."); }
    if ($_SESSION['is_guest'] ?? true) { /* debug_log("PM_MESSAGES: Is Guest. Dying."); */ die("Access Denied (Guests cannot PM)."); }
    if (!isset($_GET['with_user_id']) || !ctype_digit($_GET['with_user_id'])) { /* debug_log("PM_MESSAGES: with_user_id missing/invalid. Dying."); */ die("Invalid PM target."); }
    $my_id = (int)$_SESSION['user_id'];
    $their_id = (int)$_GET['with_user_id'];
    if ($my_id === $their_id) { /* debug_log("PM_MESSAGES: Self PM. Dying."); */ die("Cannot PM self."); }

    // --- LOGIC ---
    // Mark incoming messages from this user as read upon viewing.
    $pdo->prepare("UPDATE private_messages SET is_read = 1 WHERE from_user_id = ? AND to_user_id = ?")
        ->execute([$their_id, $my_id]);

    // Fetch the entire conversation history.
    $pm_stmt = $pdo->prepare(
        "SELECT * FROM private_messages
         WHERE (from_user_id = :my_id AND to_user_id = :their_id)
            OR (from_user_id = :their_id AND to_user_id = :my_id)
         ORDER BY created_at DESC" // Newest at top
    );
    $pm_stmt->execute(['my_id' => $my_id, 'their_id' => $their_id]);
    $conversation = $pm_stmt->fetchAll(PDO::FETCH_ASSOC);

    // --- RENDER THE PM MESSAGES IFRAME ---
    ?>
    <!DOCTYPE html><html><head><meta http-equiv="refresh" content="7"><link rel="stylesheet" href="style.css"></head><body class="frame-body">
        <div class="pm-messages">
            <?php if (empty($conversation)): ?>
                <div style="text-align:center; color:#888; margin-top: 50px;">This is the beginning of your private conversation.</div>
            <?php else: ?>
                <?php foreach ($conversation as $pm):
                    $message_class = ($pm['from_user_id'] == $my_id) ? 'sent' : 'received';
                    if ($pm['from_user_id'] == $my_id && $pm['to_user_id'] == $my_id) { $message_class = 'sent'; }
                    $is_pm_system_message = $pm['is_system_message'] ?? 0;

                    $raw_content = $pm['message'];
                    $pm_display_message = '';

                    // Check for PGP format in the RAW message first
                    if (strpos($raw_content, '[PGP]') === 0 && strpos($raw_content, '[/PGP]') !== false) {
                        // Simplified PGP Block Formatting
                        $pm_display_message = preg_replace_callback('/\[PGP\](.*?)\[\/PGP\]/is', function($matches) {
                            // Extract the raw content inside the tags
                            $raw_block_content = $matches[1];
                            // Sanitize the entire block at once, preserving all whitespace and newlines
                            $sanitized_content = htmlspecialchars($raw_block_content, ENT_QUOTES, 'UTF-8');
                            // Wrap it in the styled div. The CSS will handle the line breaks.
                            return '<div class="pgp-block">' . $sanitized_content . '</div>';
                        }, $raw_content);
                    } else {
                        // Not PGP, so it's a regular or system message
                        $safe_content = htmlspecialchars($raw_content, ENT_QUOTES, 'UTF-8');
                        
                        // BBCode Transformations (case-insensitive for robustness)
                        $processed_content = preg_replace('/\[B\](.*?)\[\/B\]/is', '<strong>$1</strong>', $safe_content);
                        $processed_content = preg_replace('/\[I\](.*?)\[\/I\]/is', '<em>$1</em>', $processed_content);
                        $processed_content = preg_replace('/\[U\](.*?)\[\/U\]/is', '<u>$1</u>', $processed_content);
                        $processed_content = preg_replace_callback('/\[COLOR=([a-fA-F0-9#]{3,7})\](.*?)\[\/COLOR\]/is', function($matches) {
                            $color = htmlspecialchars($matches[1]);
                            $text = $matches[2]; // Text is already sanitized
                            return "<span style=\"color:{$color};\">{$text}</span>";
                        }, $processed_content);
        
                        // Convert newlines to breaks
                        $pm_display_message = nl2br($processed_content, false);
                    }
                ?>
                    <div class="pm-message-wrapper <?php echo $message_class; ?> <?php echo $is_pm_system_message ? 'system' : ''; ?>">
                        <div class="pm-message-bubble">
                            <?php echo $pm_display_message; ?>
                            <div class="pm-timestamp"><?php echo date('H:i', strtotime($pm['created_at'])); ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </body></html>
    <?php
    break;

case 'pm_input':
    // --- SECURITY & VALIDATION ---
    // Added debug to help diagnose iframes not loading
    if (!isset($_SESSION['username'])) { /* debug_log("PM_INPUT: Session Username NOT SET. Dying."); */ die("Session Error."); }
    if ($_SESSION['is_guest'] ?? true) { /* debug_log("PM_INPUT: Is Guest. Dying."); */ die("Access Denied (Guests cannot PM)."); }
    if (!isset($_GET['with_user_id']) || !ctype_digit($_GET['with_user_id'])) { /* debug_log("PM_INPUT: with_user_id missing/invalid. Dying."); */ die("Invalid PM target."); }
    $their_id = (int)$_GET['with_user_id'];

    // Re-fetch their_username for display in this iframe context
    $user_stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
    $user_stmt->execute([$their_id]);
    $their_username = $user_stmt->fetchColumn();
    if (!$their_username) { die("User not found."); } // Ensure user still exists

    // --- RENDER THE PM INPUT IFRAME ---
    ?>
    <!DOCTYPE html><html><head><link rel="stylesheet" href="style.css"></head><body class="frame-body">
        <div class="pm-input-area">
            <form method="post" action="chat.php" class="pm-form" target="_self"> 
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="to_user_id" value="<?php echo $their_id; ?>">
                <input type="text" name="private_message" class="pm-input" placeholder="Type a private message to <?php echo htmlspecialchars($their_username); ?>..." autofocus>
                <button type="submit" name="send_private_message">Send</button>
            </form>
        </div>
    </body></html>
    <?php
    break;

case 'claim_account':
    ?>
    <!DOCTYPE html><html><head><title>Claim Account</title><link rel="stylesheet" href="style.css"></head><body>
        <div class="chat-container">
            <div class="auth-container">
                <form method="post" class="auth-form">
                    <h2>Claim Your Account</h2>
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <?php if (!empty($error_message)) { echo "<p class='error-message'>$error_message</p>"; } ?>
                    <?php if (isset($_GET['success'])) { echo "<p class='success-message'>Password set! You may now log in.</p>"; } ?>
                    <input type="text" name="username" placeholder="Your Username" required>
                    <input type="text" name="token" placeholder="Your One-Time Claim Token" required>
                    <input type="password" name="password" placeholder="Choose a New Password" required>
                    <button type="submit" name="claim_account">Set Password and Claim</button>
                    <p><a href="chat.php">Back to Login</a></p>
                </form>
            </div>
        </div>
    </body></html>
    <?php
    break;

default: // Main page view
    // If the user was kicked, show the termination screen IN the main container.
    if ($kicked_info !== null) {
?>
    <!DOCTYPE html><html><head><title>Session Terminated</title><link rel="stylesheet" href="style.css"></head><body>
        <div class="chat-container" style="display: flex; justify-content: center; align-items: center;">
            <div class="auth-form" style="max-width: 450px;">
                <h2 style="color: #ff3333;">SESSION TERMINATED</h2>
                <p class="error-message" style="margin-bottom: 25px;"><?php echo htmlspecialchars($kicked_info); ?></p>
                <a href="chat.php" class="pm-back-button" style="padding: 10px 20px;">Return to Login</a>
            </div>
        </div>
    </body></html>
<?php
    // --- SESSION CLEANUP ---
    // This code runs AFTER the kick page has been sent to the user.
    // It correctly logs them out and cleans up their session from the database.
    if (isset($_SESSION['session_id'])) {
        $session_id_to_clear = $_SESSION['session_id'];

        // Cleanly destroy the PHP session
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        session_destroy();

        // Use the main $pdo connection to delete the session record, which also removes the kick message
        $pdo->prepare("DELETE FROM sessions WHERE session_id = ?")->execute([$session_id_to_clear]);
    }

    // Otherwise, show the normal chat interface.
    } else {
        // --- NEW: Fetch stats and rules for the login/register page ---
        $stats = [
            'total_members' => 0,
            'messages_today' => 0,
            'online_total' => 0,
            'online_guests' => 0,
            'site_rules' => 'No rules have been set by the administrator.'
        ];
        $online_users_list = []; // Initialize empty list for online users
        try {
            $stats['total_members'] = $pdo->query("SELECT COUNT(*) FROM users WHERE password_hash IS NOT NULL")->fetchColumn();
            $stats['messages_today'] = $pdo->query("SELECT COUNT(*) FROM messages WHERE created_at >= CURDATE()")->fetchColumn();
            
            // Fetch both the count and the list of online users, excluding hidden ones
            $online_users_stmt = $pdo->query("SELECT s.username FROM sessions s LEFT JOIN users u ON s.user_id = u.id WHERE (u.is_hidden IS NULL OR u.is_hidden = 0)");
            $online_users_list = $online_users_stmt->fetchAll(PDO::FETCH_COLUMN);
            $stats['online_total'] = count($online_users_list);

            $stats['online_guests'] = $pdo->query("SELECT COUNT(*) FROM sessions WHERE is_guest = 1")->fetchColumn();
            $rules_text = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'site_rules'")->fetchColumn();
            if ($rules_text) {
                $stats['site_rules'] = $rules_text;
            }
        } catch (PDOException $e) {
            // Ignore errors if the stats can't be fetched
        }

        // --- Channel Activity Tracking ---
        // Initialize if not set
        if (!isset($_SESSION['last_channel_activity_messages_frame'])) {
            $_SESSION['last_channel_activity_messages_frame'] = [];
        }
        $_SESSION['last_channel_activity_messages_frame'][$_SESSION['current_channel'] ?? 'general'] = time();

        $unread_channels_info = [];
        if (isset($_SESSION['username'])) {
            $user_role_name_for_check = ($_SESSION['is_guest'] ?? true) ? 'guest' : strtolower($_SESSION['user_role'] ?? 'user');
            $user_role_level_for_check = $role_hierarchy[$user_role_name_for_check] ?? 0;

            foreach ($channels as $channel_key => $channel_data) {
                if ($user_role_level_for_check >= $role_hierarchy[$channel_data['min_role']]) {
                    if (($channel_key !== ($_SESSION['current_channel'] ?? 'general'))) {
                        $latest_msg_stmt = $pdo->prepare("SELECT MAX(created_at) FROM messages WHERE channel = ?");
                        $latest_msg_stmt->execute([$channel_key]);
                        $latest_message_timestamp_str = $latest_msg_stmt->fetchColumn();
                        $latest_message_timestamp = $latest_message_timestamp_str ? strtotime($latest_message_timestamp_str) : 0;
                        $last_seen_channel_timestamp = $_SESSION['last_channel_activity_messages_frame'][$channel_key] ?? 0;
                        if ($latest_message_timestamp > $last_seen_channel_timestamp) {
                            $unread_channels_info[$channel_key] = $channel_data['display'];
                        }
                    }
                }
            }
        }

        $profile_frame_src = '?view=profile';
        // Initialize variables to prevent "Undefined variable" warnings
        $user_level = 0; // Default for guests or not logged in
        $required_level = 0; // Default until determined by settings
        ?>
        <!DOCTYPE html><html><head><title>Rot Chat</title><link rel="stylesheet" href="style.css">
        <link rel="icon" href="/favicon.ico" type="image/x-icon"> </head>
    <?php
        $visual_settings_stmt = $pdo->query("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('chat_border_color', 'chat_glow_color', 'title_animation', 'special_effect', 'default_enable_visual_effects')");
        $visuals = $visual_settings_stmt->fetchAll(PDO::FETCH_KEY_PAIR);

        $global_enable_visual_effects = ($visuals['default_enable_visual_effects'] ?? '1') == '1';
        $user_enable_visual_effects = null; // Default to null, meaning no specific user setting

        // Get user/guest specific visual effect setting
        if (isset($_SESSION['user_id']) && !($_SESSION['is_guest'] ?? true)) {
            $stmt = $pdo->prepare("SELECT enable_visual_effects FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $user_enable_visual_effects = $stmt->fetchColumn();
        } elseif (isset($_SESSION['guest_id']) && ($_SESSION['is_guest'] ?? false)) {
            $stmt = $pdo->prepare("SELECT enable_visual_effects FROM guests WHERE id = ?");
            $stmt->execute([$_SESSION['guest_id']]);
            $user_enable_visual_effects = $stmt->fetchColumn();
        }

        // Determine the effective setting: user's override if set, otherwise global default
        $effective_enable_visual_effects = ($user_enable_visual_effects === null) ? $global_enable_visual_effects : (bool)$user_enable_visual_effects;
        
        // Store effective setting in session for easy access
        $_SESSION['effective_enable_visual_effects'] = $effective_enable_visual_effects;


        $border_color = htmlspecialchars($visuals['chat_border_color'] ?? '#cc0000');
        $glow_color = htmlspecialchars($visuals['chat_glow_color'] ?? 'linear-gradient(to bottom, #cc0000, #ff00ff)');
        $is_animation_enabled = ($visuals['title_animation'] ?? '1') == '1';
        $selected_effect = $visuals['special_effect'] ?? 'none';
        $allowed_effects = ['fade-to-black', 'glitch-classic', 'glitch-burn'];
        $body_class = '';

        if (!$effective_enable_visual_effects) {
            $body_class .= ' disable-visual-effects';
        }
        
        if (in_array($selected_effect, $allowed_effects)) {
            $body_class .= ' effect-' . $selected_effect;
        }
    ?>
<style>
    :root {
        --dynamic-border-color: <?php echo $border_color; ?>;
        --dynamic-glow-gradient: <?php echo $glow_color; ?>;
    }

/* This new wrapper will hold the glow effect and center the container */
.glow-wrapper {
    position: relative;
    width: 100%;
    max-width: 1300px;
    height: 95vh;
    /* Add flex properties to center the child .chat-container */
    display: flex;
    justify-content: center;
    align-items: center;
}

    /* This pseudo-element creates the blurred gradient background for the wrapper */
    .glow-wrapper::before {
        content: '';
        position: absolute;
        top: -20px; 
        left: -20px;
        right: -20px;
        bottom: -20px;
        background: var(--dynamic-glow-gradient);
        filter: blur(25px); /* Slightly increased blur for a softer effect */
        z-index: -1;
        border-radius: 8px; /* Should match the container's border-radius */
    }

    /* We re-add overflow:hidden here to keep the main container's layout stable */
    .chat-container {
        overflow: hidden;
    }

    <?php if (!$is_animation_enabled): ?>
    .chat-header h1 {
        animation: none !important;
        background: #444 !important;
        -webkit-background-clip: unset !important;
        background-clip: unset !important;
        color: var(--dynamic-border-color) !important;
        /* A simple shadow for when the main animation is off */
        text-shadow: 0 0 8px rgba(0,0,0,0.5) !important;
    }
    <?php endif; ?>
</style>
    </head>
<style>
    /* CSS for the hover-over user list tooltip */
    .stat-item {
        position: relative; /* Establishes a positioning context for the tooltip */
        display: inline-block;
        cursor: default;
    }
    .online-users-tooltip {
        display: none; /* Hidden by default */
        position: absolute;
        bottom: 100%; /* Position the bottom of the tooltip at the top of the text */
        right: 1000; /* Align the tooltip with the right edge of the text */
        margin-bottom: 450px; /* Add a nice gap above the text */
        margin-left: 100px;
        background-color: var(--dark-bg, #1a1a1a);
        color: var(--primary-text, #e0e0e0);
        border: 1px solid var(--header-border-color, #444);
        border-radius: 5px;
        padding: 10px;
        z-index: 10;
        width: 180px;
        box-shadow: 0 4px 10px rgba(0,0,0,0.5);
        text-align: left;
    }
    .stat-item:hover .online-users-tooltip {
        display: block; /* Show on hover */
    }
    .online-users-tooltip ul {
        margin: 5px 0 0 0;
        padding-left: 20px;
        list-style: square;
    }
    .online-users-tooltip li {
        font-size: 0.95em;
        font-weight: normal;
        margin-bottom: 3px;
    }
</style>
</head>
<body class="<?php echo htmlspecialchars(trim($body_class)); ?>">

<?php
// This block now handles BOTH guest and member promotion notifications
if (isset($_SESSION['promotion_details']) && is_array($_SESSION['promotion_details'])) :
    $details = $_SESSION['promotion_details'];
    // Unset the session variable to ensure the banner only shows once per promotion
    unset($_SESSION['promotion_details']); 
?>
    <div class="promotion-notification-bar">
        <?php 
        // Case 1: Guest-to-Member promotion with a temporary password
        if (isset($details['temp_pass'])): 
        ?>
            Congratulations! You have been promoted. Your temporary password is:
            <strong><?php echo htmlspecialchars($details['temp_pass']); ?></strong>.
            You must now
            <form method="POST" action="chat.php" target="_top" class="inline-logout-form">
                 <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                 <input type="hidden" name="redirect_target" value="login">
                 <button type="submit" name="logout" class="link-style-button">LOG OUT</button>
            </form>
            and log in as a member.

        <?php 
        // Case 2: Member-to-Trusted (or higher) promotion
        elseif (isset($details['new_role'])): 
        ?>
            Congratulations! You have been promoted to 
            <strong><?php echo ucfirst(htmlspecialchars($details['new_role'])); ?></strong>. 
            Your new permissions are now active.

        <?php endif; ?>
    </div>
<?php endif; ?>

<?php
// Define a variable to easily check if the user is a moderator or admin
$is_privileged_user = isset($_SESSION['user_role']) && in_array(strtolower($_SESSION['user_role']), ['moderator', 'admin']);
?>

<?php
// Check for and display the promotion notification after a user has been promoted.
if (isset($_SESSION['user_id']) && !($_SESSION['is_guest'] ?? true)) {
    $promo_pass_stmt = $pdo->prepare("SELECT promoted_temp_pass FROM users WHERE id = ?");
    $promo_pass_stmt->execute([$_SESSION['user_id']]);
    if ($temp_pass = $promo_pass_stmt->fetchColumn()) {
        // Clear the temp pass from the database now that it has been displayed once.
        $pdo->prepare("UPDATE users SET promoted_temp_pass = NULL WHERE id = ?")->execute([$_SESSION['user_id']]);
?>
    <div class="promotion-notification-bar">
        Congratulations! You have been promoted. Your temporary password is:
        <strong><?php echo htmlspecialchars($temp_pass); ?></strong>.
        You must now
        <form method="POST" action="chat.php" target="_top" class="inline-logout-form">
             <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
             <input type="hidden" name="redirect_target" value="login">
             <button type="submit" name="logout" class="link-style-button">LOG OUT</button>
        </form>
        and log in as a member.
    </div>
<?php
    }
}
?>
<div class="glow-wrapper">
    <input type="checkbox" id="toggle-input-position-checkbox" class="toggle-checkbox">
    <div class="chat-container">
        <input type="checkbox" id="toggle-chatters-checkbox" class="toggle-checkbox">
        <input type="checkbox" id="toggle-profile-checkbox" class="toggle-checkbox">
        <input type="checkbox" id="toggle-profile-expand-checkbox" class="toggle-checkbox">
        <input type="checkbox" id="toggle-rules-checkbox" class="toggle-checkbox">
        <input type="checkbox" id="toggle-notes-checkbox" class="toggle-checkbox">
        <input type="checkbox" id="toggle-game-checkbox" class="toggle-checkbox">
        

        <?php
        // This logic ensures the hidden checkbox that opens the upload modal
        // is present for ALL users who are allowed to see and use the upload button.
        // The variables $upload_allowed_role, $user_level, and $required_level
        // are already defined earlier in this file.
        if (isset($_SESSION['user_id']) && !($_SESSION['is_guest'] ?? true) && $user_level >= $required_level):
        ?>
            <input type="checkbox" id="toggle-upload-checkbox" class="toggle-checkbox">
        <?php endif; ?>


        <div class="chat-header">
            <div class="header-buttons-left">
                <?php if (isset($_SESSION['session_id'])): // ONLY SHOW BUTTONS IF LOGGED IN ?>
                    <label for="toggle-chatters-checkbox" class="toggle-button" title="Toggle User List">☰</label>
                    <label for="toggle-rules-checkbox" class="rules-button" title="Rules">!</label>
                    <label for="toggle-game-checkbox" class="toggle-button" title="Game Lobby">🎮</label>
                    <?php if (!($_SESSION['is_guest'] ?? true)): // Member-only buttons ?>
                        <a href="gallery.php" target="_blank" class="toggle-button" title="Image Gallery">🖼️</a>
                        <a href="docs.php" target="_blank" class="toggle-button" title="Documents">📄</a>
                        <a href="zips.php" target="_blank" class="toggle-button" title="ZIP Archives">🗜️</a>
                    <?php endif; ?>
                    <label for="toggle-input-position-checkbox" class="toggle-button" title="Toggle Input Position">↕️</label>
                    <?php
                    // Check for upload permissions
                    $upload_allowed_role = $settings['upload_allowed_roles'] ?? 'admin';
                    $user_level = $role_hierarchy[strtolower($_SESSION['user_role'] ?? 'guest')] ?? 0;
                    $required_level = $role_hierarchy[$upload_allowed_role] ?? 4;

                    if (isset($_SESSION['user_id']) && !($_SESSION['is_guest'] ?? true) && $user_level >= $required_level):
                    ?>
                        <label for="toggle-upload-checkbox" class="toggle-button" title="Upload Files">📤</label>
                    <?php endif; ?>
                <?php else: // If NOT logged in, add a placeholder to maintain title centering ?>
                    <div style="width: 60px;">&nbsp;</div>
                <?php endif; ?>
            </div>

            <h1>Rot-Chat</h1>

            <div class="header-buttons-right">
                <?php if (isset($_SESSION['session_id'])): // ONLY SHOW BUTTONS IF LOGGED IN ?>
                    <label for="toggle-profile-expand-checkbox" class="toggle-button" title="Expand Profile">↔️</label>
                    <label for="toggle-profile-checkbox" id="profile-label" class="toggle-profile-button" title="Settings">⚙️</label>
                    <form method="post" class="logout-header-form"><input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>"><button type="submit" name="logout" title="Exit" class="logout-header-button">❌</button></form>
                <?php else: // If NOT logged in, add a placeholder to maintain title centering ?>
                    <div style="width: 60px;">&nbsp;</div>
                <?php endif; ?>
            </div>
        </div>

                <?php
                if (isset($_SESSION['moderation_feedback'])): ?>
                    <div class="moderation-feedback-bar">
                        <?php echo htmlspecialchars($_SESSION['moderation_feedback']); ?>
                    </div>
                <?php
                    unset($_SESSION['moderation_feedback']);
                endif;
                
                if (isset($_SESSION['system_feedback'])): ?>
                    <div class="system-feedback-bar">
                        <?php echo htmlspecialchars($_SESSION['system_feedback']); ?>
                    </div>
                <?php
                    unset($_SESSION['system_feedback']);
                endif;
                ?>

                <?php if (isset($_SESSION['username'])): ?>
                    <?php
                    $settings_stmt = $pdo->query("SELECT * FROM settings");
                    $settings = $settings_stmt->fetchAll(PDO::FETCH_KEY_PAIR);
                    $announcement_message = $settings['announcement_message'] ?? '';
                    $announcement_level = $settings['announcement_level'] ?? 'hidden';
                    $is_member = !($_SESSION['is_guest'] ?? true);
                    $show_announcement = !empty($announcement_message) && ($announcement_level == 'all' || ($announcement_level == 'members' && $is_member));
                    if ($show_announcement):
                    ?>
                        <div class='announcement-bar'>
                            <span class="announcement-message"><?php echo format_announcement($announcement_message); ?></span>
                            <label for="toggle-notes-checkbox" class="announcement-notes-button" title="View Notes">🗒️</label>
                        </div>
                    <?php endif; ?>

                    <div class="main-content">
                        <iframe name="chatters" src="?view=chatters" class="chatters-frame"></iframe>
                        
                        <iframe name="messages" src="?view=messages" class="messages-frame message-pulse"></iframe>
                        
                        <iframe name="game" src="game_lobby.php" class="game-frame"></iframe>
                        
                        <iframe name="profile" src="<?php echo htmlspecialchars($profile_frame_src); ?>" class="profile-frame"></iframe>
                    </div>
                    <iframe name="input" src="?view=input" class="input-frame"></iframe>
                    <?php if (strtolower($_SESSION['user_role'] ?? '') === 'admin'): ?>
                        <div class="admin-footer"><a href="admin.php" target="_blank">Admin Panel</a></div>
                    <?php endif; ?>
                <?php else: ?>
<div class="auth-container">
                        <?php
                        $csrf_token_html = "<input type='hidden' name='csrf_token' value='{$_SESSION['csrf_token']}'/>";
                        $captcha_html = "<div class='captcha-container' style='margin-bottom: 15px;'><img src='captcha.php' alt='Captcha Image'><input type='text' name='captcha' placeholder='Enter text from image' required autocomplete='off'></div>";

                        

                        // --- NEW: Create a reusable and STYLED HTML block for the rules display ---
                        $rules_html = "<div style='margin: 20px 0 15px;'><label for='rules' style='display:block; text-align:center; font-weight:bold; margin-bottom: 8px; color: #ff8888;'>Site Rules</label><textarea id='rules' readonly rows='4' style='width:100%; box-sizing:border-box; background:#111; color:#ccc; border:1px solid #444; padding:10px; font-size:0.9em; text-align:center; resize:none;'>" . htmlspecialchars($stats['site_rules']) . "</textarea></div>";

                        $enable_login_captcha = ($settings['enable_login_captcha'] ?? '0') === '1';
                        if ($view === 'login') { 
                            echo "<form method='post' class='auth-form'><h2>Member Login</h2>{$csrf_token_html}"
                                .($error_message ? "<p class='error-message'>$error_message</p>" : '')
                                .(isset($_GET['registered']) ? "<p class='success-message'>Registered! Please log in.</p>" : '')
                                ."<input type='text' name='username' placeholder='Nickname' required><input type='password' name='password' placeholder='Password' required>";
                                if ($enable_login_captcha) {
                                     echo $captcha_html;
                                }
                                echo $rules_html // Display rules here
                                ."<button type='submit' name='login'>Log In</button><p><a href='?view=register'>Register</a> | <a href='". $_SERVER['PHP_SELF'] ."'>Join as Guest</a></p></form>"; 
                        }
                        elseif ($view === 'register') {
                            $reg_lock_stmt = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'registration_locked'");
                            $is_locked = $reg_lock_stmt->fetchColumn() === '1';
                            $form_html = "<form method='post' class='auth-form'><h2>Register Account</h2>{$csrf_token_html}" . ($error_message ? "<p class='error-message'>$error_message</p>" : '');
                            if ($is_locked) {
                                $form_html .= "<p class='success-message' style='background-color:#003366; color:#cce4ff; border-color:#005599;'>Registration requires a token from an admin.</p>";
                                $form_html .= "<input type='text' name='token' placeholder='Registration Token' required>";
                            }
                            $form_html .= "<input type='text' name='username' placeholder='Choose a nickname' required><input type='password' name='password' placeholder='Choose a password' required>";
                            
                            // --- RULES AND AGREEMENT ---
                            $form_html .= $rules_html; // Display rules here
                            $form_html .= "<div style='margin: 10px 0 15px; display:flex; justify-content: center; align-items:center; gap: 8px;'><input type='checkbox' name='rules_agree' id='rules_agree' required><label for='rules_agree' style='font-size:0.9em;'>I have read and agree to the rules.</label></div>";
                            
                            if ($enable_login_captcha) {
                                 $form_html .= $captcha_html;
                            }
                            $form_html .= "<button type='submit' name='register'>Register</button><p><a href='?view=login'>Already registered? Log In</a></p></form>";
                            echo $form_html;
                        }
                        else { // Guest login form
                             echo "<form method='post' class='auth-form'><h2>Join as a Guest</h2>{$csrf_token_html}"
                                .($error_message ? "<p class='error-message'>$error_message</p>" : '')
                                ."<input type='text' name='username' placeholder='Enter a guest name' required>";
                            if ($enable_login_captcha) {
                                echo $captcha_html;
                            }
                            echo $rules_html // Display rules here
                            ."<button type='submit' name='join_guest'>Enter Chat</button><p>Are you a member? <a href='?view=login'>Log In Here</a></p></form>"; 
                        }
                        ?>
                        <div style="margin-top: 25px; border-top: 1px solid #444; padding-top: 15px; text-align: center;">
                            <a href="polls.php" style="font-weight: bold; margin: 0 10px;">View Polls</a> | 
                            <a href="feedback.php" style="font-weight: bold; margin: 0 10px;">Submit Feedback</a>
                        </div>
                    </div>
                    <?php 
                        // --- NEW, GRANULAR STATS DISPLAY WITH HOVER LIST ---
                        $stats_to_display = [];
                        if (($settings['stats_show_total_members'] ?? '1') === '1') {
                            $stats_to_display[] = "Registered Members: <strong>" . htmlspecialchars($stats['total_members']) . "</strong>";
                        }
                        if (($settings['stats_show_messages_today'] ?? '1') === '1') {
                            $stats_to_display[] = "Messages Today: <strong>" . htmlspecialchars($stats['messages_today']) . "</strong>";
                        }
                        if (($settings['stats_show_online_total'] ?? '0') === '1') {
                            $online_stat_html = '<span class="stat-item">Online Now: <strong>' . htmlspecialchars($stats['online_total']) . '</strong>';
                            $online_stat_html .= '<div class="online-users-tooltip"><strong>Online Users:</strong><ul>';
                            if (empty($online_users_list)) {
                                $online_stat_html .= '<li>No one is online.</li>';
                            } else {
                                foreach ($online_users_list as $user) {
                                    $online_stat_html .= '<li>' . htmlspecialchars($user) . '</li>';
                                }
                            }
                            $online_stat_html .= '</ul></div></span>';
                            $stats_to_display[] = $online_stat_html;
                        }
                        if (($settings['stats_show_online_guests'] ?? '0') === '1') {
                            $stats_to_display[] = "Guests Online: <strong>" . htmlspecialchars($stats['online_guests']) . "</strong>";
                        }
                        
                        if (!empty($stats_to_display)):
                    ?>
                        <div class='site-stats' style='text-align: center; color: #888; margin-top: 25px; font-size: 0.9em;'>
                            <?php echo implode(' | ', $stats_to_display); ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>  


                

                <div class="rules-modal-overlay"><div class="rules-modal-content"><label for="toggle-rules-checkbox" class="close-rules-button">×</label><h2>Rules</h2><ul><li>No CP</li><li>-</li><li>-</li></ul></div></div>
                <div class="notes-modal-overlay">
                    <div class="notes-modal-content">
                        <label for="toggle-notes-checkbox" class="close-notes-button">×</label>
                        <h2>Notes & Updates</h2>
                        <?php
                        if (isset($_SESSION['notes_feedback'])) {
                            $feedback = $_SESSION['notes_feedback'];
                            echo "<div class='notes-feedback {$feedback['type']}'>" . htmlspecialchars($feedback['message']) . "</div>";
                            unset($_SESSION['notes_feedback']);
                        }
                        $notes_settings = $pdo->query("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('public_notes', 'admin_notes')")->fetchAll(PDO::FETCH_KEY_PAIR);
                        $public_notes = $notes_settings['public_notes'] ?? '';
                        $admin_notes = $notes_settings['admin_notes'] ?? '';
                        $actor_role = strtolower($_SESSION['user_role'] ?? 'user');
                        if ($actor_role === 'admin' || $actor_role === 'moderator'):
                        ?>
                            <form method="post" class="notes-edit-form">
                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                <div class="notes-section">
                                    <h4>Public Notes (Visible to all)</h4>
                                    <textarea name="public_notes"><?php echo htmlspecialchars($public_notes); ?></textarea>
                                </div>
                                <div class="notes-section">
                                    <h4>Admin Notes (Mods & Admins only)</h4>
                                    <textarea name="admin_notes"><?php echo htmlspecialchars($admin_notes); ?></textarea>
                                </div>
                                <button type="submit" name="update_notes">Save Notes</button>
                            </form>
                        <?php else: ?>
                            <div class="notes-section">
                                <h4>Public Notes</h4>
                                <p><?php echo format_notes_content($public_notes); ?></p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

<?php
                // The $upload_allowed_role, $user_level, $required_level variables are set earlier in the file.
                // This ensures the entire modal HTML is only present if the user is allowed to upload,
                // matching the visibility of the button and its controlling checkbox.
                if (isset($_SESSION['user_id']) && !($_SESSION['is_guest'] ?? true) && $user_level >= $required_level):
                ?>
                <div class="upload-modal-overlay">
                    <div class="upload-modal-content">
                        <label for="toggle-upload-checkbox" class="close-upload-button">×</label>
                        <h2>Upload File</h2>
                        <p style="text-align:center; font-weight: bold; color: #ffc2c2;"><?php echo $upload_message; ?></p>
                        <form action="upload_handler.php" method="post" enctype="multipart/form-data" target="_top">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? ''); ?>">
                            <div class="form-group">
                                <label for="file_upload">File</label>
                                <input type="file" name="file_upload" id="file_upload" required class="upload-file-input">
                            </div>
                            <div class="form-group">
                                <label for="link_name">Link Text (Optional)</label>
                                <input type="text" name="link_name" id="link_name" placeholder="e.g., My Cool File" style="width: 100%; padding: 10px; box-sizing: border-box;">
                            </div>
                            <hr style="border-color: #333; margin: 20px 0;">
                            <div class="form-group">
                                <label for="expires_in_days">Expire After (Days)</label>
                                <input type="number" name="expires_in_days" id="expires_in_days" placeholder="Leave blank for indefinite">
                            </div>
                            <div class="form-group">
                                <label for="max_views">Expire After (Views)</label>
                                <input type="number" name="max_views" id="max_views" placeholder="Leave blank for unlimited">
                            </div>
                            <button type="submit" name="submit_upload" class="upload-submit-btn">Upload and Post Link</button>
                        </form>
                    </div>
                </div>
                <?php endif; ?>

            </div>

</div>


</body>
</html>
    <?php
    } // End of the new else block
break;
}
?>