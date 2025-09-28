<?php
/**
 * Gets the real client IP address, considering proxies.
 * @return string The client's IP address.
 */
function get_client_ip() {
    $ip_address = 'UNKNOWN';
    if (isset($_SERVER['HTTP_CLIENT_IP']) && filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP)) {
        $ip_address = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        foreach ($ips as $ip) {
            $ip = trim($ip);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                $ip_address = $ip;
                break;
            }
        }
    } elseif (isset($_SERVER['REMOTE_ADDR']) && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
        $ip_address = $_SERVER['REMOTE_ADDR'];
    }
    return $ip_address;
}


/**
 * Parses announcement text for URLs and BBCode, converting them to safe HTML links.
 * - Converts [url=http://...]Text[/url] into a clickable link.
 * - Auto-links standalone URLs (http://, https://).
 * This function processes BBCode first, then sanitizes and linkifies the remaining plain text.
 *
 * @param string $text The raw announcement text from the database.
 * @return string The processed text with HTML <a> tags.
 */
function format_announcement($text) {
    // Pass 1: Handle the [url=...] BBCode. This gives it priority.
    // The text inside the tag is sanitized. The URL is sanitized for the href.
    $processed_text = preg_replace_callback(
        '/\[url=(https?:\/\/[^\]]+)\](.*?)\[\/url\]/si',
        function ($matches) {
            $url = $matches[1];
            $link_text = $matches[2];
            // Ensure the URL is valid before creating a link
            if (filter_var($url, FILTER_VALIDATE_URL)) {
                 return '<a href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener noreferrer">' . htmlspecialchars($link_text, ENT_QUOTES, 'UTF-8') . '</a>';
            }
            // If URL is invalid, just return the original text which will be sanitized later
            return htmlspecialchars($matches[0], ENT_QUOTES, 'UTF-8');
        },
        $text
    );

    // Pass 2: Sanitize the remaining plain text and linkify any standalone URLs.
    // To do this safely, we split the string by the <a> tags we just created.
    $parts = preg_split('/(<a.*?\/a>)/s', $processed_text, -1, PREG_SPLIT_DELIM_CAPTURE);
    
    $result = '';
    foreach ($parts as $part) {
        if (strpos($part, '<a') === 0) {
            // This part is already a safe HTML link from Pass 1, so add it as is.
            $result .= $part;
        } else {
            // This part is plain text. Sanitize it first.
            $safe_part = htmlspecialchars($part, ENT_QUOTES, 'UTF-8');
            
            // Now, linkify any standalone URLs within this sanitized part.
            $linked_part = preg_replace(
                '/\b(https?:\/\/[^\s<>()]+)/i',
                '<a href="$0" target="_blank" rel="noopener noreferrer">$0</a>',
                $safe_part
            );
            $result .= $linked_part;
        }
    }

    return $result;
}

/**
 * Generates a fingerprint based on a combination of HTTP headers.
 * This is more persistent than a session, but can be the same for multiple users
 * running identical browser/OS versions (e.g., Tor Browser).
 * @return string The SHA256 hash of the combined headers.
 */
function generate_header_fingerprint() {
    $data_string = ($_SERVER['HTTP_USER_AGENT'] ?? '') . 
                   ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') .
                   ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '') .
                   ($_SERVER['HTTP_ACCEPT'] ?? '');
    
    // Return a hash of the combined string.
    return hash('sha256', $data_string);
}

/**
 * Parses text with simple BBCode-like tags for notes.
 * @param string $text The raw text from the database.
 * @return string The processed text with HTML tags.
 */
function format_notes_content($text) {
    if (empty($text)) {
        return '';
    }
    // 1. Sanitize the entire input to prevent XSS
    $safe_text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');

    // 2. Define BBCode patterns and their HTML replacements
    $patterns = [
        '/\[b\](.*?)\[\/b\]/is',
        '/\[i\](.*?)\[\/i\]/is',
        '/\[u\](.*?)\[\/u\]/is',
        '/\[color=([a-fA-F0-9#]{3,7})\](.*?)\[\/color\]/is'
    ];
    $replacements = [
        '<strong>$1</strong>',
        '<em>$1</em>',
        '<u>$1</u>',
        '<span style="color: $1;">$2</span>'
    ];

    // 3. Apply the replacements
    $formatted_text = preg_replace($patterns, $replacements, $safe_text);

    // 4. Convert newlines to <br> tags for display
    return nl2br($formatted_text);
}



/**
 * Promotes a guest to a full member account.
 *
 * @param PDO $pdo The database connection object.
 * @param int $guest_id The ID of the guest to promote.
 * @param string|null $session_id The guest's current session ID.
 * @return array An array with 'success' (boolean) and 'message' (string).
 */
function promote_guest_to_member($pdo, $guest_id, $session_id) {
    if (!$guest_id || !$session_id) {
        return ['success' => false, 'message' => 'Missing guest or session ID.'];
    }

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
        $sql = "INSERT INTO users (username, password_hash, color, show_login_msgs, show_system_msgs, refresh_rate, role, message_count) 
                VALUES (?, ?, ?, ?, ?, ?, 'user', ?)";
        $pdo->prepare($sql)->execute([
            $guest['username'], $password_hash, $guest['color'],
            $guest['show_login_msgs'], $guest['show_system_msgs'], $guest['refresh_rate'], $guest['message_count']
        ]);
        $new_user_id = $pdo->lastInsertId();

        // 5. MIGRATE OWNERSHIP: Re-assign all of the guest's messages to their new user_id
        $pdo->prepare("UPDATE messages SET user_id = ?, guest_id = NULL WHERE guest_id = ?")
            ->execute([$new_user_id, $guest_id]);

        // 6. Flag the user's session with the temporary password for the notification banner
        $pdo->prepare("UPDATE sessions SET promoted_temp_pass = ? WHERE session_id = ?")
            ->execute([$temp_pass, $session_id]);
        
        // 7. Delete the old guest record now that messages are migrated
        $pdo->prepare("DELETE FROM guests WHERE id = ?")->execute([$guest_id]);
        
        $pdo->commit();
        return ['success' => true, 'message' => "Guest '".htmlspecialchars($guest['username'])."' promoted! Their messages have been migrated."];

    } catch (Exception $e) {
        $pdo->rollBack();
        return ['success' => false, 'message' => "Error promoting guest: " . $e->getMessage()];
    }
}


/**
 * Renders a full-page, styled CSRF token error message.
 * This should be used whenever a CSRF check fails.
 * @param string $message The specific error message to display.
 */
function render_csrf_error_page($message = 'Invalid or expired security token. Please go back, refresh the page, and try again.') {
    // Explicitly set headers to prevent caching and ensure HTML content type
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    // Start output buffering
    ob_start();
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Token Error</title>
        <link rel="stylesheet" href="style.css"> 
    </head>
    <body>
        <div class="chat-container">
             <div class="auth-container">
                <div class="auth-form" style="border-color: #cc0000; box-shadow: 0 0 25px rgba(204, 0, 0, 0.7);">
                    <h2 style="color: #ff3333;">Security Error</h2>
                    <p class="error-message">
                        <?php echo htmlspecialchars($message); ?>
                    </p>
                    <p style="color: #999; font-size: 0.9em;">
                        This is a security measure to protect your account.
                    </p>
                    <a href="chat.php" target="_top" style="background-color:#610000; border-color:#990000; color: #ffc2c2;">Return to Chat</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
    echo ob_get_clean();
    die();
}

/**
 * Renders a full-page, styled error message and terminates the script.
 *
 * @param string $title The title for the error page.
 * @param string $message The specific error message to display.
 */
function render_error_page($title, $message) {
    http_response_code(404); // Use 404 Not Found as a general code
    $html = <<<HTML
    <!DOCTYPE html><html lang="en"><head><title>{$title}</title><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="admin_style.css">
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
                <h1>{$title}</h1>
            </header>
            <p>{$message}</p>
            <a href="chat.php" class="back-link">Return to Chat</a>
        </div>
    </body></html>
HTML;
    die($html);
}

/**
 * Renders a full-page, styled ban message and terminates the script.
 * This should be used when a fingerprint ban is detected.
 * @param string $reason The reason for the ban.
 */
function render_ban_page($reason = 'Your device has been banned.') {
    // Explicitly set headers to prevent caching and ensure HTML content type
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    // Securely destroy any session that might exist
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    @session_destroy();

    // Start output buffering
    ob_start();
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Access Denied</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="chat-container">
             <div class="auth-container">
                <div class="auth-form" style="border-color: #cc0000; box-shadow: 0 0 25px rgba(204, 0, 0, 0.7);">
                    <h2 style="color: #ff3333;">Access Denied</h2>
                    <p class="error-message">
                        <?php echo htmlspecialchars($reason); ?>
                    </p>
                    <p style="color: #999; font-size: 0.9em;">
                        Access Denied.
                    </p>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
    echo ob_get_clean();
    die();
}

?>