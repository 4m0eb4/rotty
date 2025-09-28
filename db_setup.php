<?php
// db_setup.php (V15 - Consolidated & Repaired with all features)

ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once 'config.php';

echo "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>Database Setup</title>";
echo "<style>body { font-family: monospace; background: #111; color: #eee; padding: 20px; line-height: 1.6; } .success { color: #7f7; } .error { color: #f77; } .info { color: #77f; } hr { border-color: #333; }</style>";
echo "</head><body><h1>Rot-Chat Database Setup & Repair (V15)</h1>";

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "<p class='success'>Database connection successful.</p><hr>";

    // --- Table: users ---
    echo "<p>Checking 'users' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `users` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `username` VARCHAR(50) NOT NULL UNIQUE,
        `password_hash` VARCHAR(255) NULL,
        `role` ENUM('user', 'trusted', 'moderator', 'admin') NOT NULL DEFAULT 'user',
        `color` VARCHAR(7) NOT NULL DEFAULT '#ffffff',
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `last_seen` DATETIME NULL DEFAULT NULL,
        `is_banned` TINYINT(1) NOT NULL DEFAULT 0,
        `is_deactivated` TINYINT(1) NOT NULL DEFAULT 0,
        `kick_cooldown_until` DATETIME NULL DEFAULT NULL,
        `last_login_ip` VARCHAR(45) NULL DEFAULT NULL,
        `show_login_msgs` TINYINT(1) NOT NULL DEFAULT 0,
        `show_system_msgs` TINYINT(1) NOT NULL DEFAULT 1,
        `refresh_rate` INT NOT NULL DEFAULT 5,
        `custom_css` TEXT NULL DEFAULT NULL,
        `pgp_public_key` TEXT NULL DEFAULT NULL,
        `allow_offline_pm` TINYINT(1) NOT NULL DEFAULT 1,
        `is_hidden` TINYINT(1) NOT NULL DEFAULT 0,
        `registration_token` VARCHAR(64) NULL DEFAULT NULL UNIQUE,
        `moderator_notes` TEXT NULL DEFAULT NULL,
        `can_post_links` TINYINT(1) NOT NULL DEFAULT 0,
        `promoted_temp_pass` VARCHAR(255) NULL DEFAULT NULL,
        `message_count` INT NOT NULL DEFAULT 0,
        `enable_visual_effects` TINYINT(1) NULL DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'users' table exists.</p>";
    
    // Alter statements for existing columns or new ones
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `last_seen` DATETIME NULL DEFAULT NULL AFTER `created_at`;"); echo "<p class='info'>Added 'last_seen' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'last_seen' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` MODIFY `password_hash` VARCHAR(255) NULL;"); echo "<p class='info'>Modified 'password_hash' to allow NULL for unclaimed accounts.</p>"; } catch (PDOException $e) { echo "<p class='info'>'password_hash' column already allows NULL.</p>"; }
    
    // Alter statements for existing columns or new ones
    try { $pdo->exec("ALTER TABLE `users` MODIFY `password_hash` VARCHAR(255) NULL;"); echo "<p class='info'>Modified 'password_hash' to allow NULL for unclaimed accounts.</p>"; } catch (PDOException $e) { echo "<p class='info'>'password_hash' column already allows NULL.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `is_banned` TINYINT(1) NOT NULL DEFAULT 0;"); echo "<p class='info'>Added 'is_banned' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'is_banned' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `is_deactivated` TINYINT(1) NOT NULL DEFAULT 0 AFTER `is_banned`;"); echo "<p class='info'>Added 'is_deactivated' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'is_deactivated' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `kick_cooldown_until` DATETIME NULL DEFAULT NULL;"); echo "<p class='info'>Added 'kick_cooldown_until' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'kick_cooldown_until' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `last_login_ip` VARCHAR(45) NULL DEFAULT NULL;"); echo "<p class='info'>Added 'last_login_ip' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'last_login_ip' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` MODIFY COLUMN `role` ENUM('user','trusted','moderator','admin') NOT NULL DEFAULT 'user';"); echo "<p class='info'>Updated 'role' ENUM in 'users' table to include 'trusted' and 'moderator'.</p>"; } catch (PDOException $e) { echo "<p class='info'>'role' ENUM in 'users' table is already updated.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `show_login_msgs` TINYINT(1) NOT NULL DEFAULT 0;"); echo "<p class='info'>Added 'show_login_msgs' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'show_login_msgs' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `show_system_msgs` TINYINT(1) NOT NULL DEFAULT 1;"); echo "<p class='info'>Added 'show_system_msgs' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'show_system_msgs' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `refresh_rate` INT NOT NULL DEFAULT 5;"); echo "<p class='info'>Added 'refresh_rate' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'refresh_rate' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `custom_css` TEXT NULL DEFAULT NULL;"); echo "<p class='info'>Added 'custom_css' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'custom_css' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `pgp_public_key` TEXT NULL DEFAULT NULL AFTER `custom_css`;"); echo "<p class='info'>Added 'pgp_public_key' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'pgp_public_key' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `allow_offline_pm` TINYINT(1) NOT NULL DEFAULT 1;"); echo "<p class='info'>Added 'allow_offline_pm' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'allow_offline_pm' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `is_hidden` TINYINT(1) NOT NULL DEFAULT 0;"); echo "<p class='info'>Added 'is_hidden' column to 'users' table for moderator privacy.</p>"; } catch (PDOException $e) { echo "<p class='info'>'is_hidden' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `registration_token` VARCHAR(64) NULL DEFAULT NULL UNIQUE;"); echo "<p class='info'>Added 'registration_token' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'registration_token' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `moderator_notes` TEXT NULL DEFAULT NULL AFTER `pgp_public_key`;"); echo "<p class='info'>Added 'moderator_notes' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'moderator_notes' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `can_post_links` TINYINT(1) NOT NULL DEFAULT 0;"); echo "<p class='info'>Added 'can_post_links' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'can_post_links' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `promoted_temp_pass` VARCHAR(255) NULL DEFAULT NULL;"); echo "<p class='info'>Added 'promoted_temp_pass' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'promoted_temp_pass' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `message_count` INT NOT NULL DEFAULT 0;"); echo "<p class='info'>Added 'message_count' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'message_count' column already exists in 'users'.</p>"; }
    try { $pdo->exec("ALTER TABLE `users` ADD COLUMN `enable_visual_effects` TINYINT(1) NULL DEFAULT NULL;"); echo "<p class='info'>Added 'enable_visual_effects' column to 'users' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'enable_visual_effects' column already exists in 'users'.</p>"; }
    echo "<p class='success'>'users' table OK.</p><hr>";

// --- Table: guests ---
echo "<p>Checking 'guests' table...</p>";
$pdo->exec("CREATE TABLE IF NOT EXISTS `guests` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL,
    `color` VARCHAR(7) NOT NULL DEFAULT '#ffffff',
    `show_login_msgs` TINYINT(1) NOT NULL DEFAULT 0,
    `show_system_msgs` TINYINT(1) NOT NULL DEFAULT 1,
    `message_count` INT NOT NULL DEFAULT 0,
    `message_limit` INT NOT NULL DEFAULT 50,
    `kick_cooldown_until` DATETIME NULL DEFAULT NULL,
    `fingerprint` VARCHAR(128) NULL DEFAULT NULL,
    `last_login_ip` VARCHAR(45) NULL DEFAULT NULL,
    `refresh_rate` INT NOT NULL DEFAULT 5,
    `status` ENUM('active','promoted') NOT NULL DEFAULT 'active',
    `can_post_links` TINYINT(1) NOT NULL DEFAULT 0,
    `enable_visual_effects` TINYINT(1) NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
echo "<p class='info'>Ensured 'guests' table exists and is fully up-to-date.</p>";

// Drop the old unique index if it exists, then add a non-unique one.
try {
    // This will fail if the index doesn't exist, which is fine.
    $pdo->exec("ALTER TABLE `guests` DROP INDEX `fingerprint_idx`;");
    echo "<p class='info'>Removed old unique index from 'guests' table.</p>";
} catch (PDOException $e) {
    echo "<p class='info'>No old unique index to remove, or it was already removed.</p>";
}
// Add a non-unique index for performance.
try {
    $pdo->exec("ALTER TABLE `guests` ADD INDEX `fingerprint_idx` (`fingerprint`);");
    echo "<p class='info'>Ensured a non-unique 'fingerprint' index exists for performance.</p>";
} catch (PDOException $e) {
    echo "<p class='info'>Non-unique 'fingerprint' index already exists.</p>";
}

echo "<p class='success'>'guests' table OK.</p><hr>";

    // --- Table: ban_list ---
    echo "<p>Checking 'ban_list' table...</p>";
    try { $pdo->exec("DROP TABLE IF EXISTS `ip_bans`;"); echo "<p class='info'>Removed obsolete 'ip_bans' table if it existed.</p>"; } catch (PDOException $e) { /* Ignore */ }
    $pdo->exec("CREATE TABLE IF NOT EXISTS `ban_list` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `ban_type` ENUM('ip', 'fingerprint') NOT NULL,
        `ban_value` VARCHAR(128) NOT NULL,
        `reason` TEXT NULL,
        `banned_by_user_id` INT NULL,
        `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `banned_until` DATETIME NULL DEFAULT NULL,
        UNIQUE INDEX `ban_idx` (`ban_type`, `ban_value`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'ban_list' table exists.</p>";
    try { $pdo->exec("ALTER TABLE `ban_list` ADD COLUMN `banned_until` DATETIME NULL DEFAULT NULL AFTER `created_at`;"); echo "<p class='info'>Added 'banned_until' column to 'ban_list' for temporary bans.</p>"; } catch (PDOException $e) { echo "<p class='info'>'banned_until' column already exists in 'ban_list'.</p>"; }
    echo "<p class='success'>'ban_list' table OK.</p><hr>";

// --- Table: guest_name_bans ---
echo "<p>Checking 'guest_name_bans' table for temporary cooldowns...</p>";
$pdo->exec("CREATE TABLE IF NOT EXISTS `guest_name_bans` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `banned_by_user_id` INT NULL,
    `banned_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `reason` VARCHAR(255) NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
echo "<p class='info'>Ensured 'guest_name_bans' table (for temporary bans) exists.</p>";
try { $pdo->exec("ALTER TABLE `guest_name_bans` MODIFY COLUMN `banned_until` DATETIME NOT NULL;"); echo "<p class='info'>Modified 'banned_until' to be NOT NULL.</p>"; } catch (PDOException $e) { echo "<p class='info'>'banned_until' column already updated.</p>"; }
echo "<p class='success'>'guest_name_bans' table OK.</p><hr>";

// --- NEW TABLE: banned_guest_names (for permanent bans) ---
echo "<p>Checking 'banned_guest_names' table for permanent bans...</p>";
$pdo->exec("CREATE TABLE IF NOT EXISTS `banned_guest_names` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `reason` TEXT NULL,
    `banned_by_user_id` INT NOT NULL,
    `banned_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`banned_by_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
echo "<p class='info'>Ensured 'banned_guest_names' table (for permanent bans) exists.</p>";
echo "<p class='success'>'banned_guest_names' table OK.</p><hr>";

    // --- Table: messages ---
    echo "<p>Checking 'messages' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `messages` (
        `id` INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
        `user_id` INT(11) DEFAULT NULL,
        `guest_id` INT(11) DEFAULT NULL,
        `username` VARCHAR(50) NOT NULL,
        `color` VARCHAR(7) NOT NULL,
        `message` TEXT NOT NULL,
        `is_system_message` TINYINT(1) NOT NULL DEFAULT 0,
        `channel` VARCHAR(50) NOT NULL DEFAULT 'general',
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `replying_to_message_id` INT(11) NULL DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'messages' table exists.</p>";
    try { $pdo->exec("ALTER TABLE `messages` ADD COLUMN `delete_at` DATETIME NULL DEFAULT NULL;"); echo "<p class='info'>Added 'delete_at' column to 'messages' table for expiring messages.</p>"; } catch (PDOException $e) { echo "<p class='info'>'delete_at' column already exists in 'messages'.</p>"; }
    echo "<p class='success'>'messages' table OK.</p><hr>";

    // --- Table: sessions ---
    echo "<p>Checking 'sessions' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `sessions` (
        `session_id` VARCHAR(128) NOT NULL PRIMARY KEY,
        `user_id` INT NULL DEFAULT NULL,
        `guest_id` INT NULL DEFAULT NULL,
        `username` VARCHAR(50) NOT NULL,
        `is_guest` TINYINT(1) NOT NULL DEFAULT 0,
        `status` ENUM('online','afk') NOT NULL DEFAULT 'online',
        `afk_message` VARCHAR(100) NULL DEFAULT NULL,
        `last_active` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `kick_message` TEXT NULL DEFAULT NULL,
        `promoted_temp_pass` VARCHAR(255) NULL DEFAULT NULL,
        `is_shadow_kicked` TINYINT(1) NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'sessions' table exists.</p>";
    try { $pdo->exec("ALTER TABLE `sessions` ADD COLUMN `afk_message` VARCHAR(100) NULL DEFAULT NULL AFTER `status`;"); echo "<p class='info'>Added 'afk_message' column to 'sessions' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'afk_message' column already exists in 'sessions'.</p>"; }
    echo "<p class='success'>'sessions' table OK.</p><hr>";
    // --- Table: settings (Corrected & Consolidated) ---
echo "<p>Checking 'settings' table...</p>";
$pdo->exec("CREATE TABLE IF NOT EXISTS `settings` (
    `setting_key` VARCHAR(64) NOT NULL PRIMARY KEY,
    `setting_value` TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
echo "<p class='info'>Ensured 'settings' table exists.</p>";

// Insert ALL default settings at once
$pdo->exec("INSERT IGNORE INTO `settings` (`setting_key`, `setting_value`) VALUES
    ('announcement_message', ''),
    ('announcement_level', 'hidden'),
    ('chat_locked', '0'),
    ('public_notes', 'Welcome to Rot-Chat!'),
    ('admin_notes', 'Admin notes here.'),
    ('system_message_level', 'all'),
    ('chat_border_color', '#cc0000'),
    ('chat_glow_color', 'linear-gradient(to bottom, #cc0000, #ff00ff)'),
    ('title_animation', '1'),
    ('banned_words_list', 'viagra,casino,cialis'),
    ('special_effect', 'none'),
    ('guest_default_tokens', '50'),
    ('chat_history_limit', '150'),
    ('banned_name_words_list', 'admin,moderator,support,system'),
    ('upload_allowed_roles', 'user'),
    ('upload_allowed_roles_docs', 'user'),
    ('upload_allowed_roles_zips', 'user'),
    ('view_allowed_roles_images', 'user'),
    ('view_allowed_roles_docs', 'user'),
    ('view_allowed_roles_zips', 'user'),
    ('upload_limit_user', '5'),
    ('upload_limit_trusted', '20'),
    ('upload_limit_moderator', '50'),
    ('allowed_file_types', 'jpg,jpeg,png,gif,mp4,webp,pdf,zip'),
    ('max_file_size_kb', '2048'),
    ('registration_locked', '0'),
    ('default_enable_visual_effects', '1'),
    ('site_rules', '1. Be respectful.\n2. No spamming or flooding the chat.\n3. Do not share illegal content.'),
    ('stats_show_total_members', '1'),
    ('stats_show_messages_today', '1'),
    ('stats_show_online_total', '0'),
    ('stats_show_online_guests', '0'),
    ('trusted_delete_mode', 'own'),
    ('known_roles', 'admin,moderator,supermod,trusted,member,guest'),
    ('roles_delete_any', 'admin,moderator,supermod'),
    ('roles_delete_own', 'trusted,member');
");
echo "<p class='info'>Ensured default settings are present.</p>";
echo "<p class='success'>'settings' table OK.</p><hr>";

// ... code that creates the settings table ...

echo "<p class='info'>Ensured default settings are present.</p>";
echo "<p class='success'>'settings' table OK.</p><hr>";

// --- Role configuration (CSV lists; lower-case role names) ---  <-- PASTE IT BEFORE THIS LINE
$pdo->exec("
    INSERT IGNORE INTO settings (setting_key, setting_value) VALUES
    ('known_roles', 'admin,moderator,supermod,trusted,member,guest'),
    ('roles_delete_any', 'admin,moderator,supermod'),
    ('roles_delete_own', 'trusted,member')
");

// --- Table: channels ---
// ... rest of the file ...
    // --- Table: private_messages ---
    echo "<p>Checking 'private_messages' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `private_messages` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `from_user_id` INT NOT NULL,
        `to_user_id` INT NOT NULL,
        `message` TEXT NOT NULL,
        `is_read` TINYINT(1) NOT NULL DEFAULT 0,
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `is_system_message` TINYINT(1) NOT NULL DEFAULT 0,
        `pm_destroy_status` TINYINT(1) NOT NULL DEFAULT 0,
        INDEX `from_user_idx` (`from_user_id`),
        INDEX `to_user_idx` (`to_user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'private_messages' table exists.</p>";
    echo "<p class='success'>'private_messages' table OK.</p><hr>";

    // --- Table: kick_logs ---
    echo "<p>Checking 'kick_logs' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `kick_logs` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `kicked_user_id` INT NULL,
        `kicked_guest_id` INT NULL,
        `kicked_username` VARCHAR(50) NOT NULL,
        `kicked_user_ip` VARCHAR(45) NULL,
        `kicked_user_fingerprint` VARCHAR(128) NULL,
        `moderator_user_id` INT NULL, -- Changed to NULL to allow system kicks
        `moderator_username` VARCHAR(50) NOT NULL,
        `kick_reason` TEXT NULL,
        `chat_history` TEXT NOT NULL,
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'kick_logs' table exists.</p>";
    try { $pdo->exec("ALTER TABLE `kick_logs` MODIFY COLUMN `moderator_user_id` INT NULL;"); echo "<p class='info'>Modified 'moderator_user_id' to allow NULL in 'kick_logs'.</p>"; } catch (PDOException $e) { echo "<p class='info'>'moderator_user_id' column already allows NULL.</p>"; }
    echo "<p class='success'>'kick_logs' table OK.</p><hr>";

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


    // --- Table: archived_messages ---
    echo "<p>Checking 'archived_messages' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `archived_messages` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `original_message_id` INT NOT NULL,
        `user_id` INT NULL,
        `guest_id` INT NULL,
        `username` VARCHAR(50) NOT NULL,
        `color` VARCHAR(7) NOT NULL,
        `message` TEXT NOT NULL,
        `channel` VARCHAR(50) NOT NULL,
        `created_at` TIMESTAMP NOT NULL,
        `archived_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `archived_by_user_id` INT NOT NULL,
        `archive_reason` VARCHAR(255) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'archived_messages' table exists.</p>";
    echo "<p class='success'>'archived_messages' table OK.</p><hr>";

    // --- Table: feedback ---
    echo "<p>Checking 'feedback' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `feedback` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `submitter_id` VARCHAR(50) NOT NULL,
        `submitter_ip` VARCHAR(45) NOT NULL,
        `submitter_fingerprint` VARCHAR(128) NULL,
        `submission_type` ENUM('Suggestion', 'Bug Report', 'Poll', 'Other') NOT NULL,
        `subject` VARCHAR(255) NOT NULL,
        `content` TEXT NOT NULL,
        `admin_reply` TEXT NULL DEFAULT NULL,
        `replied_by_user_id` INT NULL DEFAULT NULL,
        `replied_at` TIMESTAMP NULL DEFAULT NULL,
        `status` ENUM('New', 'Reviewed', 'In Progress', 'Resolved', 'Archived') NOT NULL DEFAULT 'New',
        `is_poll` TINYINT(1) NOT NULL DEFAULT 0,
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'feedback' table exists.</p>";
    echo "<p class='success'>'feedback' table OK.</p><hr>";

    // --- Table: poll_votes ---
    echo "<p>Checking 'poll_votes' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `poll_votes` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `poll_id` INT NOT NULL,
        `voter_fingerprint` VARCHAR(128) NOT NULL,
        `vote` TINYINT(1) NOT NULL,
        `voted_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX `poll_id_idx` (`poll_id`),
        UNIQUE INDEX `poll_voter_idx` (`poll_id`, `voter_fingerprint`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'poll_votes' table exists.</p>";
    echo "<p class='success'>'poll_votes' table OK.</p><hr>";
    
    // --- Table: games ---
    echo "<p>Checking 'games' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `games` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `game_uuid` VARCHAR(32) NOT NULL UNIQUE,
        `board_size` TINYINT NOT NULL,
        `current_turn` TINYINT NOT NULL DEFAULT 1,
        `game_state` JSON NOT NULL,
        `status` ENUM('waiting', 'active', 'finished') NOT NULL DEFAULT 'waiting',
        `winner_player_number` TINYINT NULL DEFAULT NULL,
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX `status_idx` (`status`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'games' table exists.</p>";
    echo "<p class='success'>'games' table OK.</p><hr>";

    // --- Table: game_players ---
    echo "<p>Checking 'game_players' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `game_players` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `game_id` INT NOT NULL,
        `user_id` INT NULL DEFAULT NULL,
        `guest_id` INT NULL DEFAULT NULL,
        `player_number` TINYINT NOT NULL,
        UNIQUE INDEX `game_user_idx` (`game_id`, `user_id`),
        UNIQUE INDEX `game_guest_idx` (`game_id`, `guest_id`),
        INDEX `user_id_idx` (`user_id`),
        FOREIGN KEY (`game_id`) REFERENCES `games`(`id`) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'game_players' table exists and is updated for guest players.</p>";
    echo "<p class='success'>'game_players' table OK.</p><hr>";

    // --- Table: uploads ---
    echo "<p>Checking 'uploads' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `uploads` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `user_id` INT NOT NULL,
        `upload_type` ENUM('image', 'document', 'zip', 'audio') NOT NULL DEFAULT 'image',
        `original_filename` VARCHAR(255) NOT NULL,
        `unique_filename` VARCHAR(255) NOT NULL UNIQUE,
        `file_path` VARCHAR(255) NOT NULL,
        `mime_type` VARCHAR(100) NOT NULL,
        `file_size` INT NOT NULL,
        `file_hash` VARCHAR(64) NULL DEFAULT NULL UNIQUE,
        `link_text` VARCHAR(255) NULL,
        `thumbnail_path` VARCHAR(255) NULL DEFAULT NULL,
        `expires_at` DATETIME NULL DEFAULT NULL,
        `max_views` INT NULL DEFAULT NULL,
        `current_views` INT NOT NULL DEFAULT 0,
        `download_count` INT NOT NULL DEFAULT 0,
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX `user_id_idx` (`user_id`),
        INDEX `upload_type_idx` (`upload_type`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'uploads' table exists.</p>";

    // This command will modify the existing table to add the 'audio' type if needed.
    try { $pdo->exec("ALTER TABLE `uploads` MODIFY COLUMN `upload_type` ENUM('image', 'document', 'zip', 'audio') NOT NULL DEFAULT 'image';"); echo "<p class='info'>Updated 'upload_type' column in 'uploads' table to include 'audio'.</p>"; } catch (PDOException $e) { echo "<p class='error'>Could not update 'upload_type' column. Manual check required.</p>"; }
    
    try { $pdo->exec("ALTER TABLE `uploads` ADD COLUMN `thumbnail_path` VARCHAR(255) NULL DEFAULT NULL AFTER `link_text`;"); echo "<p class='info'>Added 'thumbnail_path' column to 'uploads' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'thumbnail_path' column already exists in 'uploads'.</p>"; }
    try { $pdo->exec("ALTER TABLE `uploads` ADD COLUMN `expires_at` DATETIME NULL DEFAULT NULL;"); echo "<p class='info'>Added 'expires_at' column to 'uploads' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'expires_at' column already exists in 'uploads'.</p>"; }
    try { $pdo->exec("ALTER TABLE `uploads` ADD COLUMN `max_views` INT NULL DEFAULT NULL;"); echo "<p class='info'>Added 'max_views' column to 'uploads' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'max_views' column already exists in 'uploads'.</p>"; }
    try { $pdo->exec("ALTER TABLE `uploads` ADD COLUMN `current_views` INT NOT NULL DEFAULT 0;"); echo "<p class='info'>Added 'current_views' column to 'uploads' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'current_views' column already exists in 'uploads'.</p>"; }
    try { $pdo->exec("ALTER TABLE `uploads` ADD COLUMN `download_count` INT NOT NULL DEFAULT 0 AFTER `current_views`;"); echo "<p class='info'>Added 'download_count' column to 'uploads' table.</p>"; } catch (PDOException $e) { echo "<p class='info'>'download_count' column already exists in 'uploads'.</p>"; }
    echo "<p class='success'>'uploads' table OK.</p><hr>";

    // --- Table: upload_comments ---
    echo "<p>Checking 'upload_comments' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `upload_comments` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `upload_id` INT NOT NULL,
        `user_id` INT NULL,
        `guest_id` INT NULL,
        `username` VARCHAR(50) NOT NULL,
        `comment_text` TEXT NOT NULL,
        `parent_id` INT NULL DEFAULT NULL,
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX `upload_id_idx` (`upload_id`),
        INDEX `parent_id_idx` (`parent_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'upload_comments' table exists.</p>";
    echo "<p class='success'>'upload_comments' table OK.</p><hr>";

    // --- Table: votes ---
    echo "<p>Checking 'votes' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `votes` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `voter_fingerprint` VARCHAR(128) NOT NULL,
        `item_id` INT NOT NULL,
        `item_type` ENUM('upload', 'comment', 'poll') NOT NULL,
        `vote` TINYINT(1) NOT NULL,
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE INDEX `unique_vote` (`voter_fingerprint`, `item_id`, `item_type`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'votes' table exists.</p>";
    echo "<p class='success'>'votes' table OK.</p><hr>";

// --- Table: settings ---
    echo "<p>Checking 'settings' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `settings` (
        `setting_key` VARCHAR(64) NOT NULL PRIMARY KEY,
        `setting_value` TEXT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'settings' table exists.</p>";
    
// Insert default settings, ignoring duplicates
    $pdo->exec("INSERT IGNORE INTO `settings` (`setting_key`, `setting_value`) VALUES
        ('announcement_message', ''),
        ('announcement_level', 'hidden'),
        ('chat_locked', '0'),
        ('public_notes', 'Welcome to Rot-Chat!'),
        ('admin_notes', 'Admin notes here.'),
        ('system_message_level', 'all'),
        ('chat_border_color', '#cc0000'),
        ('chat_glow_color', 'linear-gradient(to bottom, #cc0000, #ff00ff)'),
        ('title_animation', '1'),
        ('banned_words_list', 'viagra,casino,cialis'),
        ('special_effect', 'none'),
        ('guest_default_tokens', '50'),
        ('chat_history_limit', '150'),
        ('banned_name_words_list', 'admin,moderator,support,system'),
        ('upload_allowed_roles', 'user'),
        ('upload_allowed_roles_docs', 'user'),
        ('upload_allowed_roles_zips', 'user'),
        ('view_allowed_roles_images', 'user'),
        ('view_allowed_roles_docs', 'user'),
        ('view_allowed_roles_zips', 'user'),
        ('upload_limit_user', '5'),
        ('upload_limit_trusted', '20'),
        ('upload_limit_moderator', '50'),
        ('allowed_file_types', 'jpg,jpeg,png,gif,mp4,webp,pdf,zip'),
        ('max_file_size_kb', '2048'),
       ('registration_locked', '0'),
        ('default_enable_visual_effects', '1'),
        ('site_rules', '1. Be respectful.\n2. No spamming or flooding the chat.\n3. Do not share illegal content.'),
        ('stats_show_total_members', '1'),
        ('stats_show_messages_today', '1'),
        ('stats_show_online_total', '0'),
        ('stats_show_online_guests', '0'),
        ('trusted_delete_mode', 'own'),
        ('enable_login_captcha', '0');
        
    ");
    echo "<p class='info'>Ensured default settings are present.</p>";
    echo "<p class='success'>'settings' table OK.</p><hr>";
// --- Role configuration (CSV lists; lower-case role names) ---
$pdo->exec("
    INSERT IGNORE INTO settings (setting_key, setting_value) VALUES
    ('known_roles', 'admin,moderator,supermod,trusted,member,guest'),
    ('roles_delete_any', 'admin,moderator,supermod'),
    ('roles_delete_own', 'trusted,member')
");

    // --- Table: channels ---
    echo "<p>Checking 'channels' table...</p>";
    $pdo->exec("CREATE TABLE IF NOT EXISTS `channels` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `name` VARCHAR(50) NOT NULL UNIQUE,
        `topic` VARCHAR(255) NULL DEFAULT NULL,
        `min_role` ENUM('guest', 'user', 'trusted', 'moderator', 'admin') NOT NULL DEFAULT 'guest',
        `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    echo "<p class='info'>Ensured 'channels' table exists.</p>";
    try { $pdo->exec("ALTER TABLE `channels` MODIFY COLUMN `min_role` ENUM('guest', 'user', 'trusted', 'moderator', 'admin') NOT NULL DEFAULT 'guest';"); echo "<p class='info'>Updated 'min_role' ENUM in 'channels' table to include 'trusted'.</p>"; } catch (PDOException $e) { echo "<p class='info'>'min_role' ENUM in 'channels' table is already updated.</p>"; }

    // Insert default channels only if the table is empty
    $channel_count = $pdo->query("SELECT COUNT(*) FROM `channels`")->fetchColumn();
    if ($channel_count == 0) {
        $pdo->exec("INSERT INTO `channels` (`name`, `topic`, `min_role`) VALUES
            ('general', 'General chat for everyone.', 'guest'),
            ('members', 'A private room for registered members.', 'user'),
            ('moderators', 'Coordination room for staff.', 'moderator'),
            ('admin', 'For admins only.', 'admin');
        ");
        echo "<p class='info'>Inserted default channels.</p>";
    }
    echo "<p class='success'>'channels' table OK.</p><hr>";

    echo "<h2><span class='success'>Setup Complete!</span></h2><p>Your database schema is now fully updated and ready for Rot-Chat.</p>";

    // --- Data Fix from db_fix.php ---
    echo "<hr><h2>Attempting to fix incorrect data...</h2>";
    echo "<p class='info'>This will find any upload with a document extension (.pdf, .txt, .doc, .docx) and ensure its type is set to 'document'.</p>";

    $sql = "UPDATE uploads
            SET upload_type = 'document'
            WHERE
                   original_filename LIKE '%.pdf'
                OR original_filename LIKE '%.txt'
                OR original_filename LIKE '%.doc'
                OR original_filename LIKE '%.docx'
            ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute();

    $affected_rows = $stmt->rowCount();

    if ($affected_rows > 0) {
        echo "<p class='success'>Success! Corrected the data for {$affected_rows} document(s).</p>";
    } else {
        echo "<p class='info'>No incorrect document data was found to fix. All document uploads appear to have the correct type.</p>";
    }
    // --- End of Data Fix ---


} catch (PDOException $e) {
    die("<p class='error'>Database setup failed: " . $e->getMessage() . "</p>");
}

echo "</body></html>";
?>