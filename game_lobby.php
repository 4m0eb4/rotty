<?php
// game_lobby.php - (REFACTORED) Main game menu and specific game lobbies.

ini_set('display_errors', 0);
error_reporting(E_ALL);

session_start();
require_once 'config.php';

// --- Security & Initialization ---
$is_logged_in = isset($_SESSION['session_id']);
$is_member = $is_logged_in && !($_SESSION['is_guest'] ?? true);
$current_user_id = (int)($_SESSION['user_id'] ?? 0);
$current_guest_id = (int)($_SESSION['guest_id'] ?? 0);
$game_type = $_GET['game_type'] ?? null;

// --- Database Connection ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Error: Could not connect to the database.");
}

// --- Handle Dots & Boxes Game Creation ---
// This logic now only runs if we are in the 'dots_and_boxes' lobby view.
if ($game_type === 'dots_and_boxes' && $is_logged_in && isset($_GET['new'], $_GET['size']) && ctype_digit($_GET['size'])) {
    $size = max(2, min(10, (int)$_GET['size']));
    $game_uuid = bin2hex(random_bytes(12));

    $initial_state = json_encode([
        'score' => [1 => 0, 2 => 0],
        'lines' => ['h' => array_fill(0, $size + 1, array_fill(0, $size, 0)), 'v' => array_fill(0, $size, array_fill(0, $size + 1, 0))],
        'boxes' => array_fill(0, $size, array_fill(0, $size, 0))
    ]);

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("INSERT INTO games (game_uuid, board_size, game_state) VALUES (?, ?, ?)");
        $stmt->execute([$game_uuid, $size, $initial_state]);
        $game_id = $pdo->lastInsertId();

        if ($is_member) {
            $stmt = $pdo->prepare("INSERT INTO game_players (game_id, user_id, player_number) VALUES (?, ?, 1)");
            $stmt->execute([$game_id, $current_user_id]);
        } else {
            $stmt = $pdo->prepare("INSERT INTO game_players (game_id, guest_id, player_number) VALUES (?, ?, 1)");
            $stmt->execute([$game_id, $current_guest_id]);
        }
        $pdo->commit();

        header("Location: lines.php?game={$game_uuid}");
        exit;
    } catch (Exception $e) {
        $pdo->rollBack();
        die("Error creating game: " . $e->getMessage());
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Game Lobby</title>
    <link rel="stylesheet" href="style.css?v=1">
    <link rel="stylesheet" href="game_style.css?v=1">
    <link rel="icon" href="/favicon.ico" type="image/x-icon"> </head>
    <style>
        body { background: transparent; padding: 15px; }
        .project-modal { margin: 0 0 20px 0; border-color: #444; background-color: rgba(0,0,0,0.3); }
        .project-modal h2 { color: #ff5555; font-family: 'Courier Prime', monospace; border-color: #444; }
        /* Style for the new main menu */
        .game-menu-item {
            display: block;
            padding: 1rem 1.5rem;
            background: #333;
            color: #e0e0e0;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            text-align: center;
            transition: all 0.2s ease;
            border: 1px solid #555;
        }
        .game-menu-item:hover { background-color: var(--accent-color); border-color: var(--accent-hover-color); color: #fff; }
        .game-menu-item.disabled { background: #222; color: #666; cursor: not-allowed; border-color: #333; }
        .game-menu-item.disabled:hover { background: #222; }
    </style>
</head>
<body class="frame-body">

<?php if (!$is_logged_in): ?>
    <section class="project-modal">
        <h2>Access Denied</h2>
        <p style="text-align:center;">You must be logged-in to play games.</p>
    </section>

<?php elseif ($game_type === 'dots_and_boxes'): // --- DOTS & BOXES LOBBY VIEW --- ?>
    <?php
    // Fetch game lists specifically for this view
    $joinableGames = [];
    $otherGames = [];
    $joinable_sql = "SELECT g.game_uuid, g.board_size, COALESCE(u.username, gu.username) as p1_username FROM games g JOIN game_players gp ON g.id = gp.game_id LEFT JOIN users u ON gp.user_id = u.id LEFT JOIN guests gu ON gp.guest_id = gu.id WHERE g.status = 'waiting' AND gp.player_number = 1";
    if ($is_member) {
        $joinable_sql .= " AND (gp.user_id IS NULL OR gp.user_id != ?)";
        $params = [$current_user_id];
    } else {
        $joinable_sql .= " AND (gp.guest_id IS NULL OR gp.guest_id != ?)";
        $params = [$current_guest_id];
    }
    $joinable_stmt = $pdo->prepare($joinable_sql);
    $joinable_stmt->execute($params);
    $joinableGames = $joinable_stmt->fetchAll(PDO::FETCH_ASSOC);

    $other_sql = "SELECT g.game_uuid, g.board_size, g.status, COALESCE(u.username, gu.username) as p1_username FROM games g JOIN game_players gp ON g.id = gp.game_id LEFT JOIN users u ON gp.user_id = u.id LEFT JOIN guests gu ON gp.guest_id = gu.id WHERE gp.player_number = 1 ORDER BY g.updated_at DESC LIMIT 10";
    $other_stmt = $pdo->prepare($other_sql);
    $other_stmt->execute();
    $otherGames = $other_stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>
    <section class="project-modal">
        <h2>Dots & Boxes: New Game</h2>
        <div style="display: flex; justify-content: center; align-items: center; gap: 15px; flex-wrap: wrap;">
            <form method="GET" action="game_lobby.php" target="_self" style="margin: 0;">
                <input type="hidden" name="game_type" value="dots_and_boxes">
                <label for="size-select">Board size:</label>
                <select name="size" id="size-select">
                    <option value="3">3×3</option>
                    <option value="5" selected>5×5</option>
                    <option value="8">8×8</option>
                </select>
                <button type="submit" name="new" value="1" class="btn">Start</button>
            </form>
            <a href="game_lobby.php?game_type=dots_and_boxes" target="_self" class="btn" style="background-color: #444;">Refresh</a>
        </div>
    </section>

    <section class="project-modal">
        <h2>Join Open Game</h2>
        <?php if (!empty($joinableGames)): ?>
            <ul><?php foreach ($joinableGames as $g): ?><li><span class="game-info"><strong><?= htmlspecialchars($g['p1_username'] ?? 'Player 1') ?>'s Game</strong> (<?= $g['board_size'] ?>×<?= $g['board_size'] ?>)</span><a href="lines.php?game=<?= htmlspecialchars($g['game_uuid']) ?>" class="btn" target="_self">Join</a></li><?php endforeach; ?></ul>
        <?php else: ?><p>No games are currently waiting for an opponent.</p><?php endif; ?>
    </section>

    <section class="project-modal">
        <h2>Active & Recent Games</h2>
        <?php if (!empty($otherGames)): ?>
            <ul><?php foreach ($otherGames as $g): ?><li><span class="game-info"><strong><?= htmlspecialchars($g['p1_username'] ?? 'Player 1') ?>'s Game</strong> (<?= ucfirst($g['status']) ?>)</span><a href="lines.php?game=<?= htmlspecialchars($g['game_uuid']) ?>" class="btn" target="_self"><?= ($g['status'] === 'finished') ? 'View' : 'Spectate' ?></a></li><?php endforeach; ?></ul>
        <?php else: ?><p>No other games to display.</p><?php endif; ?>
    </section>
    <div style="text-align:center;"><a href="game_lobby.php" target="_self" class="btn">« Back to Main Menu</a></div>

<?php else: // --- MAIN GAME MENU VIEW --- ?>
    <section class="project-modal">
        <h2>Game Lobby</h2>
        <div style="display: flex; flex-direction: column; gap: 10px;">
            <a href="game_lobby.php?game_type=dots_and_boxes" target="_self" class="game-menu-item">Dots & Boxes</a>
            <span class="game-menu-item disabled">To Be Decided.</span>
            <span class="game-menu-item disabled">To Be Decided.</span>
        </div>
    </section>
<?php endif; ?>

</body>
</html>