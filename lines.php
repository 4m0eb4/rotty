<?php
// lines.php - (REVISED, MERGED VERSION) Main Game Interface & Board Renderer

ini_set('display_errors', 0);
error_reporting(E_ALL);

session_start();
require_once 'config.php';
require_once 'functions.php';

// --- Security & Initialization ---
if (!isset($_SESSION['session_id'])) {
    die('You must be logged in to play.');
}
// Define user/guest status for use throughout the script
$is_member = !($_SESSION['is_guest'] ?? true);
$current_user_id = (int)($_SESSION['user_id'] ?? 0);
$current_guest_id = (int)($_SESSION['guest_id'] ?? 0);
if (!isset($_GET['game'])) { die('Error: No game specified.'); }
$game_uuid = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['game']);
if (empty($game_uuid)) { die('Error: Invalid game ID.'); }

// --- Database Connection ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) { die("Error: Could not connect to the database."); }

// --- Load Game State from DB ---
$stmt = $pdo->prepare("SELECT * FROM games WHERE game_uuid = ?");
$stmt->execute([$game_uuid]);
$game = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$game) { die('Game not found.'); }
$gameState = json_decode($game['game_state'], true);
if ($gameState === null) { die('Error: Game data is corrupted.'); }

// --- Determine Player Role & Handle Joining ---
$me = 0;
$players = [];
$players_stmt = $pdo->prepare("SELECT user_id, guest_id, player_number FROM game_players WHERE game_id = ?");
$players_stmt->execute([$game['id']]);
$player_rows = $players_stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($player_rows as $row) {
    $players[$row['player_number']] = ['user_id' => $row['user_id'], 'guest_id' => $row['guest_id']];
    // Check if the current user is this player
    if (($is_member && $row['user_id'] == $current_user_id) || (!$is_member && $row['guest_id'] == $current_guest_id)) {
        $me = (int)$row['player_number'];
    }
}

// Logic for a new player joining a waiting game
if ($me === 0 && $game['status'] === 'waiting' && count($players) < 2) {
    $me = 2;
    if ($is_member) {
        $pdo->prepare("INSERT INTO game_players (game_id, user_id, player_number) VALUES (?, ?, 2)")->execute([$game['id'], $current_user_id]);
        $players[2] = ['user_id' => $current_user_id, 'guest_id' => null];
    } else { // Is a guest
        $pdo->prepare("INSERT INTO game_players (game_id, guest_id, player_number) VALUES (?, ?, 2)")->execute([$game['id'], $current_guest_id]);
        $players[2] = ['user_id' => null, 'guest_id' => $current_guest_id];
    }
}

// Self-correcting game status logic
if ($game['status'] === 'waiting' && count($players) === 2) {
    $pdo->prepare("UPDATE games SET status = 'active' WHERE id = ?")->execute([$game['id']]);
    $game['status'] = 'active';
}

// --- Handle a Player's Move ---
$canPlay = ($me > 0 && $game['status'] === 'active' && $me === (int)$game['current_turn']);
if (isset($_GET['move']) && $canPlay && preg_match('/^([HV]),(\d+),(\d+)$/', $_GET['move'], $matches)) {
    $type = $matches[1]; $r = (int)$matches[2]; $c = (int)$matches[3];
    $madeBox = false; $validMove = false; $boardSize = (int)$game['board_size'];
    if ($type === 'H' && $r <= $boardSize && $c < $boardSize && $gameState['lines']['h'][$r][$c] === 0) {
        $gameState['lines']['h'][$r][$c] = $me; $validMove = true;
        if ($r > 0 && !empty($gameState['lines']['h'][$r-1][$c]) && !empty($gameState['lines']['v'][$r-1][$c]) && !empty($gameState['lines']['v'][$r-1][$c+1])) {
            $gameState['boxes'][$r-1][$c] = $me; $gameState['score'][$me]++; $madeBox = true;
        }
        if ($r < $boardSize && !empty($gameState['lines']['h'][$r+1][$c]) && !empty($gameState['lines']['v'][$r][$c]) && !empty($gameState['lines']['v'][$r][$c+1])) {
            $gameState['boxes'][$r][$c] = $me; $gameState['score'][$me]++; $madeBox = true;
        }
    }
    elseif ($type === 'V' && $r < $boardSize && $c <= $boardSize && $gameState['lines']['v'][$r][$c] === 0) {
        $gameState['lines']['v'][$r][$c] = $me; $validMove = true;
        if ($c > 0 && !empty($gameState['lines']['v'][$r][$c-1]) && !empty($gameState['lines']['h'][$r][$c-1]) && !empty($gameState['lines']['h'][$r+1][$c-1])) {
            $gameState['boxes'][$r][$c-1] = $me; $gameState['score'][$me]++; $madeBox = true;
        }
        if ($c < $boardSize && !empty($gameState['lines']['v'][$r][$c+1]) && !empty($gameState['lines']['h'][$r][$c]) && !empty($gameState['lines']['h'][$r+1][$c])) {
            $gameState['boxes'][$r][$c] = $me; $gameState['score'][$me]++; $madeBox = true;
        }
    }
    if ($validMove) {
        // NEW: Record the last move made
        $gameState['last_move'] = ['type' => $type, 'r' => $r, 'c' => $c];

        if (!$madeBox) { $game['current_turn'] = ($game['current_turn'] === 1 ? 2 : 1); }

        // Check for game completion
        if (($gameState['score'][1] + $gameState['score'][2]) >= ($boardSize * $boardSize)) {
            $game['status'] = 'finished';
            
            $winner_player_number = 0; // 0 for a tie
            if ($gameState['score'][1] > $gameState['score'][2]) {
                $winner_player_number = 1;
            } elseif ($gameState['score'][2] > $gameState['score'][1]) {
                $winner_player_number = 2;
            }
            $game['winner_player_number'] = $winner_player_number;

            // --- NEW: Award tokens if the winner is a guest ---
            if ($winner_player_number > 0) {
                $winner_stmt = $pdo->prepare("SELECT guest_id FROM game_players WHERE game_id = ? AND player_number = ?");
                $winner_stmt->execute([$game['id'], $winner_player_number]);
                $winning_guest_id = $winner_stmt->fetchColumn();

                if ($winning_guest_id) {
                    $token_award = 20;
                    $pdo->prepare("UPDATE guests SET message_limit = message_limit + ? WHERE id = ?")->execute([$token_award, $winning_guest_id]);
                }
            }
        }
        
        $pdo->prepare("UPDATE games SET current_turn=?, game_state=?, status=?, winner_player_number=? WHERE id=?")->execute([$game['current_turn'], json_encode($gameState), $game['status'], $game['winner_player_number'] ?? null, $game['id']]);
        header("Location: lines.php?game={$game_uuid}"); exit;
    }
}

// --- Page Display Logic ---
function get_player_username($pdo, $player_data) {
    if (!empty($player_data['user_id'])) {
        $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
        $stmt->execute([$player_data['user_id']]);
        return $stmt->fetchColumn();
    } elseif (!empty($player_data['guest_id'])) {
        $stmt = $pdo->prepare("SELECT username FROM guests WHERE id = ?");
        $stmt->execute([$player_data['guest_id']]);
        return $stmt->fetchColumn();
    }
    return 'Player';
}

$p1_username = isset($players[1]) ? get_player_username($pdo, $players[1]) : 'Player 1';
$p2_username = isset($players[2]) ? get_player_username($pdo, $players[2]) : 'Waiting...';

$winner_db_id = $game['winner_player_number'] ?? 0;
if ($game['status'] === 'finished') {
    $winner_username = null;
    if ($winner_db_id > 0 && isset($players[$winner_db_id])) {
         $winner_username = get_player_username($pdo, $players[$winner_db_id]);
    }
    $statusMessage = $winner_username ? "Game Over! ".htmlspecialchars($winner_username)." Wins!" : "Game Over! It's a Tie!";
}

// Board rendering variables
$size = (int)$game['board_size'];
$isMyTurnForBoard = ($me > 0 && $game['status'] === 'active' && $me === (int)$game['current_turn']);

?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <?php
    // Automatically refresh the page every 5 seconds ONLY if the game is active and it's not our turn.
    if ($game['status'] === 'active' && $me !== (int)$game['current_turn']) {
        echo '<meta http-equiv="refresh" content="5">';
    }
  ?>
  <title>Dots & Boxes Game</title>
  <link rel="stylesheet" href="style.css?v=1.2">
<link rel="stylesheet" href="game_style.css?v=1.3">
  <style>
    html, body {
        height: 100%;
        width: 100%;
        overflow-y: auto; /* Allow scrolling if content is too large */
    }
    body {
        background: transparent;
        display: flex;
        flex-direction: column;
        align-items: center; /* Center all content */
        padding: 10px;
    }
    .game-wrapper {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 15px; /* Space between elements */
    }
  </style>
</head>

<body class="frame-body">
    <div class="game-wrapper">
        <div class="scoreboard">
            <div class="score-box p1 <?= ($game['current_turn'] == 1 && $game['status'] === 'active') ? 'current-turn' : '' ?>">
              <div class="label"><?= htmlspecialchars($p1_username) ?> <?= ($me === 1) ? '(You)' : '' ?></div>
              <div class="value"><?= htmlspecialchars($gameState['score'][1] ?? 0) ?></div>
            </div>
            <div class="status-message"><?= htmlspecialchars($statusMessage) ?></div>
            <div class="score-box p2 <?= ($game['current_turn'] == 2 && $game['status'] === 'active') ? 'current-turn' : '' ?>">
               <div class="label"><?= htmlspecialchars($p2_username) ?> <?= ($me === 2) ? '(You)' : '' ?></div>
              <div class="value"><?= htmlspecialchars($gameState['score'][2] ?? 0) ?></div>
            </div>
        </div>

        <table class="board-table">
          <?php for ($r = 0; $r <= 2 * $size; $r++): ?>
            <tr>
              <?php for ($c = 0; $c <= 2 * $size; $c++): ?>
                <?php if ($r % 2 === 0 && $c % 2 === 0): // --- Dot --- ?>
                  <td class="cell dot"></td>
                <?php elseif ($r % 2 === 0 && $c % 2 === 1): // --- Horizontal Line --- ?>
                  <?php
                    $rr = (int)($r / 2); $cc = (int)(($c - 1) / 2);
                    $owner = $gameState['lines']['h'][$rr][$cc] ?? 0;
                    $isAvailable = ($owner === 0 && $isMyTurnForBoard);
                    $lineClass = $isAvailable ? "available p{$me}" : ($owner ? "taken p{$owner}" : "");
                    $link = "lines.php?game={$game_uuid}&move=H,{$rr},{$cc}";
                    
                    $linkOpen = $isAvailable ? "<a href='{$link}' target='_self'>" : "";
                    $linkClose = $isAvailable ? "</a>" : "";
                    echo "<td class='cell h-line-cell'>{$linkOpen}<div class='line h-line {$lineClass}'></div>{$linkClose}</td>";
                  ?>
                <?php elseif ($r % 2 === 1 && $c % 2 === 0): // --- Vertical Line --- ?>
                  <?php
                    $rr = (int)(($r - 1) / 2); $cc = (int)($c / 2);
                    $owner = $gameState['lines']['v'][$rr][$cc] ?? 0;
                    $isAvailable = ($owner === 0 && $isMyTurnForBoard);
                    $lineClass = $isAvailable ? "available p{$me}" : ($owner ? "taken p{$owner}" : "");
                    $link = "lines.php?game={$game_uuid}&move=V,{$rr},{$cc}";

                    $linkOpen = $isAvailable ? "<a href='{$link}' target='_self'>" : "";
                    $linkClose = $isAvailable ? "</a>" : "";
                    echo "<td class='cell v-line-cell'>{$linkOpen}<div class='line v-line {$lineClass}'></div>{$linkClose}</td>";
                  ?>
                <?php else: // --- Box Area --- ?>
                  <?php
                    $rr = (int)(($r - 1) / 2); $cc = (int)(($c - 1) / 2);
                    $owner = $gameState['boxes'][$rr][$cc] ?? 0;
                    $boxClass = $owner ? "claimed p{$owner}" : "";
                    $boxContent = $owner ? "P{$owner}" : "";
                  ?>
                  <td class="cell box <?= $boxClass ?>"><?= $boxContent ?></td>
                <?php endif; ?>
              <?php endfor; ?>
            </tr>
          <?php endfor; ?>
        </table>

        <div class="controls">
           <a href="lines.php?game=<?= $game_uuid ?>" class="btn" target="_self">Refresh ⟳</a>
           <a href="game_lobby.php" class="btn" target="_self">Back to Lobby</a>
        </div>
    </div>
</body>
</html>