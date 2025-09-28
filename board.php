<?php
// board.php - (DEFINITIVE, WORKING VERSION)

// Enable error reporting for debugging.
ini_set('display_errors', 0);
error_reporting(E_ALL);

session_start();
require_once 'config.php';

// --- Validation and Initialization ---
if (empty($_GET['game'])) { exit('Error: Game ID missing.'); }
$game_uuid = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['game']);
if (empty($game_uuid)) { exit('Error: Invalid Game ID.'); }

$current_user_id = (int)($_SESSION['user_id'] ?? 0);
if ($current_user_id === 0) { exit('Error: You must be logged in to view the board.'); }

// --- Database Connection ---
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    error_log("Board DB Error: " . $e->getMessage());
    exit("Error: Database connection failed.");
}

// --- Load Game State from DB ---
$stmt = $pdo->prepare("SELECT * FROM games WHERE game_uuid = ?");
$stmt->execute([$game_uuid]);
$game = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$game) { exit('Error: Game could not be found.'); }

$gameState = json_decode($game['game_state'], true);
if (!is_array($gameState) || !isset($gameState['lines'])) {
    error_log("Board JSON Error for game {$game_uuid}: " . $game['game_state']);
    exit('Error: Game data is corrupt or unreadable.');
}

// --- Determine Player Role ---
$me = 0;
$players_stmt = $pdo->prepare("SELECT user_id, player_number FROM game_players WHERE game_id = ?");
$players_stmt->execute([$game['id']]);
$player_list = $players_stmt->fetchAll(PDO::FETCH_KEY_PAIR);

if (isset($player_list[$current_user_id])) {
    $me = (int)$player_list[$current_user_id];
}

$isMyTurn = ($me > 0 && $game['status'] === 'active' && $me === (int)$game['current_turn']);
$size = (int)$game['board_size'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <?php if ($game['status'] === 'active'): ?>
    <meta http-equiv="refresh" content="5">
  <?php endif; ?>
  <title>Dots & Boxes Board</title>
  <link rel="stylesheet" href="style.css?v=1.2">
  <link rel="stylesheet" href="game_style.css?v=1.3">
</head>
<body class="board-body" style="background: transparent;">
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
              $isAvailable = ($owner === 0 && $isMyTurn);
              $lineClass = $isAvailable ? "available p{$me}" : ($owner ? "taken p{$owner}" : "");
              
              // Check if this is the last move
              if (isset($gameState['last_move']) && $gameState['last_move']['type'] === 'H' && $gameState['last_move']['r'] === $rr && $gameState['last_move']['c'] === $cc) {
                  $lineClass .= " last-move";
              }

              $link = "lines.php?game={$game_uuid}&move=H,{$rr},{$cc}";
              
              // This is the corrected, robust rendering logic
              $linkOpen = $isAvailable ? "<a href='{$link}' target='_parent'>" : "";
              $linkClose = $isAvailable ? "</a>" : "";
              echo "<td class='cell h-line-cell'>{$linkOpen}<div class='line h-line {$lineClass}'></div>{$linkClose}</td>";
            ?>
          <?php elseif ($r % 2 === 1 && $c % 2 === 0): // --- Vertical Line --- ?>
            <?php
              $rr = (int)(($r - 1) / 2); $cc = (int)($c / 2);
              $owner = $gameState['lines']['v'][$rr][$cc] ?? 0;
              $isAvailable = ($owner === 0 && $isMyTurn);
              $lineClass = $isAvailable ? "available p{$me}" : ($owner ? "taken p{$owner}" : "");

              // Check if this is the last move
              if (isset($gameState['last_move']) && $gameState['last_move']['type'] === 'V' && $gameState['last_move']['r'] === $rr && $gameState['last_move']['c'] === $cc) {
                  $lineClass .= " last-move";
              }

              $link = "lines.php?game={$game_uuid}&move=V,{$rr},{$cc}";

              // This is the corrected, robust rendering logic
              $linkOpen = $isAvailable ? "<a href='{$link}' target='_parent'>" : "";
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
</body>
</html>