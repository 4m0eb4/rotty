<?php
// upload_test.php
ini_set('display_errors', 1);
error_reporting(E_ALL);

echo "<h2>Upload Tester</h2>";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['test_file']) && $_FILES['test_file']['error'] === UPLOAD_ERR_OK) {
        $upload_dir = 'uploads/';
        $destination = $upload_dir . basename($_FILES['test_file']['name']);

        echo "Attempting to move file to: " . htmlspecialchars($destination) . "<br>";

        if (move_uploaded_file($_FILES['test_file']['tmp_name'], $destination)) {
            echo "<b>SUCCESS!</b> File uploaded and moved successfully.";
        } else {
            echo "<b>ERROR:</b> move_uploaded_file() failed.<br>";
            $error = error_get_last();
            if ($error) {
                echo "<b>PHP Error Message:</b> " . htmlspecialchars($error['message']);
            }
        }
    } else {
        echo "<b>ERROR:</b> No file uploaded or an upload error occurred. Code: " . $_FILES['test_file']['error'];
    }
    echo "<hr>";
}
?>

<form action="upload_test.php" method="post" enctype="multipart/form-data">
  Select a small image to upload:
  <input type="file" name="test_file" id="test_file">
  <input type="submit" value="Run Test" name="submit">
</form>