<?php
// captcha.php

session_start();

// --- Configuration ---
$width = 250;
$height = 40;
$char_length = 8;
$font_size = 5; // GD font size from 1-5

// --- Generate Random String ---
$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@$*#%';
$captcha_string = '';
for ($i = 0; $i < $char_length; $i++) {
    $captcha_string .= $chars[mt_rand(0, strlen($chars) - 1)];
}

// Store the correct string in the session
$_SESSION['captcha_string'] = $captcha_string;

// --- Create Image ---
$image = imagecreatetruecolor($width, $height);

// Define colors
$bg_color = imagecolorallocate($image, 20, 20, 20); // Dark background
$text_color = imagecolorallocate($image, 204, 0, 0); // Red text
$noise_color_1 = imagecolorallocate($image, 90, 90, 90); // Brighter grey noise
$noise_color_2 = imagecolorallocate($image, 80, 0, 0);   // Dark red noise

// Fill background
imagefilledrectangle($image, 0, 0, $width, $height, $bg_color);

// Add noise (lines)
for ($i = 0; $i < 10; $i++) {
    // Draw lines with both noise colors
    imageline($image, 0, mt_rand(0, $height), $width, mt_rand(0, $height), $noise_color_1);
    imageline($image, 0, mt_rand(0, $height), $width, mt_rand(0, $height), $noise_color_2);
}

// Add noise (pixels)
for ($i = 0; $i < 1000; $i++) {
    // Draw pixels with both noise colors
    imagesetpixel($image, mt_rand(0, $width), mt_rand(0, $height), $noise_color_1);
    imagesetpixel($image, mt_rand(0, $width), mt_rand(0, $height), $noise_color_2);
}

// --- Draw Text ---
$font = './font.ttf'; // Assumes font.ttf is in the same directory
$font_size = 20;

// Loop through each character to place it individually
for ($i = 0; $i < $char_length; $i++) {
    $letter = $captcha_string[$i];
    // Add random angle, and random X/Y offsets for each character
    $angle = mt_rand(-20, 20);
    $x = 10 + ($i * ($width / $char_length));
    $y = mt_rand($font_size, $height - 10);
    
    // Use imagettftext for advanced font rendering
    imagettftext($image, $font_size, $angle, $x, $y, $text_color, $font, $letter);
}

// --- Output Image ---
header('Content-Type: image/png');
header('Cache-Control: no-cache, must-revalidate'); // Ensure image is not cached
imagepng($image);

// Clean up memory
imagedestroy($image);