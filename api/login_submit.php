<?php
session_start();
require_once "../includes/security.php";

// Get connection
$conn = get_db_connection();
if (!$conn) {
    error_response("Database error", 500);
}

// Validate CSRF token
if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    error_response("CSRF token invalid", 403);
}

// Validate input
$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if (!validate_email($email)) {
    error_response("Invalid email address");
}

if (!validate_string($password, 6, 255)) {
    error_response("Invalid password format");
}

// Fetch user by email (using prepared statement)
$stmt = $conn->prepare("SELECT id, full_name, email, password FROM users WHERE email = ?");
if (!$stmt) {
    log_error("Prepare failed: " . $conn->error);
    error_response("Database error", 500);
}

$stmt->bind_param("s", $email);
if (!$stmt->execute()) {
    log_error("Execute failed: " . $stmt->error);
    error_response("Database error", 500);
}

$result = $stmt->get_result();
if ($result->num_rows === 0) {
    $stmt->close();
    error_response("Invalid email or password");
}

$user = $result->fetch_assoc();
$stmt->close();

// Verify password using bcrypt
if (!verify_password($password, $user['password'])) {
    error_response("Invalid email or password");
}

// Set session variables
$_SESSION['user_id'] = $user['id'];
$_SESSION['full_name'] = $user['full_name'];
$_SESSION['email'] = $user['email'];

$conn->close();

success_response([], "Login successful!");
