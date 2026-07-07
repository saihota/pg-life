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
$full_name = trim($_POST['full_name'] ?? '');
$phone = trim($_POST['phone'] ?? '');
$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$college_name = trim($_POST['college_name'] ?? '');
$gender = $_POST['gender'] ?? '';

// Input validation
if (!validate_string($full_name, 2, 100)) {
    error_response("Invalid full name (2-100 characters required)");
}

if (!preg_match('/^\d{10}$/', $phone)) {
    error_response("Invalid phone number (10 digits required)");
}

if (!validate_email($email)) {
    error_response("Invalid email address");
}

if (!validate_string($password, 6, 255)) {
    error_response("Password must be at least 6 characters");
}

if (!validate_string($college_name, 2, 150)) {
    error_response("Invalid college name (2-150 characters required)");
}

if (!in_array($gender, ['male', 'female'])) {
    error_response("Invalid gender selection");
}

// Check if email already exists (using prepared statement)
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
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
if ($result->num_rows > 0) {
    $stmt->close();
    error_response("This email is already registered");
}
$stmt->close();

// Hash password securely using bcrypt
$password_hash = hash_password($password);

// Insert new user (using prepared statement)
$stmt = $conn->prepare("INSERT INTO users (full_name, phone, email, password, gender, college_name) VALUES (?, ?, ?, ?, ?, ?)");
if (!$stmt) {
    log_error("Prepare failed: " . $conn->error);
    error_response("Database error", 500);
}

$stmt->bind_param("ssssss", $full_name, $phone, $email, $password_hash, $gender, $college_name);
if (!$stmt->execute()) {
    log_error("Insert failed: " . $stmt->error);
    error_response("Could not create account", 500);
}

$stmt->close();
$conn->close();

success_response([], "Account created successfully! Please login.");
