<?php
session_start();
require_once "../includes/security.php";

// Require login
if (!is_logged_in()) {
    error_response("Not logged in", 401);
}

$user_id = get_user_id();

// Validate property_id
$property_id = validate_int($_GET["property_id"] ?? null);
if ($property_id === null) {
    error_response("Invalid property ID", 400);
}

// Get database connection
$conn = get_db_connection();
if (!$conn) {
    error_response("Database error", 500);
}

// Check if already interested (using prepared statement)
$stmt = $conn->prepare("SELECT id FROM interested_users_properties WHERE user_id = ? AND property_id = ?");
if (!$stmt) {
    log_error("Prepare failed: " . $conn->error);
    error_response("Database error", 500);
}

$stmt->bind_param("ii", $user_id, $property_id);
if (!$stmt->execute()) {
    log_error("Execute failed: " . $stmt->error);
    error_response("Database error", 500);
}

$result = $stmt->get_result();
$is_already_interested = ($result->num_rows > 0);
$stmt->close();

if ($is_already_interested) {
    // Remove interest (using prepared statement)
    $stmt = $conn->prepare("DELETE FROM interested_users_properties WHERE user_id = ? AND property_id = ?");
    if (!$stmt) {
        log_error("Prepare failed: " . $conn->error);
        error_response("Database error", 500);
    }
    
    $stmt->bind_param("ii", $user_id, $property_id);
    if (!$stmt->execute()) {
        log_error("Delete failed: " . $stmt->error);
        error_response("Database error", 500);
    }
    
    $stmt->close();
    success_response([
        'is_interested' => false,
        'property_id' => $property_id
    ]);
} else {
    // Add interest (using prepared statement)
    $stmt = $conn->prepare("INSERT INTO interested_users_properties (user_id, property_id) VALUES (?, ?)");
    if (!$stmt) {
        log_error("Prepare failed: " . $conn->error);
        error_response("Database error", 500);
    }
    
    $stmt->bind_param("ii", $user_id, $property_id);
    if (!$stmt->execute()) {
        log_error("Insert failed: " . $stmt->error);
        error_response("Database error", 500);
    }
    
    $stmt->close();
    success_response([
        'is_interested' => true,
        'property_id' => $property_id
    ]);
}

$conn->close();
