<?php
/**
 * Database Connection with Environment Configuration
 * Security: No hardcoded credentials - uses .env file
 */

require_once __DIR__ . '/security.php';

// Get connection using environment variables
$conn = get_db_connection();

// Handle connection failure gracefully
if (!$conn) {
    // Only show detailed error if APP_DEBUG is enabled
    $debug = env('APP_DEBUG', false) === 'true';
    
    if ($debug) {
        error_log("Database connection failed");
    }
    
    // Show generic message to user
    http_response_code(500);
    die("Database connection error. Please contact the administrator.");
}
