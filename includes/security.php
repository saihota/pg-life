<?php
/**
 * Security and Configuration Utilities
 * Central location for all security-related helper functions
 */

/**
 * Load environment variables from .env file
 */
function load_env() {
    $env_file = __DIR__ . '/../.env';
    
    if (!file_exists($env_file)) {
        // Fall back to .env.example or use defaults
        $env_file = __DIR__ . '/../.env.example';
    }
    
    if (file_exists($env_file)) {
        $lines = file($env_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            // Skip comments
            if (strpos(trim($line), '#') === 0) continue;
            
            // Parse KEY=VALUE
            if (strpos($line, '=') !== false) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                // Only set if not already set by actual environment
                if (!getenv($key)) {
                    putenv("$key=$value");
                }
            }
        }
    }
}

/**
 * Get environment variable with optional default value
 */
function env($key, $default = null) {
    $value = getenv($key);
    return $value !== false ? $value : $default;
}

/**
 * Get database connection with error handling
 * Returns mysqli object or null on error
 */
function get_db_connection() {
    load_env();
    
    $host = env('DB_HOST', '127.0.0.1');
    $port = env('DB_PORT', '3306');
    $user = env('DB_USER', 'root');
    $pass = env('DB_PASS', '');
    $name = env('DB_NAME', 'pglife');
    
    $conn = new mysqli($host, $user, $pass, $name, $port);
    
    // Check connection
    if ($conn->connect_error) {
        error_log("Database connection failed: " . $conn->connect_error);
        return null;
    }
    
    // Set charset to utf8mb4
    $conn->set_charset("utf8mb4");
    
    return $conn;
}

/**
 * Escape output for HTML context
 * Prevents XSS attacks
 */
function escape_html($text) {
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

/**
 * Escape URL parameter
 * Prevents XSS in href attributes
 */
function escape_url($url) {
    return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
}

/**
 * Escape JSON for safe output
 */
function escape_json($data) {
    return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
}

/**
 * Validate and sanitize integer input
 */
function validate_int($value, $min = null, $max = null) {
    $value = filter_var($value, FILTER_VALIDATE_INT);
    
    if ($value === false) {
        return null;
    }
    
    if ($min !== null && $value < $min) {
        return null;
    }
    
    if ($max !== null && $value > $max) {
        return null;
    }
    
    return $value;
}

/**
 * Validate email address
 */
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate string length
 */
function validate_string($value, $min = 1, $max = 255) {
    $len = strlen(trim($value));
    return $len >= $min && $len <= $max;
}

/**
 * Hash password using bcrypt
 * More secure than sha1
 */
function hash_password($password) {
    return password_hash($password, PASSWORD_BCRYPT, [
        'cost' => 12
    ]);
}

/**
 * Verify password against hash
 */
function verify_password($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Generate CSRF token
 */
function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 */
function verify_csrf_token($token) {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token ?? '');
}

/**
 * Log error for debugging (without exposing to users)
 */
function log_error($message) {
    $debug = env('APP_DEBUG', false) === 'true';
    
    if ($debug) {
        error_log("[" . date('Y-m-d H:i:s') . "] " . $message);
    }
}

/**
 * Send JSON response
 */
function json_response($data, $http_code = 200) {
    http_response_code($http_code);
    header('Content-Type: application/json');
    echo escape_json($data);
    exit;
}

/**
 * Send error response
 */
function error_response($message, $http_code = 400) {
    json_response([
        'success' => false,
        'message' => $message
    ], $http_code);
}

/**
 * Send success response
 */
function success_response($data = [], $message = 'Success') {
    $response = [
        'success' => true,
        'message' => $message
    ];
    
    if (!empty($data)) {
        $response = array_merge($response, $data);
    }
    
    json_response($response, 200);
}

/**
 * Redirect to URL
 */
function redirect($url) {
    header("Location: " . $url, true, 302);
    exit;
}

/**
 * Get user ID from session (safely)
 */
function get_user_id() {
    return isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null;
}

/**
 * Check if user is logged in
 */
function is_logged_in() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * Require user to be logged in
 */
function require_login() {
    if (!is_logged_in()) {
        http_response_code(401);
        redirect('index.php');
    }
}
