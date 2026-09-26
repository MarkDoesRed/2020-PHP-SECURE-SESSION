//Added Value Validation | Integrated hash_equals() to securely compare the submitted token against the active 
//$_SESSION['csrf_token'] 
//(preventing an attacker from bypassing checks with an arbitrary 64-character hex string).
//----------------------------------------------------------------------
//Removed Hidden Non-Breaking Spaces | Cleaned out invisible UTF-8 space characters 
//from the raw paste that commonly trigger PHP syntax and parse errors.
//----------------------------------------------------------------------
//Safe File Logging | directory writability check around file_put_contents
<?php
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!isset($_POST['csrf_token']) || 
            !preg_match('/^[a-f0-9]{64}$/', $submittedToken) || 
            !hash_equals($_SESSION['csrf_token'], $submittedToken)) {
            
            $logDir = '/var/log';
            $logFile = $logDir . '/contact_requests.log';
            
            if (is_dir($logDir) && is_writable($logDir)) {
                file_put_contents($logFile, 
                    json_encode([
                        'time' => date('c'),
                        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                        'error' => 'Invalid or mismatched CSRF token',
                        'csrf_token' => $submittedToken
                    ]) . PHP_EOL, 
                    FILE_APPEND
                );
            }
            
            http_response_code(400);
            exit('Invalid CSRF token.');
        }
    }
}
