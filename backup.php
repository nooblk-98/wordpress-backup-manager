<?php
/**
 * WordPress Backup Manager
 * Single file backup solution with UI and progress tracking
 */

// ============================
// Configuration
// ============================

// Security (MD5 password - legacy)
// Set this to md5('your-password'). Example: define('BACKUP_PASSWORD_MD5', md5('MyStrongPassword'));
define('BACKUP_PASSWORD_MD5', '94f63e2f03239f2a6061ee2af18856a4');

// Optional IP allow-list (recommended if this file is accessible from the internet)
// Examples:
//   define('BACKUP_IP_WHITELIST_ENABLED', true);
//   define('BACKUP_IP_WHITELIST', ['127.0.0.1', '192.168.0.0/16', '::1']);
// Notes:
// - By default we ONLY trust REMOTE_ADDR. To trust proxy headers, enable BACKUP_TRUST_PROXY_HEADERS.
define('BACKUP_IP_WHITELIST_ENABLED', true);
define('BACKUP_IP_WHITELIST', ['127.0.0.1', '192.168.8.0/16', '123.231.94.186']);
define('BACKUP_TRUST_PROXY_HEADERS', false);
// Safe Cloudflare IP ranges (used only when REMOTE_ADDR matches one of these).
define('BACKUP_CLOUDFLARE_IP_RANGES', [
    // IPv4
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    // IPv6
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/32',
]);

// Optional ignore folder names (applies to wp-content backups).
// Any directory name in this list is excluded anywhere in wp-content (e.g. "node_modules" excludes ".../node_modules/...").
// You can add more via UI per-backup run.
define('BACKUP_IGNORE_DIRNAMES', [
    'node_modules',
    '.git',
    '.svn',
    'cache',
    'backups',
    'ai1wm-backups',
    'updraft',
    'wflogs',
    'litespeed',
    'wp-rocket-cache',
]);

// Prefer storing backups outside the web root for safety. Fallback to wp-content/backups if needed.
define('BACKUP_DIR', dirname(__DIR__) . DIRECTORY_SEPARATOR . 'backups');
define('BACKUP_DIR_FALLBACK', __DIR__ . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'backups');
define('BACKUP_DIR_TMP', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wp-backups');
define('BACKUP_DIR_SITE_TMP', __DIR__ . DIRECTORY_SEPARATOR . 'backup-manager-backups');

// Return an array of possible client IPs, ordered by trust.
function getClientIpCandidates(): array {
    $candidates = [];
    $seen = [];

    $add = function (string $ip) use (&$candidates, &$seen): void {
        if ($ip === '' || isset($seen[$ip]) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        $seen[$ip] = true;
        $candidates[] = $ip;
    };

    $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $add($remote);

    $isCfEdge = isIpFromCloudflare($remote);
    if ($isCfEdge) {
        $add((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
        $add((string)($_SERVER['HTTP_TRUE_CLIENT_IP'] ?? ''));
        $xff = (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if ($xff !== '') {
            foreach (array_map('trim', explode(',', $xff)) as $ip) {
                $add($ip);
            }
        }
    }

    if (BACKUP_TRUST_PROXY_HEADERS) {
        // WARNING: Only enable when your reverse proxy sanitizes these headers.
        $xff = (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if ($xff !== '') {
            foreach (array_map('trim', explode(',', $xff)) as $ip) {
                $add($ip);
            }
        }
        $add((string)($_SERVER['HTTP_X_REAL_IP'] ?? ''));
    }

    return $candidates;
}

function getClientIp(): string {
    $candidates = getClientIpCandidates();
    return $candidates[0] ?? '';
}

// Database dump tuning (helps on large databases)
define('DB_DUMP_INSERT_BATCH', 250);      // rows per INSERT statement
define('DB_DUMP_LOG_EVERY_ROWS', 25000);  // progress log cadence

// File backup tuning (helps on large wp-content)
define('FILES_LOG_EVERY', 500);           // progress log cadence (files)
define('ZIP_COMPRESS_LEVEL', 2);          // 0..9 (if supported); lower = faster

// Check if password is submitted
session_start();

function ipInCidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) {
        return false;
    }
    [$subnet, $prefix] = explode('/', $cidr, 2);
    $subnet = trim($subnet);
    $prefix = trim($prefix);

    if (!filter_var($ip, FILTER_VALIDATE_IP) || !filter_var($subnet, FILTER_VALIDATE_IP)) {
        return false;
    }

    $ipBin = inet_pton($ip);
    $netBin = inet_pton($subnet);
    if ($ipBin === false || $netBin === false) {
        return false;
    }

    if (strlen($ipBin) !== strlen($netBin)) {
        return false; // IPv4 vs IPv6 mismatch
    }

    $maxPrefix = strlen($ipBin) * 8;
    if (!ctype_digit($prefix)) {
        return false;
    }
    $prefixLen = (int)$prefix;
    if ($prefixLen < 0 || $prefixLen > $maxPrefix) {
        return false;
    }

    $bytes = intdiv($prefixLen, 8);
    $bits = $prefixLen % 8;

    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
        return false;
    }

    if ($bits === 0) {
        return true;
    }

    $mask = (0xFF << (8 - $bits)) & 0xFF;
    return ((ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask));
}

function isIpFromCloudflare(string $ip): bool {
    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    foreach (BACKUP_CLOUDFLARE_IP_RANGES as $range) {
        if (ipInCidr($ip, $range)) {
            return true;
        }
    }

    return false;
}

function isIpWhitelisted(string $ip): bool {
    $list = BACKUP_IP_WHITELIST;
    if (!is_array($list) || empty($list)) {
        return false;
    }

    foreach ($list as $entry) {
        $entry = trim((string)$entry);
        if ($entry === '') {
            continue;
        }
        if (strpos($entry, '/') !== false) {
            if (ipInCidr($ip, $entry)) {
                return true;
            }
        } else {
            if (hash_equals($entry, $ip)) {
                return true;
            }
        }
    }

    return false;
}

function parseIgnoreDirNames($raw): array {
    if (is_array($raw)) {
        $items = $raw;
    } else {
        $raw = (string)$raw;
        $items = preg_split('/[,\r\n]+/', $raw) ?: [];
    }

    $out = [];
    foreach ($items as $item) {
        $name = strtolower(trim((string)$item));
        if ($name === '' || $name === '.' || $name === '..') {
            continue;
        }
        // Keep it simple: dir names only, no slashes.
        if (strpos($name, '/') !== false || strpos($name, '\\') !== false) {
            continue;
        }
        $out[$name] = true;
    }

    return array_keys($out);
}

function getIgnoreDirNamesFromRequest(): array {
    $fromConfig = parseIgnoreDirNames(BACKUP_IGNORE_DIRNAMES);
    $raw = $_GET['ignore_dirs'] ?? $_POST['ignore_dirs'] ?? '';
    $fromRequest = parseIgnoreDirNames($raw);

    $merged = [];
    foreach (array_merge($fromConfig, $fromRequest) as $name) {
        $merged[strtolower($name)] = true;
    }

    return array_keys($merged);
}

// Optional IP restriction gate (runs before password checks)
if (BACKUP_IP_WHITELIST_ENABLED) {
    $ipCandidates = getClientIpCandidates();
    $clientIp = $ipCandidates[0] ?? '';
    $isAllowed = false;
    foreach ($ipCandidates as $ip) {
        if (isIpWhitelisted($ip)) {
            $isAllowed = true;
            $clientIp = $ip; // log the whitelisted match
            break;
        }
    }

    if (!$isAllowed) {
        if (isset($_GET['action']) || isset($_POST['action'])) {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'success' => false,
                'error' => 'Access denied (IP not allowed)',
                'logs' => ["ERROR: Access denied for IP: $clientIp"],
            ]);
            exit;
        }

        http_response_code(403);
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access denied</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 30px; }
                .box { max-width: 640px; margin: 0 auto; background: #fff3f3; border: 1px solid #f2c2c2; padding: 18px 20px; border-radius: 10px; }
                h1 { margin: 0 0 8px; font-size: 20px; color: #7a1c1c; }
                p { margin: 0; color: #7a1c1c; }
            </style>
        </head>
        <body>
            <div class="box">
                <h1>Access denied</h1>
                <p>Your IP (<?php echo htmlspecialchars($clientIp); ?>) is not allowed.</p>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

if (isset($_POST['backup_password'])) {
    $inputPassword = (string)$_POST['backup_password'];
    $md5 = (string)BACKUP_PASSWORD_MD5;

    $authenticated = false;
    if ($md5 !== '') {
        $authenticated = hash_equals(strtolower($md5), md5($inputPassword));
    } else {
        $_SESSION['backup_error'] = 'Backup password is not configured (BACKUP_PASSWORD_MD5 is empty)';
        $authenticated = false;
    }

    if ($authenticated) {
        $_SESSION['backup_authenticated'] = true;
    } else {
        $_SESSION['backup_error'] = 'Invalid password';
    }
}

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check authentication
if (!isset($_SESSION['backup_authenticated']) || $_SESSION['backup_authenticated'] !== true) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WordPress Backup Manager - Login</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                max-width: 400px;
                width: 100%;
            }
            h1 {
                color: #333;
                margin-bottom: 30px;
                text-align: center;
                font-size: 24px;
            }
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                margin-bottom: 20px;
                transition: border-color 0.3s;
            }
            input[type="password"]:focus {
                outline: none;
                border-color: #667eea;
            }
            button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
            }
            .error {
                background: #fee;
                color: #c33;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 20px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔒 WordPress Backup Manager</h1>
            <script>document.querySelector('.login-container h1').textContent = 'WordPress Backup Manager';</script>
            <?php if (isset($_SESSION['backup_error'])): ?>
                <div class="error"><?php echo htmlspecialchars($_SESSION['backup_error']); unset($_SESSION['backup_error']); ?></div>
            <?php endif; ?>
            <form method="POST">
                <input type="password" name="backup_password" placeholder="Enter Password" required autofocus>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// CSRF token for actions
if (empty($_SESSION['backup_csrf'])) {
    try {
        $_SESSION['backup_csrf'] = bin2hex(random_bytes(32));
    } catch (Exception $e) {
        $_SESSION['backup_csrf'] = bin2hex(uniqid('', true));
    }
}
$csrfToken = (string)$_SESSION['backup_csrf'];
// Avoid holding the session lock for normal page loads; long-running operations also close it explicitly.
releaseSessionLock();

function respondJson(array $payload, int $statusCode = 200): void {
    while (@ob_get_level()) {
        @ob_end_clean();
    }
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');

    if (!empty($GLOBALS['backup_warnings']) && is_array($GLOBALS['backup_warnings'])) {
        if (!isset($payload['logs']) || !is_array($payload['logs'])) {
            $payload['logs'] = [];
        }
        $payload['logs'] = array_merge($GLOBALS['backup_warnings'], $payload['logs']);
    }

    echo json_encode($payload);
    exit;
}

function respondJsonAndContinue(array $payload, int $statusCode = 200): void {
    while (@ob_get_level()) {
        @ob_end_clean();
    }
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    echo json_encode($payload);

    if (function_exists('session_write_close')) {
        @session_write_close();
    }

    // When running under PHP-FPM, this returns the response to the client and keeps executing in the background.
    if (function_exists('fastcgi_finish_request')) {
        @fastcgi_finish_request();
    } else {
        @ob_flush();
        @flush();
    }
}

function initAjaxHandlers(): void {
    @error_reporting(E_ALL);
    @ini_set('display_errors', '0');
    $GLOBALS['backup_warnings'] = [];

    while (@ob_get_level()) {
        @ob_end_clean();
    }
    ob_start();

    set_exception_handler(function($exception) {
        if (!empty($GLOBALS['backup_job_id'])) {
            jobFail((string)$GLOBALS['backup_job_id'], $exception->getMessage(), [
                'ERROR: ' . $exception->getMessage(),
                'File: ' . $exception->getFile(),
                'Line: ' . $exception->getLine(),
            ]);
            exit;
        }

        respondJson([
            'success' => false,
            'error' => $exception->getMessage(),
            'logs' => [
                'ERROR: ' . $exception->getMessage(),
                'File: ' . $exception->getFile(),
                'Line: ' . $exception->getLine(),
            ],
        ], 500);
    });

    set_error_handler(function($errno, $errstr, $errfile, $errline) {
        // Treat warnings/notices as non-fatal so we can fall back (common for permission checks/mkdir attempts).
        $nonFatal = [E_WARNING, E_USER_WARNING, E_NOTICE, E_USER_NOTICE, E_DEPRECATED, E_USER_DEPRECATED, E_STRICT];
        if (in_array($errno, $nonFatal, true)) {
            $GLOBALS['backup_warnings'][] = "WARN: $errstr (File: $errfile Line: $errline)";
            return true;
        }

        if (!empty($GLOBALS['backup_job_id'])) {
            jobFail((string)$GLOBALS['backup_job_id'], $errstr, [
                "ERROR: $errstr",
                "File: $errfile",
                "Line: $errline",
            ]);
            exit;
        }

        respondJson([
            'success' => false,
            'error' => $errstr,
            'logs' => [
                "ERROR: $errstr",
                "File: $errfile",
                "Line: $errline",
            ],
        ], 500);
    });

    register_shutdown_function(function() {
        $error = error_get_last();
        if (!$error) {
            return;
        }
        $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
        if (!in_array($error['type'], $fatalTypes, true)) {
            return;
        }
        if (!empty($GLOBALS['backup_job_id'])) {
            jobFail((string)$GLOBALS['backup_job_id'], $error['message'], [
                'ERROR: ' . $error['message'],
                'File: ' . $error['file'],
                'Line: ' . $error['line'],
            ]);
            return;
        }

        respondJson([
            'success' => false,
            'error' => $error['message'],
            'logs' => [
                'ERROR: ' . $error['message'],
                'File: ' . $error['file'],
                'Line: ' . $error['line'],
            ],
        ], 500);
    });
}

function requireCsrf(): void {
    $token = $_POST['csrf'] ?? $_GET['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $token = (string)$token;
    $expected = (string)($_SESSION['backup_csrf'] ?? '');
    if ($expected === '' || !hash_equals($expected, $token)) {
        respondJson([
            'success' => false,
            'error' => 'Invalid CSRF token',
            'logs' => ['ERROR: Invalid CSRF token'],
        ], 403);
    }
}

function listBackupDirCandidates(): array {
    return [
        BACKUP_DIR,
        BACKUP_DIR_FALLBACK,
        BACKUP_DIR_TMP,
        // stays inside the site (helps when open_basedir blocks /tmp)
        BACKUP_DIR_SITE_TMP,
    ];
}

function safeMkdir(string $dir): bool {
    $prev = set_error_handler(function() { return true; });
    $ok = @mkdir($dir, 0755, true);
    if ($prev !== null) {
        restore_error_handler();
    } else {
        restore_error_handler();
    }
    return (bool)$ok;
}

function isParentWritable(string $dir): bool {
    $parent = dirname($dir);
    return is_dir($parent) && isWritableDir($parent);
}

function getBackupDir(): string {
    // Prefer existing writable dirs.
    foreach (listBackupDirCandidates() as $dir) {
        if (is_dir($dir) && isWritableDir($dir)) {
            return $dir;
        }
    }

    // Prefer dirs we can create (parent is writable).
    foreach (listBackupDirCandidates() as $dir) {
        if (!is_dir($dir) && isParentWritable($dir)) {
            return $dir;
        }
    }

    // Last resort: system temp dir (may still be blocked by open_basedir).
    return BACKUP_DIR_TMP;
}

function ensureBackupDir(): string {
    $openBaseDir = (string)ini_get('open_basedir');
    $tried = [];

    foreach (listBackupDirCandidates() as $dir) {
        $tried[] = $dir;
        if (!is_dir($dir)) {
            safeMkdir($dir);
        }
        if (is_dir($dir) && isWritableDir($dir)) {
            return $dir;
        }
    }

    throw new Exception('No writable backup directory found. Tried: ' . implode(' | ', $tried) . ($openBaseDir !== '' ? (' | open_basedir=' . $openBaseDir) : ''));
}

function ensureBackupDirReady(string $backupDir): void {
    if (!is_dir($backupDir)) {
        safeMkdir($backupDir);
    }
    if (!is_dir($backupDir)) {
        throw new Exception('Failed to create backup directory: ' . $backupDir);
    }
    if (!isWritableDir($backupDir)) {
        $userInfo = '';
        if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
            $pw = @posix_getpwuid(@posix_geteuid());
            if (is_array($pw) && !empty($pw['name'])) {
                $userInfo = ' (php user: ' . $pw['name'] . ')';
            }
        }
        throw new Exception('Backup directory is not writable: ' . $backupDir . $userInfo);
    }
}

function isWritableDir(string $dir): bool {
    if (!is_dir($dir) || !is_writable($dir)) {
        return false;
    }
    $tmp = @tempnam($dir, 'bm-');
    if ($tmp === false) {
        return false;
    }
    @unlink($tmp);
    return true;
}

function releaseSessionLock(): void {
    if (function_exists('session_status') && session_status() === PHP_SESSION_ACTIVE) {
        @session_write_close();
    }
}

function getBackupSearchDirs(): array {
    $dirs = [];
    $primary = getBackupDir();
    $dirs[] = $primary;
    foreach (listBackupDirCandidates() as $dir) {
        if ($dir && $dir !== $primary) {
            $dirs[] = $dir;
        }
    }
    return array_values(array_unique($dirs));
}

function resolveBackupFilepath(string $filename): ?string {
    $safe = basename($filename);
    foreach (getBackupSearchDirs() as $dir) {
        $candidate = $dir . DIRECTORY_SEPARATOR . $safe;
        if (is_file($candidate)) {
            return $candidate;
        }
    }
    return null;
}

function getJobsDir(): string {
    $dir = getBackupDir() . DIRECTORY_SEPARATOR . 'backup-jobs';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    return $dir;
}

function jobStatusPath(string $jobId): string {
    return getJobsDir() . DIRECTORY_SEPARATOR . 'job-' . preg_replace('/[^a-zA-Z0-9_-]/', '', $jobId) . '.json';
}

function jobLogPath(string $jobId): string {
    return getJobsDir() . DIRECTORY_SEPARATOR . 'job-' . preg_replace('/[^a-zA-Z0-9_-]/', '', $jobId) . '.log';
}

function jobLockPath(string $jobId): string {
    return getJobsDir() . DIRECTORY_SEPARATOR . 'job-' . preg_replace('/[^a-zA-Z0-9_-]/', '', $jobId) . '.lock';
}

function acquireJobLock(string $jobId) {
    $path = jobLockPath($jobId);
    $fh = @fopen($path, 'c+b');
    if (!$fh) {
        return null;
    }
    if (!@flock($fh, LOCK_EX | LOCK_NB)) {
        fclose($fh);
        return null;
    }
    return $fh;
}

function releaseJobLock($fh): void {
    if (!$fh) {
        return;
    }
    @flock($fh, LOCK_UN);
    @fclose($fh);
}

function createJob(string $type, array $params = []): array {
    try {
        $jobId = bin2hex(random_bytes(8));
    } catch (Exception $e) {
        $jobId = bin2hex(uniqid('', true));
    }

    $statusPath = jobStatusPath($jobId);
    $logPath = jobLogPath($jobId);

    $state = [
        'id' => $jobId,
        'type' => $type,
        'status' => 'queued',
        'created_at' => time(),
        'updated_at' => time(),
        'params' => $params,
        'progress' => [
            'files' => 0,
            'bytes' => 0,
            'rows' => 0,
            'tables' => 0,
        ],
        'result' => null,
        'error' => null,
        'log_file' => basename($logPath),
    ];

    file_put_contents($statusPath, json_encode($state), LOCK_EX);
    @file_put_contents($logPath, "Job created: $type\n", FILE_APPEND | LOCK_EX);

    return $state;
}

function createWpContentFileList(string $listPath, bool $excludeUploads, array $ignoreDirNames, string $sourceDir, array &$logs): array {
    $excludePrefixes = wpContentExcludePrefixes();
    if ($excludeUploads) {
        $excludePrefixes[] = 'wp-content/uploads/';
    }

    $fh = @fopen($listPath, 'wb');
    if (!$fh) {
        throw new Exception('Unable to create job file list: ' . $listPath);
    }

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    $fileCount = 0;
    $totalBytes = 0;
    foreach ($files as $file) {
        if ($file->isDir() || $file->isLink()) {
            continue;
        }

        $filePath = $file->getPathname();
        $relativePath = 'wp-content/' . substr($filePath, strlen($sourceDir) + 1);
        $relativePath = str_replace('\\', '/', $relativePath);

        if (shouldExcludeWpContentPath($relativePath, $excludePrefixes, $ignoreDirNames)) {
            continue;
        }

        fwrite($fh, $filePath . "\t" . $relativePath . "\n");
        $fileCount++;
        $totalBytes += $file->getSize();

        if ($fileCount % 5000 === 0) {
            $logs[] = "Indexed $fileCount files...";
        }
    }

    fclose($fh);

    return [$fileCount, $totalBytes];
}

function runChunkedZipStep(array $job, int $maxFiles = 500, int $maxSeconds = 8): array {
    releaseSessionLock();
    $jobId = (string)$job['id'];

    // Prevent overlapping chunk steps (common cause of ZipArchive temp rename failures on Windows).
    $lock = acquireJobLock($jobId);
    if (!$lock) {
        $current = readJob($jobId) ?: $job;
        $current['busy'] = true;
        return $current;
    }

    try {
    $work = $job['work'] ?? [];
    $listPath = (string)($work['list_path'] ?? '');
    $zipPath = (string)($work['zip_path'] ?? '');
    $offset = (int)($work['offset'] ?? 0);

    if ($listPath === '' || !is_file($listPath)) {
        throw new Exception('Job list file missing');
    }
    if ($zipPath === '') {
        throw new Exception('Job zip path missing');
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE) !== TRUE) {
        throw new Exception('Cannot open zip file for append');
    }

    $start = microtime(true);
    $added = 0;

    $fh = fopen($listPath, 'rb');
    if (!$fh) {
        $zip->close();
        throw new Exception('Unable to read job list file');
    }
    fseek($fh, $offset);

    $filesAddedTotal = (int)($job['progress']['files'] ?? 0);
    $bytesAddedTotal = (int)($job['progress']['bytes'] ?? 0);

    while (!feof($fh)) {
        $line = fgets($fh);
        if ($line === false) {
            break;
        }

        $line = trim($line);
        if ($line === '') {
            continue;
        }

        $parts = explode("\t", $line, 2);
        if (count($parts) !== 2) {
            continue;
        }

        [$filePath, $relativePath] = $parts;
        $filePath = (string)$filePath;
        $relativePath = (string)$relativePath;

        if (!is_file($filePath)) {
            continue;
        }

        if (!$zip->addFile($filePath, $relativePath)) {
            throw new Exception('Failed to add file to ZIP: ' . $relativePath);
        }
        if (method_exists($zip, 'setCompressionName')) {
            @$zip->setCompressionName($relativePath, ZipArchive::CM_STORE);
        }

        $added++;
        $filesAddedTotal++;
        $bytesAddedTotal += filesize($filePath);

        if ($added >= $maxFiles) {
            break;
        }
        if ((microtime(true) - $start) >= $maxSeconds) {
            break;
        }
    }

    $newOffset = ftell($fh);
    $done = feof($fh);
    fclose($fh);

    if ($zip->close() !== true) {
        $status = method_exists($zip, 'getStatusString') ? $zip->getStatusString() : '';
        throw new Exception('ZipArchive::close failed. ' . ($status ? $status : ''));
    }

    updateJob($jobId, [
        'status' => $done ? 'complete' : 'running',
        'work' => [
            'offset' => $newOffset,
        ],
        'progress' => [
            'files' => $filesAddedTotal,
            'bytes' => $bytesAddedTotal,
        ],
    ]);

    jobLog($jobId, $done ? 'Chunked ZIP complete' : "Chunk step: added $added files");

    $updated = readJob($jobId) ?: $job;
    if ($done) {
        @unlink($listPath);
        $filesize = is_file($zipPath) ? filesize($zipPath) : 0;
        $filename = basename($zipPath);
        $result = [
            'success' => true,
            'filename' => $filename,
            'size' => formatBytes($filesize),
            'path' => $zipPath,
            'logs' => tailFileLines(jobLogPath($jobId), 200),
            'files' => $filesAddedTotal,
        ];
        updateJob($jobId, [
            'result' => $result,
        ]);
        $updated = readJob($jobId) ?: $updated;
    }

    return $updated;
    } finally {
        releaseJobLock($lock);
    }
}

function readJob(string $jobId): ?array {
    $path = jobStatusPath($jobId);
    if (!is_file($path)) {
        return null;
    }
    $raw = file_get_contents($path);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function updateJob(string $jobId, array $patch): void {
    $state = readJob($jobId);
    if (!is_array($state)) {
        return;
    }
    $state = array_replace_recursive($state, $patch);
    $state['updated_at'] = time();
    file_put_contents(jobStatusPath($jobId), json_encode($state), LOCK_EX);
}

function jobLog(string $jobId, string $line): void {
    $line = trim($line);
    @file_put_contents(jobLogPath($jobId), '[' . date('H:i:s') . '] ' . $line . "\n", FILE_APPEND | LOCK_EX);
}

function jobFail(string $jobId, string $message, array $logs = []): void {
    updateJob($jobId, [
        'status' => 'error',
        'error' => $message,
    ]);
    jobLog($jobId, 'ERROR: ' . $message);
    foreach ($logs as $l) {
        jobLog($jobId, (string)$l);
    }
}

function tailFileLines(string $path, int $maxLines = 200): array {
    if (!is_file($path)) {
        return [];
    }

    $fh = @fopen($path, 'rb');
    if (!$fh) {
        return [];
    }

    $buffer = '';
    $lines = [];
    $pos = -1;
    $lineCount = 0;
    fseek($fh, 0, SEEK_END);
    $filesize = ftell($fh);
    if ($filesize === 0) {
        fclose($fh);
        return [];
    }

    while ($lineCount < $maxLines && -$pos <= $filesize) {
        fseek($fh, $pos, SEEK_END);
        $char = fgetc($fh);
        if ($char === "\n") {
            $lines[] = strrev($buffer);
            $buffer = '';
            $lineCount++;
        } else {
            $buffer .= $char;
        }
        $pos--;
    }
    if ($buffer !== '' && $lineCount < $maxLines) {
        $lines[] = strrev($buffer);
    }

    fclose($fh);
    $lines = array_reverse(array_filter(array_map('trim', $lines), fn($l) => $l !== ''));
    return $lines;
}

// Parse wp-config.php (and wp-config-docker.php) to get database credentials without loading WordPress.
function wpConfigCandidates(): array {
    $dirs = [];
    $dir = __DIR__;
    for ($i = 0; $i < 4; $i++) {
        $dirs[] = $dir;
        $parent = dirname($dir);
        if ($parent === $dir) {
            break;
        }
        $dir = $parent;
    }

    $candidates = [];
    foreach (array_values(array_unique($dirs)) as $d) {
        $candidates[] = $d . '/wp-config.php';
        $candidates[] = $d . '/wp-config-docker.php';
    }
    return $candidates;
}

function getWpConfig() {
    $lastConfig = null;
    foreach (wpConfigCandidates() as $configFile) {
        if (!is_file($configFile)) {
            continue;
        }

        $config = array();
        $config['_source'] = $configFile;
        $content = (string)file_get_contents($configFile);

        $resolveEnvDocker = function(string $env, string $default): string {
            $fileEnv = getenv($env . '_FILE');
            if ($fileEnv !== false && $fileEnv !== '') {
                $path = (string)$fileEnv;
                if (is_file($path)) {
                    return rtrim((string)file_get_contents($path), "\r\n");
                }
            }

            $val = getenv($env);
            if ($val !== false) {
                return (string)$val;
            }

            return $default;
        };

        $resolveEnvLike = function(string $env, string $default): string {
            $val = getenv($env);
            if ($val !== false) {
                return (string)$val;
            }
            if (isset($_ENV[$env])) {
                return (string)$_ENV[$env];
            }
            if (isset($_SERVER[$env])) {
                return (string)$_SERVER[$env];
            }
            return $default;
        };

        $extractDefines = function(string $phpSource): array {
            $wanted = ['DB_NAME' => true, 'DB_USER' => true, 'DB_PASSWORD' => true, 'DB_HOST' => true];
            $defines = [];

            $tokens = token_get_all($phpSource);
            $count = count($tokens);

            for ($i = 0; $i < $count; $i++) {
                $t = $tokens[$i];
                if (!is_array($t) || $t[0] !== T_STRING || strtolower((string)$t[1]) !== 'define') {
                    continue;
                }

                $j = $i + 1;
                while ($j < $count && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                    $j++;
                }
                if ($j >= $count || $tokens[$j] !== '(') {
                    continue;
                }

                $j++;
                while ($j < $count && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                    $j++;
                }
                if ($j >= $count || !is_array($tokens[$j]) || $tokens[$j][0] !== T_CONSTANT_ENCAPSED_STRING) {
                    continue;
                }

                $name = trim((string)$tokens[$j][1], "\"'");
                if (!isset($wanted[$name])) {
                    continue;
                }

                $j++;
                while ($j < $count && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                    $j++;
                }
                if ($j >= $count || $tokens[$j] !== ',') {
                    continue;
                }

                $j++;
                $depth = 1; // inside define(...)
                $expr = '';
                for (; $j < $count; $j++) {
                    $tok = $tokens[$j];
                    $tokText = is_array($tok) ? $tok[1] : $tok;

                    if ($tokText === '(') {
                        $depth++;
                        $expr .= $tokText;
                        continue;
                    }
                    if ($tokText === ')') {
                        $depth--;
                        if ($depth === 0) {
                            break;
                        }
                        $expr .= $tokText;
                        continue;
                    }

                    $expr .= $tokText;
                }

                $defines[$name] = trim($expr);
            }

            return $defines;
        };

        $resolveExpr = function(string $expr) use ($resolveEnvDocker, $resolveEnvLike): string {
            $expr = trim($expr);
            if ($expr === '') {
                return '';
            }

            // quoted literal
            if (preg_match('/^([\'"])(.*)\\1$/s', $expr, $m)) {
                return stripcslashes((string)$m[2]);
            }

            // getenv_docker('ENV', 'default')
            if (preg_match('/^getenv_docker\\s*\\(\\s*([\'"])([^\'"]+)\\1\\s*,\\s*([\'"])([^\'"]*)\\3\\s*\\)$/is', $expr, $m)) {
                return $resolveEnvDocker((string)$m[2], stripcslashes((string)$m[4]));
            }

            // getenv('ENV') ?: 'default' OR getenv('ENV') ?? 'default'
            if (preg_match('/^getenv\\s*\\(\\s*([\'"])([^\'"]+)\\1\\s*\\)\\s*(?:\\?\\:|\\?\\?)\\s*([\'"])([^\'"]*)\\3\\s*$/is', $expr, $m)) {
                $val = $resolveEnvLike((string)$m[2], '');
                return $val !== '' ? $val : stripcslashes((string)$m[4]);
            }

            // getenv('ENV')
            if (preg_match('/^getenv\\s*\\(\\s*([\'"])([^\'"]+)\\1\\s*\\)\\s*$/is', $expr, $m)) {
                return $resolveEnvLike((string)$m[2], '');
            }

            // $_ENV['ENV'] ?? 'default' or $_SERVER['ENV'] ?? 'default'
            if (preg_match('/^\\$_(?:ENV|SERVER)\\s*\\[\\s*([\'"])([^\'"]+)\\1\\s*\\]\\s*(?:\\?\\:|\\?\\?)\\s*([\'"])([^\'"]*)\\3\\s*$/is', $expr, $m)) {
                $val = $resolveEnvLike((string)$m[2], '');
                return $val !== '' ? $val : stripcslashes((string)$m[4]);
            }

            // $_ENV['ENV'] or $_SERVER['ENV']
            if (preg_match('/^\\$_(?:ENV|SERVER)\\s*\\[\\s*([\'"])([^\'"]+)\\1\\s*\\]\\s*$/is', $expr, $m)) {
                return $resolveEnvLike((string)$m[2], '');
            }

            return '';
        };

        $defines = $extractDefines($content);
        $config['DB_NAME'] = isset($defines['DB_NAME']) ? $resolveExpr((string)$defines['DB_NAME']) : '';
        $config['DB_USER'] = isset($defines['DB_USER']) ? $resolveExpr((string)$defines['DB_USER']) : '';
        $config['DB_PASSWORD'] = isset($defines['DB_PASSWORD']) ? $resolveExpr((string)$defines['DB_PASSWORD']) : '';
        $config['DB_HOST'] = isset($defines['DB_HOST']) ? $resolveExpr((string)$defines['DB_HOST']) : '';

        $lastConfig = $config;

        // Accept this file only if it actually contains usable DB settings.
        $hasEssentials = (!empty($config['DB_NAME']) && !empty($config['DB_USER']) && !empty($config['DB_HOST']));
        $hasDockerPlaceholders = (strcasecmp((string)$config['DB_USER'], 'example username') === 0) || (strcasecmp((string)$config['DB_PASSWORD'], 'example password') === 0);
        if ($hasEssentials && !$hasDockerPlaceholders) {
            return $config;
        }
    }

    return $lastConfig ?: false;
}

function dockerEnvStatus(): array {
    $envs = ['WORDPRESS_DB_NAME', 'WORDPRESS_DB_USER', 'WORDPRESS_DB_PASSWORD', 'WORDPRESS_DB_HOST'];
    $out = [];
    foreach ($envs as $e) {
        $val = getenv($e);
        $fileVal = getenv($e . '_FILE');
        $out[$e] = [
            'set' => ($val !== false && (string)$val !== ''),
            'file_set' => ($fileVal !== false && (string)$fileVal !== ''),
            'file_path' => ($fileVal !== false ? (string)$fileVal : ''),
        ];
    }
    return $out;
}

// Handle backup actions first (before any output)
if (isset($_GET['action']) || isset($_POST['action'])) {
    $action = (string)($_GET['action'] ?? $_POST['action']);

    // Test action to verify JSON response works
    if ($action === 'test') {
        respondJson([
            'success' => true,
            'message' => 'Test successful',
            'logs' => ['Connection working!']
        ]);
    }

    if ($action === 'capabilities') {
        respondJson([
            'success' => true,
            'php_sapi' => php_sapi_name(),
            'php_version' => PHP_VERSION,
            'fastcgi_finish_request' => function_exists('fastcgi_finish_request'),
            'zip' => class_exists('ZipArchive'),
            'mysqli' => class_exists('mysqli'),
        ]);
    }

    // For AJAX actions, enforce JSON error handling + CSRF.
    if (in_array($action, ['backup_database', 'backup_files', 'backup_full', 'delete', 'job_status', 'job_step', 'config_debug'], true)) {
        initAjaxHandlers();
        requireCsrf();
    }

    $wpConfig = getWpConfig();
    
    // Check if config loaded successfully
    if (!$wpConfig || empty($wpConfig['DB_NAME']) || empty($wpConfig['DB_USER']) || empty($wpConfig['DB_HOST'])) {
        respondJson([
            'success' => false,
            'error' => 'Failed to load wp-config (or credentials missing)',
            'logs' => [
                'ERROR: Could not read wp-config or database settings are incomplete',
                'Tried: ' . implode(' | ', wpConfigCandidates()),
                'Detected: ' . ($wpConfig['_source'] ?? 'none'),
            ]
        ], 500);
    }

    // Docker configs can "parse" but still be unusable if env vars are not exposed to PHP-FPM (clear_env/etc).
    if (strcasecmp((string)$wpConfig['DB_USER'], 'example username') === 0 || strcasecmp((string)$wpConfig['DB_PASSWORD'], 'example password') === 0) {
        $env = dockerEnvStatus();
        respondJson([
            'success' => false,
            'error' => 'Docker wp-config detected but WORDPRESS_DB_* env vars are not available to PHP',
            'logs' => [
                'ERROR: wp-config is using getenv_docker(...), but PHP did not receive the environment variables (common with PHP-FPM clear_env).',
                'Set WORDPRESS_DB_NAME / WORDPRESS_DB_USER / WORDPRESS_DB_PASSWORD / WORDPRESS_DB_HOST for PHP-FPM, or hardcode DB_* in wp-config.',
                'Detected: ' . ($wpConfig['_source'] ?? 'none'),
                'Env WORDPRESS_DB_NAME set: ' . ($env['WORDPRESS_DB_NAME']['set'] ? 'yes' : 'no') . ' file: ' . ($env['WORDPRESS_DB_NAME']['file_set'] ? 'yes' : 'no'),
                'Env WORDPRESS_DB_USER set: ' . ($env['WORDPRESS_DB_USER']['set'] ? 'yes' : 'no') . ' file: ' . ($env['WORDPRESS_DB_USER']['file_set'] ? 'yes' : 'no'),
                'Env WORDPRESS_DB_PASSWORD set: ' . ($env['WORDPRESS_DB_PASSWORD']['set'] ? 'yes' : 'no') . ' file: ' . ($env['WORDPRESS_DB_PASSWORD']['file_set'] ? 'yes' : 'no'),
                'Env WORDPRESS_DB_HOST set: ' . ($env['WORDPRESS_DB_HOST']['set'] ? 'yes' : 'no') . ' file: ' . ($env['WORDPRESS_DB_HOST']['file_set'] ? 'yes' : 'no'),
            ],
        ], 500);
    }
    
    switch ($action) {
        case 'config_debug':
            $masked = $wpConfig;
            if (is_array($masked) && isset($masked['DB_PASSWORD']) && $masked['DB_PASSWORD'] !== '') {
                $masked['DB_PASSWORD'] = '********';
            }
            $placeholder = (is_array($wpConfig) && (strcasecmp((string)($wpConfig['DB_USER'] ?? ''), 'example username') === 0 || strcasecmp((string)($wpConfig['DB_PASSWORD'] ?? ''), 'example password') === 0));
            respondJson([
                'success' => true,
                'config' => $masked,
                'candidates' => wpConfigCandidates(),
                'docker_env' => dockerEnvStatus(),
                'docker_placeholders_detected' => $placeholder,
            ]);
            break;
        case 'backup_database':
            $asyncRequested = ((string)($_GET['async'] ?? $_POST['async'] ?? '')) === '1';
            $canAsync = $asyncRequested && function_exists('fastcgi_finish_request');
            if ($canAsync) {
                $job = createJob('backup_database', []);
                $jobId = (string)$job['id'];
                $GLOBALS['backup_job_id'] = $jobId;

                updateJob($jobId, ['status' => 'running']);
                respondJsonAndContinue([
                    'success' => true,
                    'job_id' => $jobId,
                    'status' => 'running',
                    'mode' => 'async',
                ]);

                ignore_user_abort(true);
                set_time_limit(0);
                jobLog($jobId, 'Job started: database backup');

                try {
                    $logs = [];
                    $backupDir = ensureBackupDir();
                    $result = databaseBackupResult($wpConfig, $backupDir, $logs, $jobId);
                    updateJob($jobId, [
                        'status' => 'complete',
                        'result' => $result,
                    ]);
                    foreach ($logs as $l) {
                        jobLog($jobId, (string)$l);
                    }
                } catch (Exception $e) {
                    jobFail($jobId, $e->getMessage(), ['ERROR: ' . $e->getMessage()]);
                }
                exit;
            }

            backupDatabase($wpConfig);
            break;
        case 'backup_files':
            $asyncRequested = ((string)($_GET['async'] ?? $_POST['async'] ?? '')) === '1';
            $canAsync = $asyncRequested && function_exists('fastcgi_finish_request');
            $chunkedRequested = ((string)($_GET['chunked'] ?? $_POST['chunked'] ?? '')) === '1';
            $excludeUploads = ((string)($_GET['exclude_uploads'] ?? $_POST['exclude_uploads'] ?? '')) === '1';

            if ($canAsync) {
                $excludeUploads = ((string)($_GET['exclude_uploads'] ?? $_POST['exclude_uploads'] ?? '')) === '1';
                $job = createJob('backup_files', ['exclude_uploads' => $excludeUploads]);
                $jobId = (string)$job['id'];
                $GLOBALS['backup_job_id'] = $jobId;

                updateJob($jobId, ['status' => 'running']);
                respondJsonAndContinue([
                    'success' => true,
                    'job_id' => $jobId,
                    'status' => 'running',
                    'mode' => 'async',
                ]);

                ignore_user_abort(true);
                set_time_limit(0);
                jobLog($jobId, 'Job started: files backup' . ($excludeUploads ? ' (excluding uploads)' : ''));

                try {
                    $backupDir = ensureBackupDir();
                    $result = filesBackupResult($backupDir, $excludeUploads, $jobId);
                    updateJob($jobId, [
                        'status' => 'complete',
                        'result' => $result,
                        'progress' => [
                            'files' => $result['files'] ?? 0,
                            'bytes' => 0,
                        ],
                    ]);
                    foreach (($result['logs'] ?? []) as $l) {
                        jobLog($jobId, (string)$l);
                    }
                } catch (Exception $e) {
                    jobFail($jobId, $e->getMessage(), ['ERROR: ' . $e->getMessage()]);
                }
                exit;
            }

            if ($chunkedRequested || $asyncRequested) {
                // Chunked mode prevents long-running requests on hosts with very few PHP workers.
                $job = createJob('backup_files_chunked', ['exclude_uploads' => $excludeUploads]);
                $jobId = (string)$job['id'];
                $GLOBALS['backup_job_id'] = $jobId;

                $backupDir = ensureBackupDir();
                ensureBackupDirReady($backupDir);
                $zipPath = $backupDir . DIRECTORY_SEPARATOR . ('wp-content-' . date('Y-m-d-His') . '.zip');
                $listPath = getJobsDir() . DIRECTORY_SEPARATOR . 'job-' . $jobId . '.list';
                $sourceDir = __DIR__ . '/wp-content';

                jobLog($jobId, 'Building file list...');
                $logs = [];
                $ignoreDirNames = getIgnoreDirNamesFromRequest();
                [$totalFiles, $totalBytes] = createWpContentFileList($listPath, $excludeUploads, $ignoreDirNames, $sourceDir, $logs);
                foreach ($logs as $l) {
                    jobLog($jobId, (string)$l);
                }
                jobLog($jobId, "File list ready: $totalFiles files");

                $zip = new ZipArchive();
                if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
                    throw new Exception('Cannot create zip file');
                }
                $zip->close();

                updateJob($jobId, [
                    'status' => 'running',
                    'work' => [
                        'zip_path' => $zipPath,
                        'list_path' => $listPath,
                        'offset' => 0,
                        'total_files' => $totalFiles,
                        'total_bytes' => $totalBytes,
                    ],
                ]);

                respondJson([
                    'success' => true,
                    'job_id' => $jobId,
                    'status' => 'running',
                    'mode' => 'chunked',
                ]);
            }

            backupFiles();
            break;
        case 'backup_full':
            $asyncRequested = ((string)($_GET['async'] ?? $_POST['async'] ?? '')) === '1';
            $canAsync = $asyncRequested && function_exists('fastcgi_finish_request');
            $chunkedRequested = ((string)($_GET['chunked'] ?? $_POST['chunked'] ?? '')) === '1';
            $excludeUploads = ((string)($_GET['exclude_uploads'] ?? $_POST['exclude_uploads'] ?? '')) === '1';
            if ($canAsync) {
                $job = createJob('backup_full', ['exclude_uploads' => $excludeUploads]);
                $jobId = (string)$job['id'];
                $GLOBALS['backup_job_id'] = $jobId;

                updateJob($jobId, ['status' => 'running']);
                respondJsonAndContinue([
                    'success' => true,
                    'job_id' => $jobId,
                    'status' => 'running',
                    'mode' => 'async',
                ]);

                ignore_user_abort(true);
                set_time_limit(0);
                jobLog($jobId, 'Job started: full backup' . ($excludeUploads ? ' (excluding uploads)' : ''));

                try {
                    $backupDir = ensureBackupDir();
                    $result = fullBackupResult($wpConfig, $backupDir, $excludeUploads, $jobId);
                    updateJob($jobId, [
                        'status' => 'complete',
                        'result' => $result,
                    ]);
                    foreach (($result['logs'] ?? []) as $l) {
                        jobLog($jobId, (string)$l);
                    }
                } catch (Exception $e) {
                    jobFail($jobId, $e->getMessage(), ['ERROR: ' . $e->getMessage()]);
                }
                exit;
            }

            if ($chunkedRequested || $asyncRequested) {
                $job = createJob('backup_full_chunked', ['exclude_uploads' => $excludeUploads]);
                $jobId = (string)$job['id'];
                $GLOBALS['backup_job_id'] = $jobId;

                $backupDir = ensureBackupDir();
                ensureBackupDirReady($backupDir);
                $timestamp = date('Y-m-d-His');
                $zipPath = $backupDir . DIRECTORY_SEPARATOR . ('full-backup-' . $timestamp . '.zip');
                $listPath = getJobsDir() . DIRECTORY_SEPARATOR . 'job-' . $jobId . '.list';
                $sourceDir = __DIR__ . '/wp-content';

                jobLog($jobId, 'Dumping database for full backup...');
                $dbFilename = 'database-' . $timestamp . '.sql';
                $dbFilepath = $backupDir . DIRECTORY_SEPARATOR . $dbFilename;
                $dbLogs = [];
                $dbStats = dumpDatabaseToSqlFile($wpConfig, $dbFilepath, $dbLogs);
                foreach ($dbLogs as $l) {
                    jobLog($jobId, (string)$l);
                }

                $zip = new ZipArchive();
                if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
                    throw new Exception('Cannot create zip file');
                }
                $zip->addFile($dbFilepath, $dbFilename);
                if (method_exists($zip, 'setCompressionName')) {
                    @$zip->setCompressionName($dbFilename, ZipArchive::CM_STORE);
                }
                $zip->close();
                @unlink($dbFilepath);

                jobLog($jobId, 'Building file list...');
                $logs = [];
                $ignoreDirNames = getIgnoreDirNamesFromRequest();
                [$totalFiles, $totalBytes] = createWpContentFileList($listPath, $excludeUploads, $ignoreDirNames, $sourceDir, $logs);
                foreach ($logs as $l) {
                    jobLog($jobId, (string)$l);
                }
                jobLog($jobId, "File list ready: $totalFiles files");

                updateJob($jobId, [
                    'status' => 'running',
                    'progress' => [
                        'tables' => $dbStats['tables'],
                        'rows' => $dbStats['rows'],
                        'bytes' => $dbStats['bytes'],
                    ],
                    'work' => [
                        'zip_path' => $zipPath,
                        'list_path' => $listPath,
                        'offset' => 0,
                        'total_files' => $totalFiles,
                        'total_bytes' => $totalBytes + $dbStats['bytes'],
                    ],
                ]);

                respondJson([
                    'success' => true,
                    'job_id' => $jobId,
                    'status' => 'running',
                    'mode' => 'chunked',
                ]);
            }

            backupFull($wpConfig);
            break;
        case 'job_status':
            $jobId = (string)($_GET['id'] ?? $_POST['id'] ?? '');
            if ($jobId === '') {
                respondJson(['success' => false, 'error' => 'Missing job id', 'logs' => ['ERROR: Missing job id']], 400);
            }
            $job = readJob($jobId);
            if (!$job) {
                respondJson(['success' => false, 'error' => 'Job not found', 'logs' => ['ERROR: Job not found']], 404);
            }
            $logs = tailFileLines(jobLogPath($jobId), 250);
            respondJson([
                'success' => true,
                'job' => $job,
                'logs' => $logs,
            ]);
            break;
        case 'job_step':
            $jobId = (string)($_GET['id'] ?? $_POST['id'] ?? '');
            if ($jobId === '') {
                respondJson(['success' => false, 'error' => 'Missing job id', 'logs' => ['ERROR: Missing job id']], 400);
            }
            $job = readJob($jobId);
            if (!$job) {
                respondJson(['success' => false, 'error' => 'Job not found', 'logs' => ['ERROR: Job not found']], 404);
            }
            if (($job['status'] ?? '') === 'complete') {
                respondJson([
                    'success' => true,
                    'job' => $job,
                    'logs' => tailFileLines(jobLogPath($jobId), 250),
                ]);
            }
            if (($job['status'] ?? '') === 'error') {
                respondJson([
                    'success' => false,
                    'job' => $job,
                    'error' => $job['error'] ?? 'Job failed',
                    'logs' => tailFileLines(jobLogPath($jobId), 250),
                ], 500);
            }

            if (!in_array((string)($job['type'] ?? ''), ['backup_files_chunked', 'backup_full_chunked'], true)) {
                respondJson(['success' => false, 'error' => 'Job is not chunked', 'logs' => ['ERROR: Job is not chunked']], 400);
            }

            $GLOBALS['backup_job_id'] = $jobId;
            try {
                $updated = runChunkedZipStep($job, 500, 8);
                respondJson([
                    'success' => true,
                    'job' => $updated,
                    'logs' => tailFileLines(jobLogPath($jobId), 250),
                ]);
            } catch (Exception $e) {
                jobFail($jobId, $e->getMessage(), ['ERROR: ' . $e->getMessage()]);
                respondJson([
                    'success' => false,
                    'error' => $e->getMessage(),
                    'job' => readJob($jobId),
                    'logs' => tailFileLines(jobLogPath($jobId), 250),
                ], 500);
            }
            break;
        case 'download':
            downloadBackup();
            break;
        case 'delete':
            deleteBackup();
            break;
    }
}

// Load config for display (only when showing the page)
$wpConfig = getWpConfig();
if (!$wpConfig || !is_array($wpConfig)) {
    $wpConfig = [
        'DB_NAME' => '',
        'DB_HOST' => '',
        'DB_USER' => '',
        '_source' => '',
    ];
}

function backupDatabaseOld($config) {
    set_time_limit(0);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    
    $logs = [];
    
    try {
        $logs[] = "Starting database backup...";
        
        $backupDir = __DIR__ . '/wp-content/backups';
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0755, true);
            $logs[] = "Created backup directory";
        }
        
        $filename = 'database-' . date('Y-m-d-His') . '.sql';
        $filepath = $backupDir . '/' . $filename;
        $logs[] = "Backup file: $filename";
        
        $logs[] = "Connecting to database: {$config['DB_NAME']}@{$config['DB_HOST']}";
        $mysqli = new mysqli($config['DB_HOST'], $config['DB_USER'], $config['DB_PASSWORD'], $config['DB_NAME']);
        
        if ($mysqli->connect_error) {
            throw new Exception('Connection failed: ' . $mysqli->connect_error);
        }
        $logs[] = "Database connection established";
        
        $tables = array();
        $result = $mysqli->query('SHOW TABLES');
        while ($row = $result->fetch_row()) {
            $tables[] = $row[0];
        }
        $logs[] = "Found " . count($tables) . " tables to backup";
        
        $sqlScript = "-- WordPress Database Backup\n";
        $sqlScript .= "-- Generated: " . date('Y-m-d H:i:s') . "\n";
        $sqlScript .= "-- Database: {$config['DB_NAME']}\n\n";
        
        $totalRows = 0;
        foreach ($tables as $table) {
            $logs[] = "Backing up table: $table";
            
            $sqlScript .= "-- Table: $table\n";
            $sqlScript .= "DROP TABLE IF EXISTS `$table`;\n";
            
            $result = $mysqli->query("SHOW CREATE TABLE `$table`");
            $row = $result->fetch_row();
            $sqlScript .= $row[1] . ";\n\n";
            
            $result = $mysqli->query("SELECT * FROM `$table`");
            $numFields = $result->field_count;
            $rowCount = $result->num_rows;
            $totalRows += $rowCount;
            
            if ($rowCount > 0) {
                $logs[] = "  - $rowCount rows";
                while ($row = $result->fetch_row()) {
                    $sqlScript .= "INSERT INTO `$table` VALUES(";
                    for ($i = 0; $i < $numFields; $i++) {
                        $row[$i] = $mysqli->real_escape_string($row[$i]);
                        $sqlScript .= isset($row[$i]) ? '"' . $row[$i] . '"' : '""';
                        if ($i < ($numFields - 1)) {
                            $sqlScript .= ',';
                        }
                    }
                    $sqlScript .= ");\n";
                }
            } else {
                $logs[] = "  - 0 rows (empty table)";
            }
            $sqlScript .= "\n\n";
        }
        
        file_put_contents($filepath, $sqlScript);
        $mysqli->close();
        
        $filesize = filesize($filepath);
        $logs[] = "Database backup completed";
        $logs[] = "Total rows backed up: $totalRows";
        $logs[] = "File size: " . formatBytes($filesize);
        
        echo json_encode([
            'success' => true,
            'filename' => $filename,
            'size' => formatBytes($filesize),
            'path' => $filepath,
            'logs' => $logs,
            'tables' => count($tables),
            'rows' => $totalRows
        ]);
    } catch (Exception $e) {
        $logs[] = "ERROR: " . $e->getMessage();
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage(),
            'logs' => $logs
        ]);
    }
    exit;
}

function backupFilesOld() {
    set_time_limit(0);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    
    $logs = [];
    
    try {
        $logs[] = "Starting wp-content files backup...";
        
        $backupDir = __DIR__ . '/wp-content/backups';
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0755, true);
            $logs[] = "Created backup directory";
        }
        
        $filename = 'wp-content-' . date('Y-m-d-His') . '.zip';
        $filepath = $backupDir . '/' . $filename;
        $logs[] = "Backup file: $filename";
        
        $sourceDir = __DIR__ . '/wp-content';
        $logs[] = "Source directory: $sourceDir";
        
        $zip = new ZipArchive();
        if ($zip->open($filepath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
            throw new Exception('Cannot create zip file');
        }
        $logs[] = "ZIP archive created";
        
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        
        $fileCount = 0;
        $totalSize = 0;
        foreach ($files as $file) {
            if (!$file->isDir()) {
                $filePath = $file->getRealPath();
                $relativePath = 'wp-content/' . substr($filePath, strlen($sourceDir) + 1);
                
                // Skip backups folder
                if (strpos($relativePath, 'wp-content/backups') === 0) {
                    continue;
                }
                
                $zip->addFile($filePath, $relativePath);
                $fileCount++;
                $totalSize += $file->getSize();
                
                if ($fileCount % 100 == 0) {
                    $logs[] = "Added $fileCount files...";
                }
            }
        }
        
        $logs[] = "Total files added: $fileCount";
        $logs[] = "Total size: " . formatBytes($totalSize);
        $logs[] = "Compressing files...";
        
        $zip->close();
        $logs[] = "ZIP archive closed";
        
        $filesize = filesize($filepath);
        $logs[] = "Files backup completed";
        $logs[] = "Compressed size: " . formatBytes($filesize);
        $compression = $totalSize > 0 ? round((1 - $filesize / $totalSize) * 100, 1) : 0;
        $logs[] = "Compression ratio: {$compression}%";
        
        echo json_encode([
            'success' => true,
            'filename' => $filename,
            'size' => formatBytes($filesize),
            'path' => $filepath,
            'logs' => $logs,
            'files' => $fileCount,
            'compression' => $compression
        ]);
    } catch (Exception $e) {
        $logs[] = "ERROR: " . $e->getMessage();
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage(),
            'logs' => $logs
        ]);
    }
    exit;
}

function backupFullOld($config) {
    set_time_limit(0);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    
    $logs = [];
    
    try {
        $logs[] = "Starting full backup (database + files)...";
        
        $backupDir = __DIR__ . '/wp-content/backups';
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0755, true);
            $logs[] = "Created backup directory";
        }
        
        $timestamp = date('Y-m-d-His');
        $filename = 'full-backup-' . $timestamp . '.zip';
        $filepath = $backupDir . '/' . $filename;
        $logs[] = "Backup file: $filename";
        
        // First backup database
        $logs[] = "Step 1/2: Backing up database...";
        $dbFilename = 'database-' . $timestamp . '.sql';
        $dbFilepath = $backupDir . '/' . $dbFilename;
        
        $logs[] = "Connecting to database: {$config['DB_NAME']}@{$config['DB_HOST']}";
        $mysqli = new mysqli($config['DB_HOST'], $config['DB_USER'], $config['DB_PASSWORD'], $config['DB_NAME']);
        if ($mysqli->connect_error) {
            throw new Exception('Connection failed: ' . $mysqli->connect_error);
        }
        $logs[] = "Database connection established";
        
        $tables = array();
        $result = $mysqli->query('SHOW TABLES');
        while ($row = $result->fetch_row()) {
            $tables[] = $row[0];
        }
        $logs[] = "Found " . count($tables) . " tables";
        
        $sqlScript = "-- WordPress Full Backup - Database\n";
        $sqlScript .= "-- Generated: " . date('Y-m-d H:i:s') . "\n";
        $sqlScript .= "-- Database: {$config['DB_NAME']}\n\n";
        
        $totalRows = 0;
        foreach ($tables as $table) {
            $sqlScript .= "-- Table: $table\n";
            $sqlScript .= "DROP TABLE IF EXISTS `$table`;\n";
            
            $result = $mysqli->query("SHOW CREATE TABLE `$table`");
            $row = $result->fetch_row();
            $sqlScript .= $row[1] . ";\n\n";
            
            $result = $mysqli->query("SELECT * FROM `$table`");
            $numFields = $result->field_count;
            $totalRows += $result->num_rows;
            
            if ($result->num_rows > 0) {
                while ($row = $result->fetch_row()) {
                    $sqlScript .= "INSERT INTO `$table` VALUES(";
                    for ($i = 0; $i < $numFields; $i++) {
                        $row[$i] = $mysqli->real_escape_string($row[$i]);
                        $sqlScript .= isset($row[$i]) ? '"' . $row[$i] . '"' : '""';
                        if ($i < ($numFields - 1)) {
                            $sqlScript .= ',';
                        }
                    }
                    $sqlScript .= ");\n";
                }
            }
            $sqlScript .= "\n\n";
        }
        
        file_put_contents($dbFilepath, $sqlScript);
        $mysqli->close();
        $dbSize = filesize($dbFilepath);
        $logs[] = "Database backup complete: " . formatBytes($dbSize) . ", $totalRows rows";
        
        // Now create full zip
        $logs[] = "Step 2/2: Creating ZIP archive...";
        $zip = new ZipArchive();
        if ($zip->open($filepath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
            throw new Exception('Cannot create zip file');
        }
        
        // Add database
        $zip->addFile($dbFilepath, $dbFilename);
        $logs[] = "Added database file to archive";
        
        // Add wp-content
        $logs[] = "Adding wp-content files...";
        $sourceDir = __DIR__ . '/wp-content';
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        
        $fileCount = 0;
        $totalSize = $dbSize;
        foreach ($files as $file) {
            if (!$file->isDir()) {
                $filePath = $file->getRealPath();
                $relativePath = 'wp-content/' . substr($filePath, strlen($sourceDir) + 1);
                
                if (strpos($relativePath, 'wp-content/backups') === 0) {
                    continue;
                }
                
                $zip->addFile($filePath, $relativePath);
                $fileCount++;
                $totalSize += $file->getSize();
                
                if ($fileCount % 100 == 0) {
                    $logs[] = "Added $fileCount files...";
                }
            }
        }
        
        $logs[] = "Total files: $fileCount";
        $logs[] = "Compressing archive...";
        $zip->close();
        
        // Clean up temp database file
        unlink($dbFilepath);
        
        $filesize = filesize($filepath);
        $compression = $totalSize > 0 ? round((1 - $filesize / $totalSize) * 100, 1) : 0;
        $logs[] = "Full backup completed successfully!";
        $logs[] = "Final size: " . formatBytes($filesize) . " (compression: {$compression}%)";
        
        echo json_encode([
            'success' => true,
            'filename' => $filename,
            'size' => formatBytes($filesize),
            'path' => $filepath,
            'logs' => $logs,
            'tables' => count($tables),
            'rows' => $totalRows,
            'files' => $fileCount,
            'compression' => $compression
        ]);
    } catch (Exception $e) {
        $logs[] = "ERROR: " . $e->getMessage();
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage(),
            'logs' => $logs
        ]);
    }
    exit;
}

// ============================
// Optimized backup routines (streaming + exclusions)
// ============================

function parseDbHost(string $host): array {
    $host = trim($host);
    $port = null;
    $socket = null;

    // Supports "host:port" and "host:/path/to/socket". Keep it conservative.
    if (strpos($host, ':') !== false && substr_count($host, ':') === 1 && $host[0] !== '[') {
        [$h, $maybePortOrSocket] = explode(':', $host, 2);
        if ($maybePortOrSocket !== '' && ctype_digit($maybePortOrSocket)) {
            $host = $h;
            $port = (int)$maybePortOrSocket;
        } elseif ($maybePortOrSocket !== '' && ($maybePortOrSocket[0] === '/' || (strlen($maybePortOrSocket) > 1 && $maybePortOrSocket[1] === ':'))) {
            $host = $h;
            $socket = $maybePortOrSocket;
        }
    }

    return [$host, $port, $socket];
}

function openDbConnection(array $config): mysqli {
    if (!class_exists('mysqli')) {
        throw new Exception('PHP extension "mysqli" is not available.');
    }

    [$host, $port, $socket] = parseDbHost((string)$config['DB_HOST']);
    $mysqli = new mysqli(
        $host,
        (string)$config['DB_USER'],
        (string)$config['DB_PASSWORD'],
        (string)$config['DB_NAME'],
        $port ?? (int)ini_get('mysqli.default_port'),
        $socket ?? (string)ini_get('mysqli.default_socket')
    );

    if ($mysqli->connect_error) {
        throw new Exception('Connection failed: ' . $mysqli->connect_error);
    }

    @$mysqli->set_charset('utf8mb4');
    return $mysqli;
}

function buildMysqliTypeSets(): array {
    $numeric = [];
    foreach (['MYSQLI_TYPE_TINY', 'MYSQLI_TYPE_SHORT', 'MYSQLI_TYPE_LONG', 'MYSQLI_TYPE_LONGLONG', 'MYSQLI_TYPE_INT24', 'MYSQLI_TYPE_DECIMAL', 'MYSQLI_TYPE_NEWDECIMAL', 'MYSQLI_TYPE_FLOAT', 'MYSQLI_TYPE_DOUBLE'] as $c) {
        if (defined($c)) {
            $numeric[] = constant($c);
        }
    }

    $blob = [];
    foreach (['MYSQLI_TYPE_TINY_BLOB', 'MYSQLI_TYPE_MEDIUM_BLOB', 'MYSQLI_TYPE_LONG_BLOB', 'MYSQLI_TYPE_BLOB', 'MYSQLI_TYPE_BIT'] as $c) {
        if (defined($c)) {
            $blob[] = constant($c);
        }
    }

    return [$numeric, $blob];
}

function sqlValue(mysqli $mysqli, $value, object $field, array $numericTypes, array $blobTypes): string {
    if ($value === null) {
        return 'NULL';
    }

    $type = $field->type ?? null;
    if ($type !== null && in_array($type, $numericTypes, true)) {
        return $value === '' ? '0' : (string)$value;
    }

    if ($type !== null && in_array($type, $blobTypes, true)) {
        $bin = (string)$value;
        return $bin === '' ? "''" : ('0x' . bin2hex($bin));
    }

    return "'" . $mysqli->real_escape_string((string)$value) . "'";
}

function dumpDatabaseToSqlFile(array $config, string $filepath, array &$logs): array {
    releaseSessionLock();
    // Ensure target directory exists, otherwise fallback to a writable backup dir.
    $targetDir = dirname($filepath);
    try {
        ensureBackupDirReady($targetDir);
    } catch (Exception $e) {
        $fallbackDir = ensureBackupDir();
        $filepath = $fallbackDir . DIRECTORY_SEPARATOR . basename($filepath);
        $logs[] = "WARNING: " . $e->getMessage();
        $logs[] = "Falling back to backup dir: $fallbackDir";
        ensureBackupDirReady(dirname($filepath));
    }

    $handle = @fopen($filepath, 'wb');
    if (!$handle) {
        throw new Exception('Unable to write SQL file: ' . $filepath);
    }

    $mysqli = openDbConnection($config);
    $logs[] = "Database connection established";

    [$numericTypes, $blobTypes] = buildMysqliTypeSets();

    $write = function(string $chunk) use ($handle) {
        if (@fwrite($handle, $chunk) === false) {
            throw new Exception('Failed to write to SQL output file.');
        }
    };

    $write("-- WordPress Database Backup\n");
    $write("-- Generated: " . date('Y-m-d H:i:s') . "\n");
    $write("-- Database: " . $config['DB_NAME'] . "\n\n");
    $write("SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n");
    $write("SET time_zone = \"+00:00\";\n");
    $write("SET FOREIGN_KEY_CHECKS=0;\n");
    $write("/*!40101 SET NAMES utf8mb4 */;\n\n");

    $tables = [];
    $result = $mysqli->query('SHOW TABLES');
    while ($row = $result->fetch_row()) {
        $tables[] = $row[0];
    }
    $result->free();
    $logs[] = "Found " . count($tables) . " tables to backup";

    $totalRows = 0;
    foreach ($tables as $table) {
        $logs[] = "Backing up table: $table";

        $write("-- Table: `$table`\n");
        $write("DROP TABLE IF EXISTS `$table`;\n");

        $createRes = $mysqli->query("SHOW CREATE TABLE `$table`");
        $createRow = $createRes ? $createRes->fetch_row() : null;
        if (!$createRow || !isset($createRow[1])) {
            throw new Exception("Failed to read CREATE TABLE statement for $table");
        }
        $write($createRow[1] . ";\n\n");
        $createRes->free();

        $selectRes = $mysqli->query("SELECT * FROM `$table`", MYSQLI_USE_RESULT);
        if (!$selectRes) {
            throw new Exception("Failed to read table data for $table: " . $mysqli->error);
        }

        $fields = $selectRes->fetch_fields();
        $colNames = [];
        foreach ($fields as $f) {
            $colNames[] = '`' . $f->name . '`';
        }
        $insertPrefix = "INSERT INTO `$table` (" . implode(',', $colNames) . ") VALUES\n";

        $batch = [];
        $batchCount = 0;
        while ($row = $selectRes->fetch_row()) {
            $values = [];
            foreach ($row as $idx => $val) {
                $values[] = sqlValue($mysqli, $val, $fields[$idx], $numericTypes, $blobTypes);
            }
            $batch[] = '(' . implode(',', $values) . ')';
            $batchCount++;
            $totalRows++;

            if ($batchCount >= DB_DUMP_INSERT_BATCH) {
                $write($insertPrefix . implode(",\n", $batch) . ";\n");
                $batch = [];
                $batchCount = 0;
            }

            if ($totalRows % DB_DUMP_LOG_EVERY_ROWS === 0) {
                $logs[] = "  - Exported $totalRows rows so far...";
            }
        }

        if (!empty($batch)) {
            $write($insertPrefix . implode(",\n", $batch) . ";\n");
        }

        $write("\n\n");
        $selectRes->free();
    }

    $write("SET FOREIGN_KEY_CHECKS=1;\n");

    $mysqli->close();
    fclose($handle);

    return [
        'tables' => count($tables),
        'rows' => $totalRows,
        'bytes' => filesize($filepath),
        'filepath' => $filepath,
    ];
}

function databaseBackupResult(array $config, string $backupDir, array &$logs, ?string $jobId = null): array {
    releaseSessionLock();
    $backupDir = ensureBackupDir();
    ensureBackupDirReady($backupDir);

    $filename = 'database-' . date('Y-m-d-His') . '.sql';
    $filepath = $backupDir . DIRECTORY_SEPARATOR . $filename;
    $logs[] = "Backup file: $filename";
    $logs[] = "Connecting to database: {$config['DB_NAME']}@{$config['DB_HOST']}";

    $stats = dumpDatabaseToSqlFile($config, $filepath, $logs);
    if (!empty($stats['filepath'])) {
        $filepath = (string)$stats['filepath'];
        $filename = basename($filepath);
    }

    if ($jobId) {
        updateJob($jobId, [
            'progress' => [
                'tables' => $stats['tables'],
                'rows' => $stats['rows'],
                'bytes' => $stats['bytes'],
            ],
        ]);
    }

    $logs[] = "Database backup completed";
    $logs[] = "Total rows backed up: " . $stats['rows'];
    $logs[] = "File size: " . formatBytes($stats['bytes']);

    return [
        'success' => true,
        'filename' => $filename,
        'size' => formatBytes($stats['bytes']),
        'path' => $filepath,
        'logs' => $logs,
        'tables' => $stats['tables'],
        'rows' => $stats['rows'],
    ];
}

function wpContentExcludePrefixes(): array {
    return [
        'wp-content/backups/',
        'wp-content/cache/',
        'wp-content/wflogs/',
        'wp-content/ai1wm-backups/',
        'wp-content/updraft/',
        'wp-content/wp-rocket-cache/',
        'wp-content/litespeed/',
        'wp-content/upgrade/',
    ];
}

function shouldExcludeWpContentPath(string $relativePath, array $excludePrefixes, array $ignoreDirNames = []): bool {
    foreach ($excludePrefixes as $prefix) {
        if (strpos($relativePath, $prefix) === 0) {
            return true;
        }
    }

    if (!empty($ignoreDirNames)) {
        $parts = explode('/', str_replace('\\', '/', $relativePath));
        foreach ($parts as $part) {
            $part = strtolower(trim($part));
            if ($part === '' || $part === '.' || $part === '..' || $part === 'wp-content') {
                continue;
            }
            if (in_array($part, $ignoreDirNames, true)) {
                return true;
            }
        }
    }

    return false;
}

function alreadyCompressedExtensions(): array {
    return [
        'jpg','jpeg','png','gif','webp','avif','mp4','mov','mkv','zip','gz','bz2','rar','7z','pdf','mp3','ogg','webm'
    ];
}

function addWpContentToZip(ZipArchive $zip, string $sourceDir, bool $excludeUploads, array $ignoreDirNames, array &$logs): array {
    $excludePrefixes = wpContentExcludePrefixes();
    if ($excludeUploads) {
        $excludePrefixes[] = 'wp-content/uploads/';
    }
    $alreadyCompressedExts = alreadyCompressedExtensions();

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    $fileCount = 0;
    $totalSize = 0;

    foreach ($files as $file) {
        if ($file->isDir() || $file->isLink()) {
            continue;
        }

        $filePath = $file->getPathname();
        $relativePath = 'wp-content/' . substr($filePath, strlen($sourceDir) + 1);
        $relativePath = str_replace('\\', '/', $relativePath);

        if (shouldExcludeWpContentPath($relativePath, $excludePrefixes, $ignoreDirNames)) {
            continue;
        }

        if (!$zip->addFile($filePath, $relativePath)) {
            throw new Exception('Failed to add file to ZIP: ' . $relativePath);
        }

        // Prefer speed on large sites: store files by default (compression can be CPU-heavy).
        if (method_exists($zip, 'setCompressionName')) {
            @$zip->setCompressionName($relativePath, ZipArchive::CM_STORE);
        }

        $ext = strtolower(pathinfo($relativePath, PATHINFO_EXTENSION));
        if (in_array($ext, $alreadyCompressedExts, true) && method_exists($zip, 'setCompressionName')) {
            @$zip->setCompressionName($relativePath, ZipArchive::CM_STORE);
        }

        $fileCount++;
        $totalSize += $file->getSize();

        if ($fileCount % FILES_LOG_EVERY === 0) {
            $logs[] = "Added $fileCount files...";
        }
    }

    return [$fileCount, $totalSize];
}

function filesBackupResult(string $backupDir, bool $excludeUploads, ?string $jobId = null): array {
    set_time_limit(0);
    releaseSessionLock();

    $logs = [];
    $logs[] = "Starting wp-content files backup...";
    if ($excludeUploads) {
        $logs[] = "Option: Excluding uploads/ for faster backup";
    }
    $ignoreDirNames = getIgnoreDirNamesFromRequest();
    if (!empty($ignoreDirNames)) {
        $logs[] = "Ignoring folders: " . implode(', ', $ignoreDirNames);
    }

    if (!class_exists('ZipArchive')) {
        throw new Exception('PHP extension "zip" (ZipArchive) is not available.');
    }

    $backupDir = ensureBackupDir();
    ensureBackupDirReady($backupDir);
    $logs[] = "Backup directory: $backupDir";

    $filename = 'wp-content-' . date('Y-m-d-His') . '.zip';
    $filepath = $backupDir . DIRECTORY_SEPARATOR . $filename;
    $logs[] = "Backup file: $filename";

    $sourceDir = __DIR__ . '/wp-content';
    $logs[] = "Source directory: $sourceDir";

    $zip = new ZipArchive();
    if ($zip->open($filepath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        throw new Exception('Cannot create zip file');
    }
    $logs[] = "ZIP archive created";

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    // Lightweight progress updates for async jobs.
    $excludePrefixes = wpContentExcludePrefixes();
    if ($excludeUploads) {
        $excludePrefixes[] = 'wp-content/uploads/';
    }

    $fileCount = 0;
    $totalSize = 0;
    foreach ($files as $file) {
        if ($file->isDir() || $file->isLink()) {
            continue;
        }

        $filePath = $file->getPathname();
        $relativePath = 'wp-content/' . substr($filePath, strlen($sourceDir) + 1);
        $relativePath = str_replace('\\', '/', $relativePath);

        if (shouldExcludeWpContentPath($relativePath, $excludePrefixes, $ignoreDirNames)) {
            continue;
        }

        if (!$zip->addFile($filePath, $relativePath)) {
            throw new Exception('Failed to add file to ZIP: ' . $relativePath);
        }
        if (method_exists($zip, 'setCompressionName')) {
            @$zip->setCompressionName($relativePath, ZipArchive::CM_STORE);
        }

        $fileCount++;
        $totalSize += $file->getSize();

        if ($fileCount % FILES_LOG_EVERY === 0) {
            $logs[] = "Added $fileCount files...";
            if ($jobId) {
                updateJob($jobId, [
                    'status' => 'running',
                    'progress' => [
                        'files' => $fileCount,
                        'bytes' => $totalSize,
                    ],
                ]);
            }
        }
    }

    $logs[] = "Total files added: $fileCount";
    $logs[] = "Total size: " . formatBytes($totalSize);
    $logs[] = "Finalizing archive...";

    $zip->close();
    $logs[] = "ZIP archive closed";

    $filesize = filesize($filepath);
    $compression = $totalSize > 0 ? round((1 - $filesize / $totalSize) * 100, 1) : 0;
    $logs[] = "Files backup completed";
    $logs[] = "Compressed size: " . formatBytes($filesize);
    $logs[] = "Compression ratio: {$compression}%";

    return [
        'success' => true,
        'filename' => $filename,
        'size' => formatBytes($filesize),
        'path' => $filepath,
        'logs' => $logs,
        'files' => $fileCount,
        'compression' => $compression,
    ];
}

function fullBackupResult(array $config, string $backupDir, bool $excludeUploads, ?string $jobId = null): array {
    set_time_limit(0);
    releaseSessionLock();

    $logs = [];
    $logs[] = "Starting full backup (database + files)...";
    if ($excludeUploads) {
        $logs[] = "Option: Excluding uploads/ for faster backup";
    }
    $ignoreDirNames = getIgnoreDirNamesFromRequest();
    if (!empty($ignoreDirNames)) {
        $logs[] = "Ignoring folders: " . implode(', ', $ignoreDirNames);
    }

    if (!class_exists('ZipArchive')) {
        throw new Exception('PHP extension "zip" (ZipArchive) is not available.');
    }

    $backupDir = ensureBackupDir();
    ensureBackupDirReady($backupDir);
    $logs[] = "Backup directory: $backupDir";

    $timestamp = date('Y-m-d-His');
    $filename = 'full-backup-' . $timestamp . '.zip';
    $filepath = $backupDir . DIRECTORY_SEPARATOR . $filename;
    $logs[] = "Backup file: $filename";

    $logs[] = "Step 1/2: Backing up database...";
    $dbFilename = 'database-' . $timestamp . '.sql';
    $dbFilepath = $backupDir . DIRECTORY_SEPARATOR . $dbFilename;
    $logs[] = "Connecting to database: {$config['DB_NAME']}@{$config['DB_HOST']}";
    $dbStats = dumpDatabaseToSqlFile($config, $dbFilepath, $logs);
    $dbSize = $dbStats['bytes'];
    $logs[] = "Database backup complete: " . formatBytes($dbSize) . ", {$dbStats['rows']} rows";

    if ($jobId) {
        updateJob($jobId, [
            'status' => 'running',
            'progress' => [
                'tables' => $dbStats['tables'],
                'rows' => $dbStats['rows'],
                'bytes' => $dbSize,
            ],
        ]);
    }

    $logs[] = "Step 2/2: Creating ZIP archive...";
    $zip = new ZipArchive();
    if ($zip->open($filepath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        throw new Exception('Cannot create zip file');
    }
    $zip->addFile($dbFilepath, $dbFilename);
    if (method_exists($zip, 'setCompressionName')) {
        @$zip->setCompressionName($dbFilename, ZipArchive::CM_STORE);
    }
    $logs[] = "Added database file to archive";

    $logs[] = "Adding wp-content files...";
    $sourceDir = __DIR__ . '/wp-content';

    $excludePrefixes = wpContentExcludePrefixes();
    if ($excludeUploads) {
        $excludePrefixes[] = 'wp-content/uploads/';
    }

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    $fileCount = 0;
    $contentBytes = 0;
    foreach ($files as $file) {
        if ($file->isDir() || $file->isLink()) {
            continue;
        }

        $filePath = $file->getPathname();
        $relativePath = 'wp-content/' . substr($filePath, strlen($sourceDir) + 1);
        $relativePath = str_replace('\\', '/', $relativePath);

        if (shouldExcludeWpContentPath($relativePath, $excludePrefixes, $ignoreDirNames)) {
            continue;
        }

        if (!$zip->addFile($filePath, $relativePath)) {
            throw new Exception('Failed to add file to ZIP: ' . $relativePath);
        }
        if (method_exists($zip, 'setCompressionName')) {
            @$zip->setCompressionName($relativePath, ZipArchive::CM_STORE);
        }

        $fileCount++;
        $contentBytes += $file->getSize();

        if ($fileCount % FILES_LOG_EVERY === 0) {
            $logs[] = "Added $fileCount files...";
            if ($jobId) {
                updateJob($jobId, [
                    'status' => 'running',
                    'progress' => [
                        'files' => $fileCount,
                        'bytes' => $dbSize + $contentBytes,
                        'tables' => $dbStats['tables'],
                        'rows' => $dbStats['rows'],
                    ],
                ]);
            }
        }
    }

    $logs[] = "Total files: $fileCount";
    $logs[] = "Finalizing archive...";
    $zip->close();

    @unlink($dbFilepath);

    $filesize = filesize($filepath);
    $totalSize = $dbSize + $contentBytes;
    $compression = $totalSize > 0 ? round((1 - $filesize / $totalSize) * 100, 1) : 0;
    $logs[] = "Full backup completed successfully!";
    $logs[] = "Final size: " . formatBytes($filesize) . " (compression: {$compression}%)";

    return [
        'success' => true,
        'filename' => $filename,
        'size' => formatBytes($filesize),
        'path' => $filepath,
        'logs' => $logs,
        'tables' => $dbStats['tables'],
        'rows' => $dbStats['rows'],
        'files' => $fileCount,
        'compression' => $compression,
    ];
}

function backupDatabase($config) {
    set_time_limit(0);
    $logs = [];

    try {
        $logs[] = "Starting database backup...";

        $backupDir = ensureBackupDir();
        ensureBackupDirReady($backupDir);
        $logs[] = "Backup directory: $backupDir";

        $result = databaseBackupResult($config, $backupDir, $logs);
        respondJson($result);
    } catch (Exception $e) {
        $logs[] = "ERROR: " . $e->getMessage();
        respondJson([
            'success' => false,
            'error' => $e->getMessage(),
            'logs' => $logs
        ], 500);
    }
}

function backupFiles() {
    try {
        $excludeUploads = ((string)($_GET['exclude_uploads'] ?? $_POST['exclude_uploads'] ?? '')) === '1';
        $backupDir = ensureBackupDir();
        $result = filesBackupResult($backupDir, $excludeUploads, null);
        respondJson($result);
    } catch (Exception $e) {
        respondJson([
            'success' => false,
            'error' => $e->getMessage(),
            'logs' => ['ERROR: ' . $e->getMessage()]
        ], 500);
    }
}

function backupFull($config) {
    try {
        $excludeUploads = ((string)($_GET['exclude_uploads'] ?? $_POST['exclude_uploads'] ?? '')) === '1';
        $backupDir = ensureBackupDir();
        $result = fullBackupResult($config, $backupDir, $excludeUploads, null);
        respondJson($result);
    } catch (Exception $e) {
        respondJson([
            'success' => false,
            'error' => $e->getMessage(),
            'logs' => ['ERROR: ' . $e->getMessage()]
        ], 500);
    }
}

function downloadBackup() {
    if (!isset($_GET['file'])) {
        die('No file specified');
    }

    $token = (string)($_GET['csrf'] ?? '');
    $expected = (string)($_SESSION['backup_csrf'] ?? '');
    if ($expected === '' || !hash_equals($expected, $token)) {
        die('Invalid CSRF token');
    }
    
    $filename = basename($_GET['file']);
    $filepath = resolveBackupFilepath($filename);
    
    if (!$filepath || !file_exists($filepath)) {
        die('File not found');
    }

    if (function_exists('session_write_close')) {
        @session_write_close();
    }
    set_time_limit(0);
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: no-cache');

    $handle = fopen($filepath, 'rb');
    if (!$handle) {
        die('Unable to read file');
    }
    while (!feof($handle)) {
        echo fread($handle, 1024 * 1024);
        @flush();
    }
    fclose($handle);
    exit;
}

function deleteBackup() {
    $file = $_POST['file'] ?? $_GET['file'] ?? null;
    if (!$file) {
        respondJson(['success' => false, 'error' => 'No file specified', 'logs' => ['ERROR: No file specified']], 400);
    }

    $filename = basename((string)$file);
    $filepath = resolveBackupFilepath($filename);

    if ($filepath && file_exists($filepath) && !@unlink($filepath)) {
        respondJson(['success' => false, 'error' => 'Failed to delete file', 'logs' => ['ERROR: Failed to delete file']], 500);
    }
    if (!$filepath) {
        respondJson(['success' => false, 'error' => 'File not found', 'logs' => ['ERROR: File not found']], 404);
    }

    respondJson(['success' => true, 'logs' => ['Deleted: ' . $filename]]);
}

function formatBytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

function getExistingBackups() {
    $dirs = getBackupSearchDirs();
    $files = [];
    foreach ($dirs as $dir) {
        if (!is_dir($dir)) {
            continue;
        }
        $globbed = glob($dir . '/*.{sql,zip}', GLOB_BRACE);
        if (is_array($globbed)) {
            $files = array_merge($files, $globbed);
        }
    }
    $backups = array();
    $seen = [];
    foreach ($files as $file) {
        $real = realpath($file) ?: $file;
        if (isset($seen[$real])) {
            continue;
        }
        $seen[$real] = true;
        $ts = filemtime($file);
        $backups[] = array(
            'name' => basename($file),
            'size' => formatBytes(filesize($file)),
            'date' => date('Y-m-d H:i:s', $ts),
            'ts' => $ts,
            'type' => pathinfo($file, PATHINFO_EXTENSION)
        );
    }
    
    usort($backups, function($a, $b) {
        return ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0);
    });
    
    return $backups;
}

$existingBackups = getExistingBackups();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WordPress Backup Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        header h1 {
            color: #333;
            font-size: 28px;
        }
        
        .logout-btn {
            background: #dc3545;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: 600;
            transition: background 0.3s;
        }
        
        .logout-btn:hover {
            background: #c82333;
        }
        
        .backup-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .backup-section h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 22px;
        }
        
        .backup-buttons {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .backup-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .backup-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .backup-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .progress-container {
            display: none;
            margin-top: 20px;
        }
        
        .progress-bar-wrapper {
            background: #f0f0f0;
            border-radius: 10px;
            height: 30px;
            overflow: hidden;
            position: relative;
        }
        
        .progress-bar {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            width: 0%;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 14px;
        }
        
        .progress-text {
            margin-top: 10px;
            color: #666;
            text-align: center;
        }
        
        .status-message {
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            display: none;
        }
        
        .status-message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .status-message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .backups-list {
            margin-top: 20px;
        }
        
        .backup-item {
            background: #f8f9fa;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s;
        }
        
        .backup-item:hover {
            background: #e9ecef;
        }
        
        .backup-info {
            flex: 1;
        }
        
        .backup-name {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        
        .backup-meta {
            font-size: 14px;
            color: #666;
        }
        
        .backup-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn-download, .btn-delete {
            padding: 8px 16px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s;
        }

        .btn-secondary {
            padding: 10px 14px;
            border-radius: 8px;
            border: 1px solid rgba(0,0,0,0.12);
            background: rgba(255,255,255,0.9);
            color: #18324a;
            font-weight: 700;
            cursor: pointer;
        }

        .btn-secondary:hover {
            background: #fff;
        }
        
        .btn-download {
            background: #28a745;
            color: white;
        }
        
        .btn-download:hover {
            background: #218838;
        }
        
        .btn-delete {
            background: #dc3545;
            color: white;
        }
        
        .btn-delete:hover {
            background: #c82333;
        }
        
        .type-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 10px;
        }
        
        .type-badge.sql {
            background: #17a2b8;
            color: white;
        }
        
        .type-badge.zip {
            background: #ffc107;
            color: #333;
        }
        
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .info-box strong {
            color: #1976D2;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
            align-items: start;
        }

        @media (max-width: 900px) {
            .info-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }

        @media (max-width: 520px) {
            .info-grid { grid-template-columns: 1fr; }
        }

        .info-item {
            background: rgba(255,255,255,0.65);
            border: 1px solid rgba(25,118,210,0.12);
            border-radius: 10px;
            padding: 12px;
            min-width: 0;
        }

        .info-label {
            font-size: 12px;
            font-weight: 700;
            color: #1976D2;
            letter-spacing: 0.2px;
            margin-bottom: 6px;
        }

        .info-value {
            color: #18324a;
            font-size: 14px;
            word-break: break-word;
        }

        .options-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-top: 12px;
        }

        @media (max-width: 900px) {
            .options-grid { grid-template-columns: 1fr; }
        }

        .option-card {
            background: rgba(255,255,255,0.65);
            border: 1px solid rgba(25,118,210,0.12);
            border-radius: 10px;
            padding: 12px;
        }

        .option-title {
            font-weight: 700;
            color: #18324a;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .option-help {
            margin-top: 6px;
            color: #506a85;
            font-size: 12px;
            line-height: 1.4;
        }

        .text-input {
            width: 100%;
            border: 1px solid rgba(0,0,0,0.15);
            border-radius: 8px;
            padding: 10px 12px;
            font-size: 14px;
            outline: none;
        }

        .text-input:focus {
            border-color: rgba(25,118,210,0.55);
            box-shadow: 0 0 0 3px rgba(25,118,210,0.15);
        }
        
        .logs-container {
            margin-top: 20px;
        }
        
        .logs-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            max-height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.6;
        }
        
        .log-entry {
            padding: 3px 0;
            color: #333;
        }
        
        .log-entry.error {
            color: #dc3545;
            font-weight: 600;
        }
        
        .log-entry.success {
            color: #28a745;
            font-weight: 600;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 3px solid rgba(255,255,255,0.3);
            border-top: 3px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🗄️ WordPress Backup Manager</h1>
            <script>document.querySelector('header h1').textContent = 'WordPress Backup Manager';</script>
            <a href="?logout=1" class="logout-btn">Logout</a>
        </header>
        
        <div class="backup-section">
            <h2>Create New Backup</h2>
            
            <div class="info-box">
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Database</div>
                        <div class="info-value"><?php echo htmlspecialchars($wpConfig['DB_NAME']); ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Host</div>
                        <div class="info-value"><?php echo htmlspecialchars($wpConfig['DB_HOST']); ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">User</div>
                        <div class="info-value"><?php echo htmlspecialchars($wpConfig['DB_USER']); ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Backup Directory</div>
                        <div class="info-value"><?php echo htmlspecialchars(getBackupDir()); ?></div>
                    </div>
                </div>

                <?php if (!empty($wpConfig['_source'])): ?>
                    <div style="margin-top: 10px; color: #506a85; font-size: 12px;">
                        <strong>Config file:</strong> <?php echo htmlspecialchars($wpConfig['_source']); ?>
                    </div>
                <?php endif; ?>
                <div style="margin-top: 10px;">
                    <button type="button" class="btn-secondary" onclick="showConfigDebug()">Test wp-config parsing</button>
                </div>

                <div class="options-grid">
                    <div class="option-card">
                        <div class="option-title">
                            <input type="checkbox" id="excludeUploads">
                            Exclude uploads
                        </div>
                        <div class="option-help">
                            Faster and smaller backups for media-heavy sites. (Database-only still includes media references.)
                        </div>
                    </div>

                    <div class="option-card">
                        <div class="option-title">Ignore folder names</div>
                        <input class="text-input" id="ignoreDirs" type="text" placeholder="<?php echo htmlspecialchars(implode(', ', parseIgnoreDirNames(BACKUP_IGNORE_DIRNAMES))); ?>">
                        <div class="option-help">
                            Comma-separated folder names to skip anywhere in <code>wp-content</code>. Example: <code>node_modules, cache, tmp</code>.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="backup-buttons">
                <button class="backup-btn" onclick="startBackup('database')">
                    <span>💾</span> Backup Database Only
                </button>
                <button class="backup-btn" onclick="startBackup('files')">
                    <span>📁</span> Backup Files Only (wp-content)
                </button>
                <button class="backup-btn" onclick="startBackup('full')">
                    <span>📦</span> Full Backup (Database + Files)
                </button>
            </div>
            
            <div class="progress-container" id="progressContainer">
                <div class="progress-bar-wrapper">
                    <div class="progress-bar" id="progressBar">0%</div>
                </div>
                <div class="progress-text" id="progressText">Preparing backup...</div>
            </div>
            
            <div class="status-message" id="statusMessage"></div>
            
            <div class="logs-container" id="logsContainer" style="display: none;">
                <h3 style="margin: 20px 0 10px; color: #333; font-size: 16px;">📋 Backup Log</h3>
                <div class="logs-box" id="logsBox"></div>
            </div>
        </div>
        
        <div class="backup-section">
            <h2>Existing Backups (<?php echo count($existingBackups); ?>)</h2>
            
            <?php if (empty($existingBackups)): ?>
                <p style="color: #666; text-align: center; padding: 20px;">No backups found. Create your first backup above!</p>
            <?php else: ?>
                <div class="backups-list">
                    <?php foreach ($existingBackups as $backup): ?>
                        <div class="backup-item">
                            <div class="backup-info">
                                <div class="backup-name">
                                    <?php echo htmlspecialchars($backup['name']); ?>
                                    <span class="type-badge <?php echo $backup['type']; ?>">
                                        <?php echo strtoupper($backup['type']); ?>
                                    </span>
                                </div>
                                <div class="backup-meta">
                                    <?php echo $backup['size']; ?> • Created: <?php echo $backup['date']; ?>
                                </div>
                            </div>
                            <div class="backup-actions">
                                <a href="?action=download&file=<?php echo urlencode($backup['name']); ?>&csrf=<?php echo urlencode($csrfToken); ?>" class="btn-download">
                                    ⬇️ Download
                                </a>
                                <a href="#" 
                                   class="btn-delete" 
                                   data-file="<?php echo htmlspecialchars($backup['name'], ENT_QUOTES); ?>"
                                   onclick="return deleteBackupFile(this.dataset.file);">
                                    🗑️ Delete
                                </a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <script>
        let currentBackupFile = '';
        const csrfToken = <?php echo json_encode($csrfToken); ?>;
        const defaultIgnoreDirs = <?php echo json_encode(implode(', ', parseIgnoreDirNames(BACKUP_IGNORE_DIRNAMES))); ?>;

        function showConfigDebug() {
            const logsContainer = document.getElementById('logsContainer');
            const logsBox = document.getElementById('logsBox');
            logsContainer.style.display = 'block';
            logsBox.innerHTML = '';

            fetch('?action=config_debug&csrf=' + encodeURIComponent(csrfToken))
                .then(r => r.json())
                .then(data => {
                    const lines = [];
                    if (!data || !data.success) {
                        lines.push('ERROR: Could not read config_debug');
                        if (data && data.error) lines.push('ERROR: ' + data.error);
                    } else {
                        lines.push('Config source: ' + (data.config && data.config._source ? data.config._source : 'unknown'));
                        lines.push('DB_NAME: ' + (data.config && data.config.DB_NAME ? data.config.DB_NAME : '(empty)'));
                        lines.push('DB_USER: ' + (data.config && data.config.DB_USER ? data.config.DB_USER : '(empty)'));
                        lines.push('DB_HOST: ' + (data.config && data.config.DB_HOST ? data.config.DB_HOST : '(empty)'));
                        lines.push('Docker placeholders detected: ' + (data.docker_placeholders_detected ? 'yes' : 'no'));
                        if (data.docker_env) {
                            Object.keys(data.docker_env).forEach(k => {
                                const v = data.docker_env[k];
                                lines.push(`${k}: set=${v.set ? 'yes' : 'no'} file_set=${v.file_set ? 'yes' : 'no'}`);
                            });
                        }
                    }

                    lines.forEach(line => {
                        const el = document.createElement('div');
                        el.className = 'log-entry';
                        if (String(line).startsWith('ERROR:')) el.className += ' error';
                        el.textContent = String(line);
                        logsBox.appendChild(el);
                    });
                    logsBox.scrollTop = logsBox.scrollHeight;
                })
                .catch(err => {
                    const el = document.createElement('div');
                    el.className = 'log-entry error';
                    el.textContent = 'ERROR: ' + err.message;
                    logsBox.appendChild(el);
                });
        }

        (function initOptions() {
            const ignoreInput = document.getElementById('ignoreDirs');
            if (!ignoreInput) return;
            const saved = localStorage.getItem('backupManagerIgnoreDirs');
            ignoreInput.value = (saved !== null) ? saved : defaultIgnoreDirs;
            ignoreInput.addEventListener('change', () => {
                localStorage.setItem('backupManagerIgnoreDirs', ignoreInput.value || '');
            });
        })();

        function deleteBackupFile(filename) {
            if (!confirm('Are you sure you want to delete this backup?')) return false;

            const body = new URLSearchParams();
            body.set('action', 'delete');
            body.set('file', filename);
            body.set('csrf', csrfToken);

            fetch('?action=delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: body.toString()
            })
            .then(r => r.json())
            .then(data => {
                if (data && data.success) {
                    window.location.reload();
                } else {
                    alert((data && data.error) ? data.error : 'Delete failed');
                }
            })
            .catch(err => alert(err.message));

            return false;
        }
        
        function startBackup(type) {
            const progressContainer = document.getElementById('progressContainer');
            const progressBar = document.getElementById('progressBar');
            const progressText = document.getElementById('progressText');
            const statusMessage = document.getElementById('statusMessage');
            const logsContainer = document.getElementById('logsContainer');
            const logsBox = document.getElementById('logsBox');
            const buttons = document.querySelectorAll('.backup-btn');
            
            // Reset and show progress
            progressContainer.style.display = 'block';
            statusMessage.style.display = 'none';
            logsContainer.style.display = 'block';
            logsBox.innerHTML = '';
            progressBar.style.width = '0%';
            progressBar.innerHTML = '0%';
            progressBar.style.background = 'linear-gradient(90deg, #667eea 0%, #764ba2 100%)';
            
            // Disable all buttons
            buttons.forEach(btn => btn.disabled = true);
            
            // Determine action and text
            let action = '';
            let actionText = '';
            const excludeUploads = !!document.getElementById('excludeUploads')?.checked;
            const ignoreDirs = (document.getElementById('ignoreDirs')?.value || '').trim();
            
            switch(type) {
                case 'database':
                    action = 'backup_database';
                    actionText = 'Backing up database...';
                    break;
                case 'files':
                    action = 'backup_files';
                    actionText = 'Backing up wp-content files...';
                    break;
                case 'full':
                    action = 'backup_full';
                    actionText = 'Creating full backup...';
                    break;
            }
            
            progressText.textContent = actionText;
            
            // Simulate progress
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += Math.random() * 15;
                if (progress > 90) progress = 90;
                progressBar.style.width = progress + '%';
                progressBar.innerHTML = '<span class="spinner"></span>';
            }, 300);
            
            // Perform backup
            let url = '?action=' + action + '&csrf=' + encodeURIComponent(csrfToken) + '&async=1';
            if (excludeUploads && (type === 'files' || type === 'full')) {
                url += '&exclude_uploads=1';
            }
            if (ignoreDirs && (type === 'files' || type === 'full')) {
                url += '&ignore_dirs=' + encodeURIComponent(ignoreDirs);
            }

            fetch(url)
                .then(response => response.text().then(text => ({ response, text })))
                .then(({ response, text }) => {
                    let data = null;
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        // keep data null
                    }

                    if (!response.ok) {
                        const err = new Error((data && data.error) ? data.error : ('Request failed: HTTP ' + response.status));
                        err.data = data;
                        err.raw = text;
                        throw err;
                    }

                    if (!data) {
                        console.error('Response was not valid JSON:', text);
                        throw new Error('Invalid JSON response. Check console for details.');
                    }

                    return data;
                })
                .then(data => {
                    if (data && data.job_id) {
                        progressText.textContent = actionText + ' (running...)';
                        if (data.mode === 'chunked') {
                            pollChunkedJob(data.job_id, progressInterval, progressBar, progressText, statusMessage, logsBox, buttons);
                        } else {
                            pollJobStatus(data.job_id, progressInterval, progressBar, progressText, statusMessage, logsBox, buttons);
                        }
                        return null;
                    }
                    return data;
                })
                .then(data => {
                    if (!data) return;
                    clearInterval(progressInterval);
                    
                    // Display logs
                    if (data.logs && data.logs.length > 0) {
                        data.logs.forEach(log => {
                            const logEntry = document.createElement('div');
                            logEntry.className = 'log-entry';
                            if (log.startsWith('ERROR:')) {
                                logEntry.className += ' error';
                            } else if (log.includes('complete') || log.includes('Success')) {
                                logEntry.className += ' success';
                            }
                            logEntry.textContent = '→ ' + log;
                            logsBox.appendChild(logEntry);
                        });
                        logsBox.scrollTop = logsBox.scrollHeight;
                    }
                    
                    if (data.success) {
                        progressBar.style.width = '100%';
                        progressBar.innerHTML = '100%';
                        progressText.textContent = 'Backup completed successfully!';
                        
                        currentBackupFile = data.filename;
                        
                        let stats = '';
                        if (data.tables) stats += `${data.tables} tables, `;
                        if (data.rows) stats += `${data.rows} rows, `;
                        if (data.files) stats += `${data.files} files, `;
                        if (data.compression) stats += `${data.compression}% compressed`;
                        
                        statusMessage.className = 'status-message success';
                        statusMessage.innerHTML = `
                            <strong>✅ Success!</strong> Backup created: ${data.filename} (${data.size})<br>
                            ${stats ? '<small>' + stats + '</small><br>' : ''}
                            <a href="?action=download&file=${encodeURIComponent(data.filename)}&csrf=${encodeURIComponent(csrfToken)}" 
                               style="color: #155724; text-decoration: underline; font-weight: 600; margin-top: 10px; display: inline-block;">
                                📥 Download Now
                            </a>
                        `;
                        statusMessage.style.display = 'block';
                        
                        // Reload page after 4 seconds to show new backup
                        setTimeout(() => {
                            window.location.reload();
                        }, 4000);
                    } else {
                        progressBar.style.width = '100%';
                        progressBar.innerHTML = 'Error';
                        progressBar.style.background = '#dc3545';
                        progressText.textContent = 'Backup failed!';
                        
                        statusMessage.className = 'status-message error';
                        statusMessage.innerHTML = `<strong>❌ Error:</strong> ${data.error}`;
                        statusMessage.style.display = 'block';
                    }
                    
                    // Re-enable buttons
                    buttons.forEach(btn => btn.disabled = false);
                })
                .catch(error => {
                    clearInterval(progressInterval);
                    
                    progressBar.style.width = '100%';
                    progressBar.innerHTML = 'Error';
                    progressBar.style.background = '#dc3545';
                    progressText.textContent = 'Backup failed!';
                    
                    statusMessage.className = 'status-message error';
                    statusMessage.innerHTML = `<strong>❌ Error:</strong> ${error.message}`;
                    statusMessage.style.display = 'block';
                    
                    if (error.data && Array.isArray(error.data.logs)) {
                        error.data.logs.forEach(l => {
                            const logEntry = document.createElement('div');
                            logEntry.className = 'log-entry error';
                            logEntry.textContent = String(l);
                            logsBox.appendChild(logEntry);
                        });
                    }

                    const logEntry = document.createElement('div');
                    logEntry.className = 'log-entry error';
                    logEntry.textContent = '→ ERROR: ' + error.message;
                    logsBox.appendChild(logEntry);
                    
                    buttons.forEach(btn => btn.disabled = false);
                });
        }

        function pollJobStatus(jobId, progressInterval, progressBar, progressText, statusMessage, logsBox, buttons) {
            const poll = () => {
                fetch('?action=job_status&id=' + encodeURIComponent(jobId) + '&csrf=' + encodeURIComponent(csrfToken))
                    .then(r => r.json())
                    .then(data => {
                        if (!data || !data.success || !data.job) {
                            throw new Error((data && data.error) ? data.error : 'Job status error');
                        }

                        if (Array.isArray(data.logs)) {
                            logsBox.innerHTML = '';
                            data.logs.forEach(log => {
                                const logEntry = document.createElement('div');
                                logEntry.className = 'log-entry';
                                if (String(log).includes('ERROR:')) {
                                    logEntry.className += ' error';
                                } else if (String(log).toLowerCase().includes('completed') || String(log).toLowerCase().includes('success')) {
                                    logEntry.className += ' success';
                                }
                                logEntry.textContent = String(log);
                                logsBox.appendChild(logEntry);
                            });
                            logsBox.scrollTop = logsBox.scrollHeight;
                        }

                        const job = data.job;
                        const prog = job.progress || {};
                        let extra = [];
                        if (prog.files) extra.push(`${prog.files} files`);
                        if (prog.tables) extra.push(`${prog.tables} tables`);
                        if (prog.rows) extra.push(`${prog.rows} rows`);
                        if (extra.length) {
                            progressText.textContent = 'Running... ' + extra.join(', ');
                        }

                        if (job.status === 'complete' && job.result) {
                            clearInterval(progressInterval);
                            clearInterval(timer);
                            // Reuse existing completion handler by faking the "data" shape
                            const result = job.result;
                            if (result.success) {
                                progressBar.style.width = '100%';
                                progressBar.innerHTML = '100%';
                                progressText.textContent = 'Backup completed successfully!';

                                let stats = '';
                                if (result.tables) stats += `${result.tables} tables, `;
                                if (result.rows) stats += `${result.rows} rows, `;
                                if (result.files) stats += `${result.files} files, `;
                                if (result.compression) stats += `${result.compression}% compressed`;

                                statusMessage.className = 'status-message success';
                                statusMessage.innerHTML = `
                                    <strong>Success!</strong> Backup created: ${result.filename} (${result.size})<br>
                                    ${stats ? '<small>' + stats + '</small><br>' : ''}
                                    <a href="?action=download&file=${encodeURIComponent(result.filename)}&csrf=${encodeURIComponent(csrfToken)}"
                                       style="color: #155724; text-decoration: underline; font-weight: 600; margin-top: 10px; display: inline-block;">
                                        Download Now
                                    </a>
                                `;
                                statusMessage.style.display = 'block';

                                setTimeout(() => window.location.reload(), 4000);
                            } else {
                                progressBar.style.width = '100%';
                                progressBar.innerHTML = 'Error';
                                progressBar.style.background = '#dc3545';
                                progressText.textContent = 'Backup failed!';
                                statusMessage.className = 'status-message error';
                                statusMessage.innerHTML = `<strong>Error:</strong> ${result.error || 'Job failed'}`;
                                statusMessage.style.display = 'block';
                                buttons.forEach(btn => btn.disabled = false);
                            }
                        } else if (job.status === 'error') {
                            clearInterval(progressInterval);
                            clearInterval(timer);
                            progressBar.style.width = '100%';
                            progressBar.innerHTML = 'Error';
                            progressBar.style.background = '#dc3545';
                            progressText.textContent = 'Backup failed!';
                            statusMessage.className = 'status-message error';
                            statusMessage.innerHTML = `<strong>Error:</strong> ${job.error || 'Job failed'}`;
                            statusMessage.style.display = 'block';
                            buttons.forEach(btn => btn.disabled = false);
                        }
                    })
                    .catch(err => {
                        clearInterval(progressInterval);
                        clearInterval(timer);
                        progressBar.style.width = '100%';
                        progressBar.innerHTML = 'Error';
                        progressBar.style.background = '#dc3545';
                        progressText.textContent = 'Backup failed!';
                        statusMessage.className = 'status-message error';
                        statusMessage.innerHTML = `<strong>Error:</strong> ${err.message}`;
                        statusMessage.style.display = 'block';
                        buttons.forEach(btn => btn.disabled = false);
                    });
            };

            const timer = setInterval(poll, 2000);
            poll();
        }

        function pollChunkedJob(jobId, progressInterval, progressBar, progressText, statusMessage, logsBox, buttons) {
            let stopped = false;
            let inFlight = false;

            const step = () => {
                if (stopped || inFlight) return;
                inFlight = true;

                fetch('?action=job_step&id=' + encodeURIComponent(jobId) + '&csrf=' + encodeURIComponent(csrfToken))
                    .then(r => r.json())
                    .then(data => {
                        if (!data || !data.job) {
                            throw new Error((data && data.error) ? data.error : 'Job step error');
                        }

                        if (data.job && data.job.busy) {
                            progressText.textContent = 'Running... (waiting for worker)';
                            return;
                        }

                        if (Array.isArray(data.logs)) {
                            logsBox.innerHTML = '';
                            data.logs.forEach(log => {
                                const logEntry = document.createElement('div');
                                logEntry.className = 'log-entry';
                                if (String(log).includes('ERROR:')) {
                                    logEntry.className += ' error';
                                } else if (String(log).toLowerCase().includes('complete') || String(log).toLowerCase().includes('success')) {
                                    logEntry.className += ' success';
                                }
                                logEntry.textContent = String(log);
                                logsBox.appendChild(logEntry);
                            });
                            logsBox.scrollTop = logsBox.scrollHeight;
                        }

                        const job = data.job;
                        const prog = job.progress || {};
                        const totalFiles = job.work && job.work.total_files ? Number(job.work.total_files) : 0;
                        if (prog.files && totalFiles) {
                            const pct = Math.min(99, Math.floor((Number(prog.files) / totalFiles) * 100));
                            progressBar.style.width = pct + '%';
                            progressBar.innerHTML = '<span class="spinner"></span>';
                            progressText.textContent = `Running... ${prog.files}/${totalFiles} files`;
                        } else if (prog.files) {
                            progressText.textContent = `Running... ${prog.files} files`;
                        } else {
                            progressText.textContent = 'Running...';
                        }

                        if (job.status === 'complete' && job.result) {
                            clearInterval(progressInterval);
                            stopped = true;
                            const result = job.result;
                            progressBar.style.width = '100%';
                            progressBar.innerHTML = '100%';
                            progressText.textContent = 'Backup completed successfully!';

                            let stats = '';
                            if (result.tables) stats += `${result.tables} tables, `;
                            if (result.rows) stats += `${result.rows} rows, `;
                            if (result.files) stats += `${result.files} files, `;

                            statusMessage.className = 'status-message success';
                            statusMessage.innerHTML = `
                                <strong>Success!</strong> Backup created: ${result.filename} (${result.size})<br>
                                ${stats ? '<small>' + stats + '</small><br>' : ''}
                                <a href="?action=download&file=${encodeURIComponent(result.filename)}&csrf=${encodeURIComponent(csrfToken)}"
                                   style="color: #155724; text-decoration: underline; font-weight: 600; margin-top: 10px; display: inline-block;">
                                    Download Now
                                </a>
                            `;
                            statusMessage.style.display = 'block';
                            setTimeout(() => window.location.reload(), 4000);
                        } else if (job.status === 'error') {
                            clearInterval(progressInterval);
                            stopped = true;
                            progressBar.style.width = '100%';
                            progressBar.innerHTML = 'Error';
                            progressBar.style.background = '#dc3545';
                            progressText.textContent = 'Backup failed!';
                            statusMessage.className = 'status-message error';
                            statusMessage.innerHTML = `<strong>Error:</strong> ${job.error || 'Job failed'}`;
                            statusMessage.style.display = 'block';
                            buttons.forEach(btn => btn.disabled = false);
                        }
                    })
                    .catch(err => {
                        clearInterval(progressInterval);
                        stopped = true;
                        progressBar.style.width = '100%';
                        progressBar.innerHTML = 'Error';
                        progressBar.style.background = '#dc3545';
                        progressText.textContent = 'Backup failed!';
                        statusMessage.className = 'status-message error';
                        statusMessage.innerHTML = `<strong>Error:</strong> ${err.message}`;
                        statusMessage.style.display = 'block';
                        buttons.forEach(btn => btn.disabled = false);
                    })
                    .finally(() => {
                        inFlight = false;
                        if (!stopped) {
                            setTimeout(step, 750);
                        }
                    });
            };

            step();
        }
    </script>
</body>
</html>
