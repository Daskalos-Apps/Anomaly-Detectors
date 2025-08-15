#!/usr/bin/env python3
"""
HTTP Feature Extractor
Extracts HTTP-specific features from Apache/Nginx logs for enhanced detection
"""

import re
import math
import numpy as np
import pandas as pd
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
import logging


class HTTPFeatureExtractor:
    """
    Extracts HTTP path analysis features for anomaly detection
    """
    
    def __init__(self):
        """Initialize the HTTP feature extractor"""
        self.logger = logging.getLogger('HTTPFeatureExtractor')
        
        # Feature names for consistency
        self.feature_names = [
            'request_complexity',
            'response_pattern',
            'path_entropy',
            'encoding_indicator',
            'scan_pattern',
            'brute_force_pattern',
            'injection_pattern',
            'xss_pattern',
            'automated_pattern',
            'suspicious_timing'
        ]
        
        # Apache log regex pattern
        self.log_pattern = re.compile(
            r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] '
            r'"(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}|-) (\d+|-)\s?'
            r'"?([^"]*)"?\s?"?([^"]*)"?'
        )
    
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """
        Parse Apache/Nginx log line
        
        Args:
            line: Raw log line
            
        Returns:
            Parsed log entry or None
        """
        match = self.log_pattern.match(line)
        if not match:
            return None
        
        groups = match.groups()
        
        return {
            'ip': groups[0],
            'timestamp': groups[1],
            'method': groups[2],
            'path': groups[3] if groups[3] else '',
            'protocol': groups[4] if groups[4] else '',
            'status': int(groups[5]) if groups[5] != '-' else 0,
            'size': int(groups[6]) if groups[6] != '-' else 0,
            'referer': groups[7] if len(groups) > 7 else '',
            'user_agent': groups[8] if len(groups) > 8 else ''
        }
    
    def calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            string: Input string
            
        Returns:
            Entropy value
        """
        if not string or len(string) < 2:
            return 0.0
        
        # Calculate character frequency
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        
        # Calculate entropy
        entropy = -sum(p * math.log(p, 2) for p in prob if p > 0)
        
        return entropy
    
    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract HTTP features from log data
        
        Args:
            data: DataFrame with parsed log entries
            
        Returns:
            DataFrame with HTTP features
        """
        features = pd.DataFrame()
        
        # 1. Request Complexity
        # Measures the complexity of HTTP requests
        if 'path' in data.columns and 'status' in data.columns:
            features['request_complexity'] = (
                data['path'].str.len() * 
                data['path'].str.count('[^a-zA-Z0-9/]') / 
                (data['status'] + 1)
            ).fillna(0)
        else:
            features['request_complexity'] = 0
        
        # 2. Response Pattern
        # Analyzes server response patterns
        if 'size' in data.columns and 'status' in data.columns:
            features['response_pattern'] = (
                data['size'] / (data['status'] + 1)
            ).fillna(0)
        else:
            features['response_pattern'] = 0
        
        # 3. Path Entropy
        # Detects randomized/obfuscated paths
        if 'path' in data.columns:
            features['path_entropy'] = data['path'].apply(self.calculate_entropy)
        else:
            features['path_entropy'] = 0
        
        # 4. URL Encoding Indicator
        # Detects encoded payloads
        if 'path' in data.columns:
            features['encoding_indicator'] = (
                data['path'].str.contains('%[0-9a-fA-F]{2}', regex=True, na=False)
            ).astype(int)
        else:
            features['encoding_indicator'] = 0
        
        # 5. Scanning Pattern
        # Identifies vulnerability scanning
        if 'path' in data.columns and 'status' in data.columns:
            features['scan_pattern'] = (
                (data['status'] == 404) & 
                (data['path'].str.len() < 50)
            ).astype(int)
        else:
            features['scan_pattern'] = 0
        
        # 6. Brute Force Pattern
        # Detects repetitive login attempts
        if 'path' in data.columns:
            login_paths = ['login', 'signin', 'auth', 'admin', 'wp-login']
            pattern = '|'.join(login_paths)
            features['brute_force_pattern'] = (
                data['path'].str.contains(pattern, case=False, na=False)
            ).astype(int)
        else:
            features['brute_force_pattern'] = 0
        
        # 7. SQL Injection Pattern
        # Identifies potential SQL injection
        if 'path' in data.columns:
            sql_patterns = ['union', 'select', 'insert', 'update', 'delete', 'drop']
            pattern = '|'.join(sql_patterns)
            features['injection_pattern'] = (
                data['path'].str.contains(pattern, case=False, na=False) |
                data['path'].str.contains("'", na=False) |
                data['path'].str.contains('--', na=False)
            ).astype(int)
        else:
            features['injection_pattern'] = 0
        
        # 8. XSS Pattern
        # Detects Cross-Site Scripting attempts
        if 'path' in data.columns:
            xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'alert(']
            pattern = '|'.join(xss_patterns)
            features['xss_pattern'] = (
                data['path'].str.contains(pattern, case=False, na=False)
            ).astype(int)
        else:
            features['xss_pattern'] = 0
        
        # 9. Automated Tool Detection
        # Identifies automated security tools
        if 'user_agent' in data.columns:
            bot_patterns = ['bot', 'crawler', 'spider', 'scan', 'nikto', 'sqlmap']
            pattern = '|'.join(bot_patterns)
            features['automated_pattern'] = (
                data['user_agent'].str.contains(pattern, case=False, na=False)
            ).astype(int)
        else:
            features['automated_pattern'] = 0
        
        # 10. Suspicious Timing
        # Flags abnormal request timing (placeholder for actual timing analysis)
        if 'status' in data.columns:
            features['suspicious_timing'] = (
                (data['status'] >= 500) | (data['status'] == 403)
            ).astype(int)
        else:
            features['suspicious_timing'] = 0
        
        # Ensure all features are numeric
        for col in features.columns:
            features[col] = pd.to_numeric(features[col], errors='coerce').fillna(0)
        
        return features
    
    def get_feature_names(self) -> List[str]:
        """
        Get list of feature names
        
        Returns:
            List of feature names
        """
        return self.feature_names
    
    def extract_advanced_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract advanced HTTP features for improved detection
        
        Args:
            data: DataFrame with parsed log entries
            
        Returns:
            DataFrame with advanced features
        """
        features = self.extract_features(data)
        
        # Additional advanced features
        if 'path' in data.columns:
            # Path depth
            features['path_depth'] = data['path'].str.count('/')
            
            # Query string analysis
            features['has_query'] = data['path'].str.contains('\\?', na=False).astype(int)
            features['query_params'] = data['path'].str.count('&') + features['has_query']
            
            # Special characters ratio
            features['special_char_ratio'] = (
                data['path'].str.count('[^a-zA-Z0-9/]') / 
                data['path'].str.len()
            ).fillna(0)
            
            # File extension detection
            features['has_extension'] = data['path'].str.contains('\\.[a-zA-Z]{2,4}$', 
                                                                  regex=True, na=False).astype(int)
            
            # Suspicious extensions
            suspicious_ext = ['php', 'asp', 'jsp', 'cgi', 'pl', 'py', 'rb', 'sh']
            ext_pattern = '\\.(' + '|'.join(suspicious_ext) + ')$'
            features['suspicious_extension'] = data['path'].str.contains(
                ext_pattern, regex=True, case=False, na=False
            ).astype(int)
        
        # User agent analysis
        if 'user_agent' in data.columns:
            # User agent length
            features['ua_length'] = data['user_agent'].str.len().fillna(0)
            
            # Empty user agent
            features['ua_empty'] = (
                data['user_agent'].isna() | 
                (data['user_agent'] == '') | 
                (data['user_agent'] == '-')
            ).astype(int)
            
            # Known browsers
            browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera']
            browser_pattern = '|'.join(browsers)
            features['known_browser'] = data['user_agent'].str.contains(
                browser_pattern, case=False, na=False
            ).astype(int)
        
        # Response analysis
        if 'status' in data.columns:
            # Error categories
            features['client_error'] = ((data['status'] >= 400) & 
                                       (data['status'] < 500)).astype(int)
            features['server_error'] = (data['status'] >= 500).astype(int)
            features['redirect'] = ((data['status'] >= 300) & 
                                   (data['status'] < 400)).astype(int)
        
        return features
    
    def detect_attack_patterns(self, path: str) -> Dict[str, bool]:
        """
        Detect specific attack patterns in a path
        
        Args:
            path: HTTP request path
            
        Returns:
            Dictionary of detected attack patterns
        """
        patterns = {
            'sql_injection': False,
            'xss': False,
            'path_traversal': False,
            'command_injection': False,
            'file_inclusion': False,
            'directory_listing': False
        }
        
        if not path:
            return patterns
        
        path_lower = path.lower()
        
        # SQL Injection
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 
                       'exec', 'execute', 'script', 'javascript']
        patterns['sql_injection'] = any(kw in path_lower for kw in sql_keywords) or \
                                   bool(re.search(r"'|\"|;|--|\*/|/\*", path))
        
        # XSS
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 
                       'prompt(', 'confirm(']
        patterns['xss'] = any(xp in path_lower for xp in xss_patterns)
        
        # Path Traversal
        patterns['path_traversal'] = bool(re.search(r'\.\./|\.\.\\|%2e%2e', path_lower))
        
        # Command Injection
        cmd_chars = [';', '|', '&', '$', '`', '\n', '\r']
        patterns['command_injection'] = any(char in path for char in cmd_chars)
        
        # File Inclusion
        inclusion_patterns = ['/etc/passwd', '/windows/system32', '.php', '.asp', '.jsp']
        patterns['file_inclusion'] = any(ip in path_lower for ip in inclusion_patterns)
        
        # Directory Listing
        dir_patterns = ['/admin', '/backup', '/config', '/tmp', '/temp', '/.git', '/.env']
        patterns['directory_listing'] = any(dp in path_lower for dp in dir_patterns)
        
        return patterns


def main():
    """Test the HTTP feature extractor"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python http_feature_extractor.py <log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    # Initialize extractor
    extractor = HTTPFeatureExtractor()
    
    # Read and parse logs
    logs = []
    with open(log_file, 'r') as f:
        for line in f:
            parsed = extractor.parse_log_line(line.strip())
            if parsed:
                logs.append(parsed)
    
    # Convert to DataFrame
    df = pd.DataFrame(logs)
    
    # Extract features
    features = extractor.extract_advanced_features(df)
    
    # Print statistics
    print(f"Processed {len(df)} log entries")
    print(f"Extracted {len(features.columns)} features")
    print("\nFeature statistics:")
    print(features.describe())
    
    # Detect attacks
    print("\nPotential attacks detected:")
    attack_cols = ['injection_pattern', 'xss_pattern', 'scan_pattern', 
                  'brute_force_pattern', 'automated_pattern']
    for col in attack_cols:
        if col in features.columns:
            count = features[col].sum()
            if count > 0:
                print(f"  {col}: {count} instances")


if __name__ == "__main__":
    main()