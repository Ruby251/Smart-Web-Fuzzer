import hashlib
import difflib
from typing import Dict, Any, List, Tuple
from collections import Counter
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

class HeuristicAnalyzer:
    def __init__(self):
        self.baseline_response = None
        self.response_clusters = {}
        
    def compute_signature(self, response: Dict[str, Any]) -> str:
        content = response.get('text', '')
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        status = response.get('status', 0)
        length = len(content)
        
        signature_data = f"{status}|{length}|{content_hash[:16]}"
        return hashlib.md5(signature_data.encode()).hexdigest()
    
    def compute_similarity(self, resp1: Dict[str, Any], resp2: Dict[str, Any]) -> float:
        content1 = resp1.get('text', '')
        content2 = resp2.get('text', '')
        
        similarity = difflib.SequenceMatcher(None, content1, content2).ratio()
        return similarity
    
    def detect_anomaly(self, responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not responses:
            return []
            
        features = []
        for resp in responses:
            content = resp.get('text', '')
            features.append([
                len(content),
                resp.get('status', 0),
                resp.get('response_time', 0),
                content.count('error'),
                content.count('exception'),
                content.count('warning')
            ])
            
        if len(features) < 3:
            return []
            
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        clustering = DBSCAN(eps=0.5, min_samples=2)
        labels = clustering.fit_predict(features_scaled)
        
        anomalies = []
        for i, label in enumerate(labels):
            if label == -1:
                anomalies.append(responses[i])
                
        return anomalies
    
    def is_sql_injection(self, baseline: Dict[str, Any], test_response: Dict[str, Any]) -> Tuple[bool, float]:
        indicators = []
        confidence = 0.0
        
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql error',
            'unclosed quotation mark', 'microsoft ole db', 'odbc driver',
            'division by zero', 'sqlstate', 'syntax error'
        ]
        
        content_lower = test_response.get('text', '').lower()
        
        for error in sql_errors:
            if error in content_lower:
                indicators.append(('error_pattern', 0.9))
                break
                
        if baseline and test_response:
            similarity = self.compute_similarity(baseline, test_response)
            status_changed = baseline.get('status') != test_response.get('status')
            length_ratio = len(test_response.get('text', '')) / max(1, len(baseline.get('text', '')))
            
            if similarity < 0.3 and length_ratio > 2:
                indicators.append(('content_anomaly', 0.8))
            if status_changed:
                indicators.append(('status_change', 0.6))
                
        if indicators:
            confidence = sum(w for _, w in indicators) / len(indicators)
            confidence = min(0.95, confidence)
            
        return len(indicators) > 0, confidence
    
    def is_xss(self, response: Dict[str, Any], payload: str) -> Tuple[bool, float]:
        indicators = []
        content = response.get('text', '')
        
        if payload in content and not self.is_html_encoded(content, payload):
            indicators.append(('payload_reflected', 0.95))
            
        script_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
        for pattern in script_patterns:
            if pattern in content:
                indicators.append(('script_context', 0.7))
                break
                
        confidence = sum(0.8 for _ in indicators) / max(1, len(indicators))
        return len(indicators) > 0, confidence
    
    def is_lfi(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        indicators = []
        content = response.get('text', '')
        
        lfi_indicators = [
            ('root:', 0.9),
            ('bin/bash', 0.8),
            ('etc/passwd', 0.95),
            ('windows\\system32', 0.9),
            ('boot.ini', 0.85),
            ('[extensions]', 0.7)
        ]
        
        for indicator, weight in lfi_indicators:
            if indicator in content:
                indicators.append(weight)
                
        if indicators:
            confidence = max(indicators)
            return True, confidence
            
        return False, 0.0
        
    def is_html_encoded(self, content: str, payload: str) -> bool:
        import html
        decoded = html.unescape(content)
        return payload not in decoded