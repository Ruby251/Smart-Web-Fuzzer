#!/usr/bin/env python3
import sys
import asyncio
import json
import hashlib
import difflib
import time
from collections import deque
from typing import Dict, Any, List, Tuple
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QLineEdit, QSpinBox, QPushButton, QTextEdit,
    QProgressBar, QSplitter, QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush
import aiohttp
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler


class RateLimiter:
    def __init__(self, max_requests: int = 100, time_window: float = 1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()

    async def acquire(self):
        now = time.time()
        while self.requests and self.requests[0] < now - self.time_window:
            self.requests.popleft()
        if len(self.requests) >= self.max_requests:
            sleep_time = self.time_window - (now - self.requests[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        self.requests.append(now)


class HttpEngine:
    def __init__(self, timeout: int = 10, max_retries: int = 3, rate_limit: int = 50):
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limiter = RateLimiter(max_requests=rate_limit)
        self.session = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=200, ttl_dns_cache=300, ssl=False)
        self.session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def request(self, url: str, method: str = 'GET',
                     params: Dict = None, headers: Dict = None,
                     data: Dict = None) -> Dict[str, Any]:
        await self.rate_limiter.acquire()
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                async with self.session.request(
                    method=method, url=url, params=params,
                    headers=headers or {}, data=data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=True
                ) as response:
                    response_time = (time.time() - start_time) * 1000
                    text = await response.text()
                    return {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'text': text,
                        'response_time': response_time,
                        'url': str(response.url)
                    }
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return {'error': 'timeout', 'status': 0}
                await asyncio.sleep(0.5 * (2 ** attempt))
            except Exception:
                if attempt == self.max_retries - 1:
                    return {'error': 'exception', 'status': 0}
                await asyncio.sleep(0.5)
        return {'error': 'max_retries_exceeded', 'status': 0}


class HeuristicAnalyzer:
    def __init__(self):
        self.baseline_response = None

    def compute_similarity(self, resp1: Dict[str, Any], resp2: Dict[str, Any]) -> float:
        content1 = resp1.get('text', '')
        content2 = resp2.get('text', '')
        return difflib.SequenceMatcher(None, content1, content2).ratio()

    def detect_anomaly(self, responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if len(responses) < 3:
            return []
        features = []
        for resp in responses:
            content = resp.get('text', '')
            features.append([
                len(content), resp.get('status', 0), resp.get('response_time', 0),
                content.count('error'), content.count('exception')
            ])
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        clustering = DBSCAN(eps=0.5, min_samples=2)
        labels = clustering.fit_predict(features_scaled)
        return [responses[i] for i, label in enumerate(labels) if label == -1]

    def is_sql_injection(self, baseline: Dict[str, Any], test_response: Dict[str, Any]) -> Tuple[bool, float]:
        indicators = []
        content_lower = test_response.get('text', '').lower()
        sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql error',
                      'unclosed quotation mark', 'odbc driver', 'sqlstate']
        for error in sql_errors:
            if error in content_lower:
                indicators.append(('error_pattern', 0.9))
                break
        if baseline and test_response:
            similarity = self.compute_similarity(baseline, test_response)
            if similarity < 0.3:
                indicators.append(('content_anomaly', 0.8))
        if indicators:
            confidence = sum(w for _, w in indicators) / len(indicators)
            return True, min(0.95, confidence)
        return False, 0.0

    def is_xss(self, response: Dict[str, Any], payload: str) -> Tuple[bool, float]:
        content = response.get('text', '')
        if payload in content:
            return True, 0.9
        script_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
        for pattern in script_patterns:
            if pattern in content:
                return True, 0.7
        return False, 0.0

    def is_lfi(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        content = response.get('text', '')
        lfi_indicators = [('root:', 0.9), ('bin/bash', 0.8), ('etc/passwd', 0.95),
                          ('windows\\system32', 0.9), ('boot.ini', 0.85)]
        for indicator, weight in lfi_indicators:
            if indicator in content:
                return True, weight
        return False, 0.0


class ScanThread(QThread):
    progress = pyqtSignal(int)
    result_found = pyqtSignal(dict)
    scan_finished = pyqtSignal()
    log_message = pyqtSignal(str)

    def __init__(self, target_url, parameters, payload_type, threads, timeout, delay):
        super().__init__()
        self.target_url = target_url
        self.parameters = parameters
        self.payload_type = payload_type
        self.threads = threads
        self.timeout = timeout
        self.delay = delay

    def run(self):
        asyncio.run(self._async_run())

    async def _async_run(self):
        self.log_message.emit("Initializing fuzzing engine")
        payloads = self.load_payloads()
        self.log_message.emit(f"Loaded {len(payloads)} payloads")

        async with HttpEngine(timeout=self.timeout) as engine:
            baseline = await engine.request(self.target_url)
            self.log_message.emit("Baseline response captured")

            total_tests = len(self.parameters) * len(payloads)
            completed = 0
            analyzer = HeuristicAnalyzer()

            for param in self.parameters:
                for payload in payloads:
                    params = {param: payload}
                    response = await engine.request(self.target_url, params=params)

                    result = {
                        'param': param, 'payload': payload[:80],
                        'url': self.target_url, 'status': response.get('status', 0),
                        'response_time': response.get('response_time', 0),
                        'vulnerable': False, 'type': None, 'confidence': 0.0
                    }

                    if self.payload_type in ['SQL Injection', 'All']:
                        is_vuln, conf = analyzer.is_sql_injection(baseline, response)
                        if is_vuln:
                            result['vulnerable'], result['type'], result['confidence'] = True, 'SQL Injection', conf
                            self.result_found.emit(result)
                            self.log_message.emit(f"[VULN] SQL Injection on {param}")

                    if not result['vulnerable'] and self.payload_type in ['XSS', 'All']:
                        is_vuln, conf = analyzer.is_xss(response, payload)
                        if is_vuln:
                            result['vulnerable'], result['type'], result['confidence'] = True, 'XSS', conf
                            self.result_found.emit(result)
                            self.log_message.emit(f"[VULN] XSS on {param}")

                    if not result['vulnerable'] and self.payload_type in ['LFI', 'All']:
                        is_vuln, conf = analyzer.is_lfi(response)
                        if is_vuln:
                            result['vulnerable'], result['type'], result['confidence'] = True, 'LFI', conf
                            self.result_found.emit(result)
                            self.log_message.emit(f"[VULN] LFI on {param}")

                    completed += 1
                    self.progress.emit(int((completed / total_tests) * 100))
                    if self.delay > 0:
                        await asyncio.sleep(self.delay / 1000)

            self.log_message.emit("Scan completed")
            self.scan_finished.emit()

    def load_payloads(self) -> List[str]:
        sqli = ["'", "\"", "1' OR '1'='1", "1' AND '1'='1", "1' OR 1=1--",
                "1' UNION SELECT NULL--", "1' AND SLEEP(5)--", "1' OR 1=1#"]
        xss = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
               "javascript:alert(1)", "\"><script>alert(1)</script>"]
        lfi = ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
               "../../../../etc/passwd%00", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"]

        if self.payload_type == 'SQL Injection':
            return sqli
        elif self.payload_type == 'XSS':
            return xss
        elif self.payload_type == 'LFI':
            return lfi
        return sqli + xss + lfi


class ResultsTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Type", "Parameter", "Payload", "Status", "Confidence"])
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.setAlternatingRowColors(True)

    def add_result(self, result: dict):
        row = self.rowCount()
        self.insertRow(row)
        items = [
            QTableWidgetItem(result.get('type', '')),
            QTableWidgetItem(result.get('param', '')),
            QTableWidgetItem(result.get('payload', '')),
            QTableWidgetItem(str(result.get('status', 0))),
            QTableWidgetItem(f"{result.get('confidence', 0)*100:.1f}%")
        ]
        if result.get('confidence', 0) > 0.8:
            brush = QBrush(QColor(139, 0, 0, 100))
            for item in items:
                item.setBackground(brush)
        for col, item in enumerate(items):
            self.setItem(row, col, item)
        self.scrollToBottom()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Smart Fuzzer - Web Security Scanner")
        self.setMinimumSize(1200, 800)
        self.scan_thread = None
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        target_group = QGroupBox("Target Configuration")
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("URL:"))
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("https://example.com/page.php?id=1")
        target_layout.addWidget(self.target_url)
        target_layout.addWidget(QLabel("Method:"))
        self.method = QComboBox()
        self.method.addItems(["GET", "POST"])
        target_layout.addWidget(self.method)
        target_group.setLayout(target_layout)

        fuzz_group = QGroupBox("Fuzzing Configuration")
        fuzz_layout = QHBoxLayout()
        fuzz_layout.addWidget(QLabel("Parameters (comma separated):"))
        self.parameters = QLineEdit()
        self.parameters.setPlaceholderText("id,page,file,redirect")
        fuzz_layout.addWidget(self.parameters)
        fuzz_layout.addWidget(QLabel("Payload Type:"))
        self.payload_type = QComboBox()
        self.payload_type.addItems(["SQL Injection", "XSS", "LFI", "All"])
        fuzz_layout.addWidget(self.payload_type)
        fuzz_layout.addWidget(QLabel("Threads:"))
        self.threads = QSpinBox()
        self.threads.setRange(1, 100)
        self.threads.setValue(30)
        fuzz_layout.addWidget(self.threads)
        fuzz_layout.addWidget(QLabel("Timeout(s):"))
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 30)
        self.timeout.setValue(10)
        fuzz_layout.addWidget(self.timeout)
        fuzz_group.setLayout(fuzz_layout)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.results_table = ResultsTable()
        splitter.addWidget(self.results_table)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        splitter.addWidget(self.log_output)
        splitter.setSizes([500, 150])

        control_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setMinimumHeight(40)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.stop_button.setMinimumHeight(40)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(30)
        control_layout.addWidget(self.scan_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.progress_bar)

        layout.addWidget(target_group)
        layout.addWidget(fuzz_group)
        layout.addWidget(splitter)
        layout.addLayout(control_layout)

    def start_scan(self):
        target = self.target_url.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Target URL is required")
            return

        param_text = self.parameters.text().strip()
        parameters = [p.strip() for p in param_text.split(',') if p.strip()] if param_text else ['id']

        self.scan_thread = ScanThread(
            target, parameters, self.payload_type.currentText(),
            self.threads.value(), self.timeout.value(), 50
        )
        self.scan_thread.progress.connect(self.progress_bar.setValue)
        self.scan_thread.result_found.connect(self.results_table.add_result)
        self.scan_thread.log_message.connect(self.log_output.append)
        self.scan_thread.scan_finished.connect(self.scan_finished)
        self.scan_thread.start()

        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_table.setRowCount(0)
        self.log_output.clear()
        self.progress_bar.setValue(0)

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_finished()

    def scan_finished(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_output.append("Scan finished")

    def apply_styles(self):
        self.setStyleSheet("""
            QGroupBox { font-weight: bold; border: 1px solid #3c3c3c; border-radius: 5px;
                        margin-top: 10px; padding-top: 10px; }
            QPushButton { background-color: #0d7377; border: none; border-radius: 4px;
                         padding: 8px; font-weight: bold; color: white; }
            QPushButton:hover { background-color: #14a085; }
            QPushButton:disabled { background-color: #323232; }
            QLineEdit, QTextEdit { border: 1px solid #3c3c3c; border-radius: 4px;
                                  padding: 4px; background-color: #2b2b2b; color: white; }
            QTableWidget { gridline-color: #3c3c3c; }
            QProgressBar { border: 1px solid #3c3c3c; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background-color: #0d7377; border-radius: 3px; }
            QLabel { color: white; }
            QMainWindow { background-color: #1e1e1e; }
        """)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()