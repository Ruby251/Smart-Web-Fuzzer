from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QGroupBox, QLabel, QLineEdit, 
    QSpinBox, QPushButton, QTextEdit, QProgressBar,
    QSplitter, QTableWidget, QHeaderView, QCheckBox,
    QComboBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter
from src.core.fuzzer import FuzzerEngine
from src.gui.results_table import ResultsTable
from src.gui.payload_editor import PayloadEditor

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
        engine = FuzzerEngine(
            self.target_url,
            self.parameters,
            self.payload_type,
            self.threads,
            self.timeout,
            self.delay
        )
        
        engine.log_signal = self.log_message
        engine.result_signal = self.result_found
        engine.progress_signal = self.progress
        
        engine.run()
        self.scan_finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Smart Fuzzer - Web Security Scanner")
        self.setMinimumSize(1200, 800)
        self.scan_thread = None
        self.setup_ui()
        self.apply_styles()
        
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Target configuration group
        target_group = self.create_target_group()
        main_layout.addWidget(target_group)
        
        # Parameters group
        params_group = self.create_parameters_group()
        main_layout.addWidget(params_group)
        
        # Splitter for results and logs
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Results table
        self.results_table = ResultsTable()
        splitter.addWidget(self.results_table)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)
        splitter.addWidget(self.log_output)
        
        splitter.setSizes([500, 200])
        main_layout.addWidget(splitter)
        
        # Control panel
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
        
        main_layout.addLayout(control_layout)
        
    def create_target_group(self):
        group = QGroupBox("Target Configuration")
        layout = QGridLayout()
        
        layout.addWidget(QLabel("Target URL:"), 0, 0)
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("https://example.com/page.php")
        layout.addWidget(self.target_url, 0, 1)
        
        layout.addWidget(QLabel("Method:"), 0, 2)
        self.method = QComboBox()
        self.method.addItems(["GET", "POST", "PUT", "DELETE"])
        layout.addWidget(self.method, 0, 3)
        
        layout.addWidget(QLabel("Headers:"), 1, 0)
        self.headers = QTextEdit()
        self.headers.setMaximumHeight(80)
        self.headers.setPlaceholderText('{"User-Agent": "SmartFuzzer/1.0", "Accept": "application/json"}')
        layout.addWidget(self.headers, 1, 1, 1, 3)
        
        group.setLayout(layout)
        return group
        
    def create_parameters_group(self):
        group = QGroupBox("Fuzzing Configuration")
        layout = QGridLayout()
        
        layout.addWidget(QLabel("Parameters:"), 0, 0)
        self.parameters = QTextEdit()
        self.parameters.setMaximumHeight(80)
        self.parameters.setPlaceholderText('["id", "page", "file", "redirect"]')
        layout.addWidget(self.parameters, 0, 1)
        
        layout.addWidget(QLabel("Payload Type:"), 0, 2)
        self.payload_type = QComboBox()
        self.payload_type.addItems(["SQL Injection", "XSS", "LFI", "All"])
        layout.addWidget(self.payload_type, 0, 3)
        
        layout.addWidget(QLabel("Threads:"), 1, 0)
        self.threads = QSpinBox()
        self.threads.setRange(1, 200)
        self.threads.setValue(50)
        layout.addWidget(self.threads, 1, 1)
        
        layout.addWidget(QLabel("Timeout (s):"), 1, 2)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 60)
        self.timeout.setValue(10)
        layout.addWidget(self.timeout, 1, 3)
        
        layout.addWidget(QLabel("Delay (ms):"), 2, 0)
        self.delay = QSpinBox()
        self.delay.setRange(0, 1000)
        self.delay.setValue(50)
        layout.addWidget(self.delay, 2, 1)
        
        layout.addWidget(QLabel("Custom Payloads:"), 2, 2)
        self.custom_payloads_btn = QPushButton("Load File")
        self.custom_payloads_btn.clicked.connect(self.load_custom_payloads)
        layout.addWidget(self.custom_payloads_btn, 2, 3)
        
        group.setLayout(layout)
        return group
        
    def load_custom_payloads(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Payload File", "", "Text Files (*.txt);;JSON Files (*.json)"
        )
        if file_path:
            self.custom_payloads_path = file_path
            self.log_message(f"Custom payloads loaded: {file_path}")
            
    def start_scan(self):
        target = self.target_url.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Target URL is required")
            return
            
        try:
            import json
            parameters = json.loads(self.parameters.toPlainText())
        except:
            parameters = []
            
        self.scan_thread = ScanThread(
            target,
            parameters,
            self.payload_type.currentText(),
            self.threads.value(),
            self.timeout.value(),
            self.delay.value()
        )
        
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.result_found.connect(self.results_table.add_result)
        self.scan_thread.log_message.connect(self.log_message)
        self.scan_thread.scan_finished.connect(self.scan_finished)
        
        self.scan_thread.start()
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_table.clear()
        self.log_output.clear()
        
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_finished()
            
    def scan_finished(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_message("Scan completed")
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def log_message(self, message):
        self.log_output.append(message)
        
    def apply_styles(self):
        style = """
        QGroupBox {
            font-weight: bold;
            border: 1px solid #3c3c3c;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QPushButton {
            background-color: #0d7377;
            border: none;
            border-radius: 4px;
            padding: 8px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #14a085;
        }
        QPushButton:disabled {
            background-color: #323232;
        }
        QTextEdit, QLineEdit {
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            padding: 4px;
            background-color: #2b2b2b;
        }
        QTableWidget {
            gridline-color: #3c3c3c;
        }
        QProgressBar {
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #0d7377;
            border-radius: 3px;
        }
        """
        self.setStyleSheet(style)