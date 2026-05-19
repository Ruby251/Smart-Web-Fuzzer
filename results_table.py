from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush

class ResultsTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            "Type", "Parameter", "Payload", "Status", "Response Time (ms)", "Confidence"
        ])
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.setAlternatingRowColors(True)
        
    def add_result(self, result: dict):
        row = self.rowCount()
        self.insertRow(row)
        
        vuln_type = QTableWidgetItem(result.get('type', ''))
        param = QTableWidgetItem(result.get('param', ''))
        payload = QTableWidgetItem(result.get('payload', '')[:100])
        status = QTableWidgetItem(str(result.get('status', 0)))
        response_time = QTableWidgetItem(f"{result.get('response_time', 0):.2f}")
        confidence = QTableWidgetItem(f"{result.get('confidence', 0)*100:.1f}%")
        
        if result.get('confidence', 0) > 0.8:
            for item in [vuln_type, param, payload, status, response_time, confidence]:
                item.setBackground(QBrush(QColor(139, 0, 0, 100)))
                
        self.setItem(row, 0, vuln_type)
        self.setItem(row, 1, param)
        self.setItem(row, 2, payload)
        self.setItem(row, 3, status)
        self.setItem(row, 4, response_time)
        self.setItem(row, 5, confidence)
        
        self.scrollToBottom()