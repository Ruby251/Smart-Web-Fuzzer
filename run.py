#!/usr/bin/env python3
import sys
import signal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from src.gui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Smart Fuzzer")
    app.setOrganizationName("Security Tools")
    
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()