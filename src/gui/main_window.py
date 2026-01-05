import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QLabel,
    QGroupBox, QFileDialog, QProgressBar, QTabWidget, QTreeWidget, 
    QTreeWidgetItem, QHeaderView, QListWidget, QCheckBox, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.core.vhd_manager import EvidenceManager 

class AnalysisThread(QThread):
    progress = pyqtSignal(str)
    vhd_done = pyqtSignal(int)
    item_processed = pyqtSignal(dict) 
    finished = pyqtSignal(list)

    def __init__(self, vhd_paths, selected_artifacts):
        super().__init__()
        self.vhd_paths = vhd_paths
        self.selected_artifacts = selected_artifacts

    def run(self):
        results = []
        total_steps = len(self.vhd_paths) * len(self.selected_artifacts)
        current_step = 0

        for i, path in enumerate(self.vhd_paths):
            vhd_name = os.path.basename(path)
            manager = EvidenceManager(path)
            
            for art_path in self.selected_artifacts:
                current_step += 1
                self.progress.emit(f"분석 중: {vhd_name} -> {art_path}")
                
                success, message = manager.extract_single_target(art_path)
                
                self.item_processed.emit({
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'artifact': art_path,
                    'status': "Success" if success else "Failed",
                    'message': message,
                    'source': vhd_name
                })

                percent = int((current_step / total_steps) * 100)
                self.vhd_done.emit(percent)
                
            results.append({'vhd_id': vhd_name, 'workspace': manager.workspace})

        self.finished.emit(results)

class VDIIntegratorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VDI Artifact Integrator")
        self.setGeometry(100, 100, 1100, 700)
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_input_tab(), "Input")
        self.tabs.addTab(self._create_results_tab(), "Results")
        self.tabs.addTab(self._create_mapping_tab(), "User Mapping")
        
        layout.addWidget(self.tabs)

    def _create_input_tab(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)

        # 이미지 리스트
        vhd_group = QGroupBox("Evidence Files")
        vhd_layout = QVBoxLayout()
        self.vhd_list_widget = QListWidget()
        btn_add = QPushButton("Add Files (VHD/E01)")
        btn_add.clicked.connect(self.add_vhds)
        vhd_layout.addWidget(self.vhd_list_widget)
        vhd_layout.addWidget(btn_add)
        vhd_group.setLayout(vhd_layout)

        # 옵션
        opt_group = QGroupBox("Options")
        opt_layout = QVBoxLayout()
        self.chk_prefetch = QCheckBox("Prefetch")
        self.chk_edge = QCheckBox("Edge History")
        self.chk_security = QCheckBox("Security Logs")
        self.progress_bar = QProgressBar()
        self.log_output = QLabel("Ready")
        self.btn_start = QPushButton("Start Analysis")
        self.btn_start.clicked.connect(self.start_analysis)
        self.btn_start.setStyleSheet("background-color: #2196F3; color: white; height: 40px;")
        
        opt_layout.addWidget(self.chk_prefetch)
        opt_layout.addWidget(self.chk_edge)
        opt_layout.addWidget(self.chk_security)
        opt_layout.addStretch()
        opt_layout.addWidget(self.log_output)
        opt_layout.addWidget(self.progress_bar)
        opt_layout.addWidget(self.btn_start)
        opt_group.setLayout(opt_layout)

        layout.addWidget(vhd_group, 2)
        layout.addWidget(opt_group, 1)
        return widget

    def _create_results_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.result_tree = QTreeWidget()
        self.result_tree.setColumnCount(5)
        self.result_tree.setHeaderLabels(["Timestamp", "Artifact Path", "Status", "Message", "Source"])
        self.result_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.result_tree)
        return widget

    def _create_mapping_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.mapping_table = QTableWidget(0, 3)
        self.mapping_table.setHorizontalHeaderLabels(["SID", "Username", "Source"])
        layout.addWidget(self.mapping_table)
        return widget

    def add_vhds(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files", "", "Forensic Images (*.e01 *.vhd *.vhdx)")
        if files: self.vhd_list_widget.addItems(files)

    def start_analysis(self):
        vhd_paths = [self.vhd_list_widget.item(i).text() for i in range(self.vhd_list_widget.count())]
        if not vhd_paths: return
        
        artifacts = []
        if self.chk_prefetch.isChecked(): artifacts.append('Windows/Prefetch')
        if self.chk_edge.isChecked(): artifacts.append('Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History')
        if self.chk_security.isChecked(): artifacts.append('Windows/System32/winevt/Logs/Security.evtx')
        

        self.result_tree.clear()
        self.tabs.setCurrentIndex(1)
        self.btn_start.setEnabled(False)

        self.worker = AnalysisThread(vhd_paths, artifacts)
        self.worker.item_processed.connect(self.add_result_row)
        self.worker.progress.connect(self.log_output.setText)
        self.worker.vhd_done.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def add_result_row(self, info):
        item = QTreeWidgetItem([info['timestamp'], info['artifact'], info['status'], info['message'], info['source']])
        if info['status'] == "Failed":
            for col in range(5): item.setForeground(col, Qt.red)
        self.result_tree.addTopLevelItem(item)
        self.result_tree.scrollToItem(item)

    def on_finished(self, results):
        self.btn_start.setEnabled(True)
        QMessageBox.information(self, "Done", "분석이 완료되었습니다.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = VDIIntegratorGUI()
    gui.show()
    sys.exit(app.exec_())