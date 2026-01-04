import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QLabel,
    QGroupBox, QFileDialog, QProgressBar, QTabWidget, QTreeWidget, 
    QTreeWidgetItem, QHeaderView, QListWidget, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from datetime import datetime

class ProcessingThread(QThread):
    """여러 VHD를 순회하며 아티팩트를 추출하고 통합하는 백그라운드 스레드"""
    progress = pyqtSignal(str)
    vhd_done = pyqtSignal(int) # 전체 중 몇 번째 VHD 완료
    finished = pyqtSignal(list)

    def __init__(self, vhd_paths, selected_artifacts):
        super().__init__()
        self.vhd_paths = vhd_paths
        self.selected_artifacts = selected_artifacts

    def run(self):
        integrated_results = []
        total_vhds = len(self.vhd_paths)
        
        for i, path in enumerate(self.vhd_paths):
            vhd_name = os.path.basename(path)
            self.progress.emit(f"[{i+1}/{total_vhds}] {vhd_name} 분석 중...")
            
            # TODO: 여기에 src/core/vhd_manager.py 와 연동하는 로직이 들어갑니다.
            # 1. VHD 마운트/파싱
            # 2. SID 매핑 테이블 생성
            # 3. 아티팩트(Prefetch, Edge 등) 추출
            
            # 샘플 데이터 생성 (추후 실제 파싱 데이터로 대체)
            integrated_results.append({
                'vhd_id': f"VHD_{i}",
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'user': "User_A",
                'type': "Prefetch",
                'desc': f"Sample process from {vhd_name}"
            })
            
            self.vhd_done.emit(i + 1)
            
        self.progress.emit("모든 VHD 분석 및 데이터 통합 완료!")
        self.finished.emit(integrated_results)

class VDIIntegratorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.vhd_list = []
        self.setWindowTitle("VDI Pooled Environment Artifact Integrator")
        self.setGeometry(100, 100, 1200, 800)
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 상단 탭 구성
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_input_tab(), "VHD Selection")
        self.tabs.addTab(self._create_results_tab(), "Integrated Results")
        self.tabs.addTab(self._create_mapping_tab(), "User Mapping")
        
        main_layout.addWidget(self.tabs)
        self.statusBar().showMessage("Ready")

    def _create_input_tab(self):
        """VHD 파일들을 선택하고 아티팩트를 고르는 탭"""
        widget = QWidget()
        layout = QHBoxLayout(widget)

        # 왼쪽: VHD 파일 리스트
        vhd_group = QGroupBox("Target VHD Files")
        vhd_layout = QVBoxLayout()
        self.vhd_list_widget = QListWidget()
        btn_add_vhd = QPushButton("Add VHD/VHDX Files")
        btn_add_vhd.clicked.connect(self.add_vhds)
        btn_remove_vhd = QPushButton("Remove Selected")
        btn_remove_vhd.clicked.connect(lambda: self.vhd_list_widget.takeItem(self.vhd_list_widget.currentRow()))
        
        vhd_layout.addWidget(self.vhd_list_widget)
        vhd_layout.addWidget(btn_add_vhd)
        vhd_layout.addWidget(btn_remove_vhd)
        vhd_group.setLayout(vhd_layout)

        # 오른쪽: 옵션 및 실행
        opt_group = QGroupBox("Extraction Options")
        opt_layout = QVBoxLayout()
        self.chk_prefetch = QCheckBox("Prefetch")
        self.chk_edge = QCheckBox("Edge History")
        self.chk_prefetch.setChecked(True)
        self.chk_edge.setChecked(True)
        
        self.progress_bar = QProgressBar()
        self.log_output = QLabel("No vhds selected.")
        
        btn_start = QPushButton("Start Integrated Analysis")
        btn_start.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold; height: 40px;")
        btn_start.clicked.connect(self.start_analysis)

        opt_layout.addWidget(QLabel("Select Artifacts to Extract:"))
        opt_layout.addWidget(self.chk_prefetch)
        opt_layout.addWidget(self.chk_edge)
        opt_layout.addStretch()
        opt_layout.addWidget(self.log_output)
        opt_layout.addWidget(self.progress_bar)
        opt_layout.addWidget(btn_start)
        opt_group.setLayout(opt_layout)

        layout.addWidget(vhd_group, 2)
        layout.addWidget(opt_group, 1)
        return widget

    def _create_results_tab(self):
        """통합된 타임라인 결과를 보여주는 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.result_tree = QTreeWidget()
        self.result_tree.setColumnCount(5)
        self.result_tree.setHeaderLabels(["Timestamp", "Username", "Artifact Type", "Description", "Source VHD"])
        self.result_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.result_tree)
        return widget

    def _create_mapping_tab(self):
        """SID와 User 매핑 정보를 보여주는 탭 (Pooled 환경 필수)"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.mapping_table = QTableWidget(0, 3)
        self.mapping_table.setHorizontalHeaderLabels(["SID", "Mapped Username", "Source VHD"])
        self.mapping_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.mapping_table)
        return widget

    def add_vhds(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select VHD Files", "", "VHD Files (*.vhd *.vhdx)")
        if files:
            self.vhd_list_widget.addItems(files)
            self.log_output.setText(f"{self.vhd_list_widget.count()} 개의 VHD 선택됨")

    def start_analysis(self):
        vhd_paths = [self.vhd_list_widget.item(i).text() for i in range(self.vhd_list_widget.count())]
        if not vhd_paths:
            return

        self.progress_bar.setMaximum(len(vhd_paths))
        self.thread = ProcessingThread(vhd_paths, [])
        self.thread.progress.connect(lambda msg: self.log_output.setText(msg))
        self.thread.vhd_done.connect(lambda val: self.progress_bar.setValue(val))
        self.thread.finished.connect(self.display_results)
        self.thread.start()

    def display_results(self, data):
        self.result_tree.clear()
        for item in data:
            tree_item = QTreeWidgetItem([
                item['timestamp'], item['user'], item['type'], item['desc'], item['vhd_id']
            ])
            self.result_tree.addTopLevelItem(tree_item)
        self.tabs.setCurrentIndex(1) # 결과 탭으로 이동

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    gui = VDIIntegratorGUI()
    gui.show()
    sys.exit(app.exec_())