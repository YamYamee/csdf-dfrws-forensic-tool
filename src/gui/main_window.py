import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QLabel,
    QGroupBox, QFileDialog, QProgressBar, QTabWidget, QTreeWidget, 
    QTreeWidgetItem, QHeaderView, QListWidget, QCheckBox, QMessageBox
    , QComboBox, QLineEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.core.vhd_manager import EvidenceManager 
from src.core.sid_mapper import SIDMapper
from src.parser.prefetch_parser import PrefetchParser
from src.parser.edge_history_parser import EdgeHistoryParser

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
                detailed_results = manager.extract_single_target(art_path)
                
                for res in detailed_results:
                    self.item_processed.emit({
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'artifact': res['path'], # 구체적인 유저 경로
                        'status': "Success" if res['success'] else "Failed",
                        'message': res['message'],
                        'source': vhd_name
                    })

                percent = int((current_step / total_steps) * 100)
                self.vhd_done.emit(percent)
                
            results.append({'vhd_id': vhd_name, 'workspace': manager.workspace})

        self.finished.emit(results)

class MappingThread(QThread):
    progress = pyqtSignal(str)
    mapping_done = pyqtSignal(list)
    finished = pyqtSignal()

    def __init__(self, vhd_info_list):
        super().__init__()
        self.vhd_info_list = vhd_info_list

    def run(self):
        mapper = SIDMapper()
        
        for info in self.vhd_info_list:
            vhd_id = info['vhd_id']
            workspace = info['workspace']
            
            # 1. SOFTWARE 하이브 먼저 분석 (폴더명 확보)
            soft_dir = os.path.join(workspace, "Windows_System32_config")
            soft_path = os.path.join(soft_dir, "SOFTWARE")
            if os.path.exists(soft_path):
                print(f"레지스트리 분석 중: {vhd_id}")
                mapper.parse_software_hive(soft_path)

            # 2. Security.evtx 분석 (이벤트 & SID 확보)
            evtx_dir = os.path.join(workspace, "Windows_System32_winevt_Logs")
            evtx_path = os.path.join(evtx_dir, "Security.evtx")
            if os.path.exists(evtx_path):
                print(f"로그 파싱 중: {vhd_id}")
                mapper.parse_evtx_file(evtx_path, vhd_id)

        # 분석 완료 후 CSV 저장 (루트 워크스페이스에 저장)
        csv_path = os.path.join("workspace", "integrated_sid_map.csv")
        mapper.save_to_csv(csv_path)

        # UI에 데이터 전송
        self.mapping_done.emit(mapper.master_map)
        self.finished.emit()


class VDIIntegratorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.extracted_info = []
        self.user_to_folder_map = {}
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

        # 이미지 리스트 (좌측)
        vhd_group = QGroupBox("Evidence Files")
        vhd_layout = QVBoxLayout()
        self.vhd_list_widget = QListWidget()
        btn_add = QPushButton("Add Files (VHD/E01)")
        btn_add.clicked.connect(self.add_vhds)
        vhd_layout.addWidget(self.vhd_list_widget)
        vhd_layout.addWidget(btn_add)
        vhd_group.setLayout(vhd_layout)

        # 옵션 (우측)
        opt_group = QGroupBox("Options")
        opt_layout = QVBoxLayout()
        self.chk_prefetch = QCheckBox("Prefetch")
        self.chk_edge = QCheckBox("Edge History")
        
        self.chk_security = QCheckBox("Security Logs")
        self.chk_security.setChecked(True) 
        self.chk_security.setEnabled(False) 

        self.chk_software = QCheckBox("SOFTWARE Hive (Registry)")
        self.chk_software.setChecked(True)
        self.chk_software.setEnabled(False)

        self.progress_bar = QProgressBar()
        self.log_output = QLabel("Ready")
        self.btn_start = QPushButton("Start Analysis")
        self.btn_start.clicked.connect(self.start_analysis)
        self.btn_start.setStyleSheet("background-color: #2196F3; color: white; height: 40px;")
        
        opt_layout.addWidget(self.chk_prefetch)
        opt_layout.addWidget(self.chk_edge)
        opt_layout.addWidget(self.chk_security)
        opt_layout.addWidget(self.chk_software)
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
        
        btn_layout = QHBoxLayout()
        self.btn_map_sid = QPushButton("Extract & Map SID")
        self.btn_map_sid.clicked.connect(self.start_sid_mapping)
        self.btn_map_sid.setStyleSheet("height: 30px; font-weight: bold;")
        btn_layout.addWidget(self.btn_map_sid)
        btn_layout.addStretch()
        
        self.mapping_table = QTableWidget(0, 5) 
        self.mapping_table.setHorizontalHeaderLabels(["Timestamp", "Mantra ID", "SID", "Folder Name", "Source VHD"])
        self.mapping_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addLayout(btn_layout)
        layout.addWidget(self.mapping_table)
        return widget
    
    def _create_edge_result_tab(self): # Edge History 결과 탭
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 1. 상단 사용자 선택 영역
        select_group = QGroupBox("Target User Selection")
        select_layout = QHBoxLayout()
        
        self.combo_user = QComboBox() # 사용자 이름 (Mapping 결과에서 가져옴)
        self.combo_user.setMinimumWidth(150)
        
        btn_analyze = QPushButton("Analyze Selected User's Edge History")
        btn_analyze.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; height: 30px;")
        btn_analyze.clicked.connect(self.run_targeted_edge_analysis)

        select_layout.addWidget(QLabel("Select User (Email):"))
        select_layout.addWidget(self.combo_user)
        select_layout.addWidget(btn_analyze)
        select_layout.addStretch()
        select_group.setLayout(select_layout)

        # 2. 결과 테이블
        self.edge_table = QTableWidget(0, 5)
        self.edge_table.setHorizontalHeaderLabels(["Visit Time", "User (Email)", "Title", "URL", "Source"])
        self.edge_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addWidget(select_group)
        layout.addWidget(self.edge_table)
        return widget

    def add_vhds(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files", "", "Forensic Images (*.e01 *.vhd *.vhdx)")
        if files: self.vhd_list_widget.addItems(files)

    def start_analysis(self):
        vhd_paths = [self.vhd_list_widget.item(i).text() for i in range(self.vhd_list_widget.count())]
        if not vhd_paths: 
            QMessageBox.warning(self, "경고", "분석할 파일이 없습니다.")
            return
        
        # 1. 선택된 아티팩트 확인
        artifacts = []
        selected_names = [] 
        
        if self.chk_prefetch.isChecked():
            artifacts.append('Windows/Prefetch')
            selected_names.append("Prefetch")
        if self.chk_edge.isChecked():
            # [중요] 경로 끝에 History 파일까지 명시
            artifacts.append('Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History')
            selected_names.append("Edge History")
        if self.chk_security.isChecked():
            artifacts.append('Windows/System32/winevt/Logs/Security.evtx')
            selected_names.append("Security Logs")
        if self.chk_software.isChecked():
            artifacts.append('Windows/System32/config/SOFTWARE')
            selected_names.append("SOFTWARE Hive (Registry)")

        # 기존 동적 탭 제거
        for i in range(self.tabs.count() - 1, 2, -1):
            self.tabs.removeTab(i)

        self.artifact_tables = {} 
        
        for name in selected_names:
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            
            if name == "Prefetch":
                btn_parse = QPushButton("Prefetch Analysis")
                btn_parse.setStyleSheet("height: 35px; background-color: #4CAF50; color: white; font-weight: bold;")
                btn_parse.clicked.connect(self.run_prefetch_parser)
                tab_layout.addWidget(btn_parse)
                
                table = QTableWidget(0, 4)
                table.setHorizontalHeaderLabels(["Last Run Time", "Process Name", "Run Count", "Source VHD"])
                self.artifact_tables[name] = table # 테이블 등록
                tab_layout.addWidget(table)

            elif name == "Edge History":
                select_group = QGroupBox("Manual Target Selection")
                select_layout = QHBoxLayout()
                
                # [수정] 콤보박스 대신 직접 입력창 사용
                self.input_folder_name = QLineEdit()
                self.input_folder_name.setPlaceholderText("폴더명 입력")
                self.input_folder_name.setMinimumWidth(200)
                self.input_folder_name.setFixedHeight(30)
                
                btn_analyze = QPushButton("Analyze History")
                btn_analyze.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; height: 30px;")
                btn_analyze.clicked.connect(self.run_targeted_edge_analysis)

                select_layout.addWidget(QLabel("Folder Name:"))
                select_layout.addWidget(self.input_folder_name)
                select_layout.addWidget(btn_analyze)
                select_layout.addStretch()
                select_group.setLayout(select_layout)

                self.edge_table = QTableWidget(0, 5)
                self.edge_table.setHorizontalHeaderLabels(["Visit Time", "Folder Name", "Title", "URL", "Source"])
                self.edge_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                
                tab_layout.addWidget(select_group)
                tab_layout.addWidget(self.edge_table)
                self.artifact_tables[name] = self.edge_table

            else:
                table = QTableWidget(0, 4)
                table.setHorizontalHeaderLabels(["VHD Source", "Artifact Path", "Status", "Message"])
                tab_layout.addWidget(table)
                self.artifact_tables[name] = table

            table_to_resize = self.artifact_tables[name]
            table_to_resize.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.tabs.addTab(tab, f"{name} 결과")

        # 분석 스레드 시작 (이 코드가 실행되어야 버튼이 먹힙니다!)
        self.result_tree.clear()
        self.tabs.setCurrentIndex(1) 
        self.btn_start.setEnabled(False)

        self.worker = AnalysisThread(vhd_paths, artifacts)
        self.worker.item_processed.connect(self.add_result_row_and_tab)
        self.worker.progress.connect(self.log_output.setText)
        self.worker.vhd_done.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.start()
    
    def run_prefetch_parser(self):
        """추출된 모든 VHD의 Prefetch를 PECmd로 통합 분석"""
        if not self.extracted_info:
            QMessageBox.warning(self, "경고", "먼저 'Start Analysis'를 통해 파일 추출을 완료해야 합니다.")
            return

        table = self.artifact_tables.get("Prefetch")
        table.setRowCount(0) # 테이블 초기화
        
        parser = PrefetchParser(pecmd_path=os.path.join(os.getcwd(), "tools", "PECmd.exe"))

        for info in self.extracted_info:
            workspace = info['workspace'] # 예: workspace/vhd_name
            
            # 위에서 만든 폴더 규칙과 일치해야 함
            input_dir = os.path.join(workspace, "Windows_Prefetch") 
            output_dir = os.path.join(workspace, "Analysis_Results")

            if os.path.exists(input_dir):
                # 실제 폴더 안에 .pf 파일이 있는지 최종 확인
                pf_files = [f for f in os.listdir(input_dir) if f.lower().endswith('.pf')]
                if not pf_files:
                    print(f"경고: {input_dir} 에 .pf 파일이 없습니다.")
                    continue

                self.log_output.setText(f"PECmd 분석 중: {info['vhd_id']}")
                if parser.execute_pecmd(input_dir, output_dir):
                    # 2. 결과 CSV 로드
                    parsed_data = parser.load_pecmd_csv(output_dir)
                    
                    # 3. 테이블에 데이터 삽입
                    for data in parsed_data:
                        row = table.rowCount()
                        table.insertRow(row)
                        table.setItem(row, 0, QTableWidgetItem(data['timestamp']))
                        table.setItem(row, 1, QTableWidgetItem(data['name']))
                        table.setItem(row, 2, QTableWidgetItem(data['count']))
                        table.setItem(row, 3, QTableWidgetItem(info['vhd_id']))
        
        table.setSortingEnabled(True)
        table.sortItems(0, Qt.DescendingOrder)
        
        self.log_output.setText("Prefetch 통합 분석 완료")
        QMessageBox.information(self, "완료", "모든 VHD 이미지의 Prefetch 분석 및 통합이 완료되었습니다.")

    def on_analysis_finished(self, results):
        """1단계: 이미지 분석 및 파일 추출 완료 시 호출"""
        self.btn_start.setEnabled(True)
        self.extracted_info = results # 중요: 이 리스트가 있어야 SID 매핑이 가능함
        QMessageBox.information(self, "완료", "파일 추출이 완료되었습니다. 이제 'User Mapping' 탭에서 SID 분석을 진행하세요.")

    def start_sid_mapping(self):
        """2단계: 추출된 Security.evtx를 기반으로 SID 매핑 시작"""
        if not self.extracted_info:
            QMessageBox.warning(self, "경고", "먼저 'Input' 탭에서 분석을 완료해야 합니다.")
            return

        self.btn_map_sid.setEnabled(False)
        self.log_output.setText("SID 매핑 및 로그 파싱 시작...")

        # 외부 스레드 클래스 실행
        self.mapping_worker = MappingThread(self.extracted_info)
        self.mapping_worker.progress.connect(self.log_output.setText)
        self.mapping_worker.mapping_done.connect(self.update_mapping_table)
        self.mapping_worker.finished.connect(self.on_mapping_finished)
        self.mapping_worker.start()

    def on_mapping_finished(self):
        self.btn_map_sid.setEnabled(True)
        self.log_output.setText("SID 매핑 완료")
        QMessageBox.information(self, "완료", "Security.evtx 기반 SID 매핑 및 CSV 저장이 완료되었습니다.")

    def add_result_row(self, info):
        item = QTreeWidgetItem([info['timestamp'], info['artifact'], info['status'], info['message'], info['source']])
        if info['status'] == "Failed":
            for col in range(5): item.setForeground(col, Qt.red)
        self.result_tree.addTopLevelItem(item)
        self.result_tree.scrollToItem(item)

    def add_result_row_and_tab(self, info):
        # 1. 전체 요약(Results 탭)에 추가 (기존 로직)
        self.add_result_row(info)
        
        # 2. 동적으로 생성된 개별 아티팩트 탭에 데이터 분류해서 추가
        # info['artifact'] 경로 문자열에 포함된 단어로 매칭
        target_tab = ""
        if "Prefetch" in info['artifact']: target_tab = "Prefetch"
        elif "Edge" in info['artifact']: target_tab = "Edge History"
        elif "Security" in info['artifact']: target_tab = "Security Logs"
        
        if target_tab in self.artifact_tables:
            table = self.artifact_tables[target_tab]
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(info['source']))
            table.setItem(row, 1, QTableWidgetItem(info['artifact']))
            table.setItem(row, 2, QTableWidgetItem(info['status']))
            table.setItem(row, 3, QTableWidgetItem(info['message']))
            
            # 실패 시 빨간색 표시
            if info['status'] == "Failed":
                for col in range(4):
                    table.item(row, col).setForeground(Qt.red)

    def on_finished(self, results):
        self.btn_start.setEnabled(True)
        QMessageBox.information(self, "Done", "분석이 완료되었습니다.")

    def start_sid_mapping(self):
        """매핑 시작 버튼 핸들러"""
        if not hasattr(self, 'extracted_info') or not self.extracted_info:
            QMessageBox.warning(self, "경고", "먼저 VHD 분석을 완료하여 워크스페이스를 생성해야 합니다.")
            return

        self.btn_map_sid.setEnabled(False)
        self.mapping_worker = MappingThread(self.extracted_info)
        self.mapping_worker.mapping_done.connect(self.update_mapping_table)
        self.mapping_worker.finished.connect(lambda: self.btn_map_sid.setEnabled(True))
        self.mapping_worker.start()

    def update_mapping_table(self, mapping_list):
        """파싱된 데이터를 테이블에 출력하고 Edge 분석용 콤보박스 업데이트"""
        self.mapping_table.setRowCount(0)
        self.user_to_folder_map = {} # 초기화
        
        # 콤보박스가 이미 생성되어 있는지 확인 후 초기화
        if hasattr(self, 'combo_user'):
            self.combo_user.clear()

        for row, data in enumerate(mapping_list):
            self.mapping_table.insertRow(row)
            self.mapping_table.setItem(row, 0, QTableWidgetItem(data.get('time', 'N/A')))
            self.mapping_table.setItem(row, 1, QTableWidgetItem(data.get('user', 'N/A')))
            self.mapping_table.setItem(row, 2, QTableWidgetItem(data.get('sid', 'N/A')))
            
            folder = data.get('folder_name', 'Unknown')
            self.mapping_table.setItem(row, 3, QTableWidgetItem(folder))
            self.mapping_table.setItem(row, 4, QTableWidgetItem(data.get('vhd', 'N/A')))
            
            # [핵심] 유저 식별자 생성 (이름 + VHD명)
            user_id = data.get('user', 'Unknown')
            vhd_id = data.get('vhd', 'Unknown')
            display_name = f"{user_id} ({vhd_id})"

            # 폴더명이 유효할 때만 콤보박스에 추가
            if folder and folder != "Unknown" and folder != "systemprofile":
                self.user_to_folder_map[display_name] = folder
                if hasattr(self, 'combo_user'):
                    self.combo_user.addItem(display_name)

        self.mapping_table.setSortingEnabled(True)
        self.mapping_table.sortItems(0, Qt.DescendingOrder)
        
        print(f"[DEBUG] 콤보박스 업데이트 완료: {list(self.user_to_folder_map.keys())}")

    def run_targeted_edge_analysis(self):
        """입력된 폴더명을 기반으로 워크스페이스 내 History 파싱"""
        # 입력창에서 텍스트 직접 가져오기
        folder_name = self.input_folder_name.text().strip()

        self.edge_table.setSortingEnabled(False)
        self.edge_table.setRowCount(0)
        
        if not folder_name:
            QMessageBox.warning(self, "경고", "분석할 사용자 폴더명을 입력하세요.")
            return

        self.edge_table.setSortingEnabled(False)
        self.edge_table.setRowCount(0)
        parser = EdgeHistoryParser()

        # 파일명 규칙: Users_FolderName_AppData_Local_Microsoft_Edge_User_Data_Default_History
        found_any = False
        
        # 추출된 워크스페이스 정보들을 순회
        for info in self.extracted_info:
            workspace = info['workspace']
            vhd_id = info['vhd_id']
            
            # TODO 공백 관리하기
            target_filename = f"Users_{folder_name}_AppData_Local_Microsoft_Edge_User Data_Default\History"
            file_path = os.path.join(workspace, target_filename)

            print(f"[DEBUG] 분석 시도 경로: {file_path}")

            if os.path.exists(file_path):
                print(f"[INFO] 분석 타겟 발견: {file_path}")
                self.log_output.setText(f"분석 중: {folder_name}'s History")
                
                history_data = parser.parse(file_path)
                
                # 테이블에 데이터 삽입
                for data in history_data:
                    row = self.edge_table.rowCount()
                    self.edge_table.insertRow(row)
                    self.edge_table.setItem(row, 0, QTableWidgetItem(data['time']))
                    self.edge_table.setItem(row, 1, QTableWidgetItem(folder_name))
                    self.edge_table.setItem(row, 2, QTableWidgetItem(data['title']))
                    self.edge_table.setItem(row, 3, QTableWidgetItem(data['url']))
                    self.edge_table.setItem(row, 4, QTableWidgetItem(vhd_id))
                found_any = True

        if found_any:
            self.edge_table.setSortingEnabled(True)
            self.edge_table.sortItems(0, Qt.DescendingOrder)
            self.log_output.setText(f"{folder_name} 분석 완료")
        else:
            QMessageBox.critical(self, "실패", 
                f"워크스페이스에서 다음 파일을 찾지 못했습니다:\n{target_filename}\n\n폴더명이 정확한지 'User Mapping' 탭에서 확인하세요.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = VDIIntegratorGUI()
    gui.show()
    sys.exit(app.exec_())