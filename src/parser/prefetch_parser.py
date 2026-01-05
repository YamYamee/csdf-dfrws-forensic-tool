import subprocess
import os
import pandas as pd # CSV 처리를 위해 pandas 사용 권장
import glob

class PrefetchParser:
    def __init__(self, pecmd_path="tools/PECmd.exe"):
        self.pecmd_path = pecmd_path

    def execute_pecmd(self, input_dir, output_dir):
        """PECmd.exe를 실행하여 CSV 생성"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # PECmd 실행 명령어: -d (디렉토리), --csv (결과 저장 폴더)
        # --quiet 옵션으로 콘솔 출력 최소화 가능

        print(f"[INFO] PECmd 실행: {self.pecmd_path} -d {input_dir} --csv {output_dir}")

        cmd = [
            self.pecmd_path,
            "-d", input_dir,
            "--csv", output_dir
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except Exception as e:
            print(f"PECmd 실행 오류: {e}")
            return False

    def load_pecmd_csv(self, output_dir):
        """생성된 CSV 파일들 중 가장 최신 결과 읽기"""
        # PECmd는 보통 YYYYMMDDHHMMSS_PECmd_Output.csv 형태로 생성함
        csv_files = glob.glob(os.path.join(output_dir, "*_PECmd_Output.csv"))
        if not csv_files:
            return []

        # 가장 최근에 생성된 CSV 선택
        latest_csv = max(csv_files, key=os.path.getctime)
        
        df = pd.read_csv(latest_csv)
        results = []
        for _, row in df.iterrows():
            results.append({
                'timestamp': str(row.get('LastRun', 'N/A')),
                'name': str(row.get('ExecutableName', 'N/A')),
                'count': str(row.get('RunCount', '0')),
            })
        return results