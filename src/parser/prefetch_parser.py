import subprocess
import os
import pandas as pd
import glob

class PrefetchParser:
    def __init__(self, pecmd_path="tools/PECmd.exe"):
        self.pecmd_path = pecmd_path

    def execute_pecmd(self, input_dir, output_dir):
        """Run PECmd.exe to generate CSV files from prefetch files"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        print(f"[INFO] Running PECmd: {self.pecmd_path} -d {input_dir} --csv {output_dir}")
        cmd = [
            self.pecmd_path,
            "-d", input_dir,
            "--csv", output_dir
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except Exception as e:
            print(f"PECmd execution error: {e}")
            return False

    def load_pecmd_csv(self, output_dir):
        """Read the most recent CSV file generated"""
        # PECmd usually generates files in the format YYYYMMDDHHMMSS_PECmd_Output.csv
        csv_files = glob.glob(os.path.join(output_dir, "*_PECmd_Output.csv"))
        if not csv_files:
            return []

        # Select the most recently created CSV file
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