import os
import csv
import xml.etree.ElementTree as ET
from Evtx import Evtx as evtx_module

class SIDMapper:
    def __init__(self):
        self.master_map = []

    def parse_evtx_file(self, evtx_path, vhd_id):
        if not os.path.exists(evtx_path):
            return False

        try:
            with evtx_module.Evtx(evtx_path) as log:
                count = 0
                for record in log.records():
                    node = ET.fromstring(record.xml())
                    
                    eid_node = node.find(".//{*}EventID")
                    if eid_node is None or eid_node.text != "4624":
                        continue

                    event_data = {d.get("Name"): d.text for d in node.findall(".//{*}Data")}
                    
                    user_id = event_data.get("TargetUserName")
                    user_sid = event_data.get("TargetUserSid")
                    domain = event_data.get("TargetDomainName")
                    logon_type = event_data.get("LogonType")

                    if domain == "NT AUTHORITY" and user_id == "SYSTEM":
                        continue

                    if user_id and user_sid:
                        if user_id.endswith('$'): continue
                        
                        valid_sid = user_sid.startswith("S-1-5-21-") or user_sid.startswith("S-1-12-1-")
                        
                        if valid_sid:
                            self.master_map.append({
                                'time': record.timestamp().strftime("%Y-%m-%d %H:%M:%S"),
                                'user': user_id,
                                'sid': user_sid,
                                'domain': domain if domain else "Unknown",
                                'logon_type': logon_type if logon_type else "-",
                                'vhd': vhd_id
                            })
                            count += 1
            return True
        except Exception as e:
            print(f"파싱 실패: {e}")
            return False

    def deduplicate_map(self):
        """
        중복된 매핑 정보를 제거합니다.
        기준: (User, SID, VHD)가 동일하면 가장 이른 시간의 기록만 남김.
        """
        if not self.master_map:
            return

        # 1. 시간순으로 정렬 (최초 로그온이 먼저 오도록 함)
        self.master_map.sort(key=lambda x: x['time'])

        unique_data = {}
        for entry in self.master_map:
            # 고유 키 생성 (VHD 이름 + SID + User)
            key = (entry['vhd'], entry['sid'], entry['user'])
            
            # 이미 존재하는 키라면 건너뜀 (이미 가장 이른 시간이 들어가 있음)
            if key not in unique_data:
                unique_data[key] = entry

        # 2. 중복 제거된 데이터로 master_map 업데이트
        self.master_map = list(unique_data.values())
        print(f"[INFO] 중복 제거 완료. 최종 {len(self.master_map)}개의 고유 매핑 확보.")

    def save_to_csv(self, output_path, deduplicate=True):
        """
        결과를 CSV로 저장. 기본적으로 중복 제거를 수행함.
        """
        if deduplicate:
            self.deduplicate_map()

        if not self.master_map:
            print("저장할 데이터가 없습니다.")
            return False

        try:
            with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                fieldnames = ['time', 'user', 'sid', 'domain', 'logon_type', 'vhd']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.master_map)
            return True
        except Exception as e:
            print(f"CSV 저장 에러: {e}")
            return False