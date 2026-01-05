import os
import csv
import xml.etree.ElementTree as ET
from Evtx import Evtx as evtx_module
from Registry import Registry

class SIDMapper:
    def __init__(self):
        self.master_map = []
        self.sid_to_folder = {}
    
    def parse_software_hive(self, software_path):
        """SOFTWARE 하이브에서 SID와 사용자 폴더 경로 매핑 추출"""
        if not os.path.exists(software_path):
            return

        try:
            reg = Registry.Registry(software_path)
            # ProfileList 경로
            key_path = r"Microsoft\Windows NT\CurrentVersion\ProfileList"
            profile_list_key = reg.open(key_path)

            for subkey in profile_list_key.subkeys():
                sid = subkey.name() # 키 이름이 바로 SID
                try:
                    path_value = subkey.value("ProfileImagePath").value()
                    folder_name = os.path.basename(path_value.replace('\\', '/'))
                    self.sid_to_folder[sid] = folder_name

                    if folder_name in ["systemprofile", "Localservice", "Networkservice"]:
                        continue

                    if not any(item['sid'] == sid for item in self.master_map):
                        self.master_map.append({
                        'time': "No Log Found",
                        'user': "Unknown",
                        'sid': sid,
                        'folder_name': folder_name,
                        'vhd': os.path.basename(os.path.dirname(os.path.dirname(software_path)))
                    })

                    print(f"[DEBUG] 매핑 추가: {sid} -> {folder_name}")
                except:
                    continue
        except Exception as e:
            print(f"SOFTWARE 하이브 파싱 에러: {e}")

    def parse_evtx_file(self, evtx_path, vhd_id):
        if not os.path.exists(evtx_path):
            return False

        try:
            with evtx_module.Evtx(evtx_path) as log:
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

                    # 시스템 계정 및 서비스 계정 필터링
                    if domain == "NT AUTHORITY" or (user_id and user_id.endswith('$')):
                        continue

                    # 일반 사용자 SID 패턴 확인
                    if user_id and user_sid:
                        if not (user_sid.startswith("S-1-5-21-") or user_sid.startswith("S-1-12-1-")):
                            continue

                        event_time = record.timestamp().strftime("%Y-%m-%d %H:%M:%S")
                        
                        # [핵심 수정] 기존 master_map에 해당 SID가 있는지 확인
                        exists = False
                        for item in self.master_map:
                            if item['sid'] == user_sid:
                                # 기존 항목이 있고, 로그 시간이 더 최신이면 업데이트
                                item['time'] = event_time
                                item['user'] = user_id
                                item['domain'] = domain
                                item['logon_type'] = logon_type
                                exists = True
                                break
                        
                        # 만약 레지스트리에 없던 SID가 로그에만 있다면 새로 추가
                        if not exists:
                            self.master_map.append({
                                'time': event_time,
                                'user': user_id,
                                'sid': user_sid,
                                'folder_name': self.sid_to_folder.get(user_sid, "Unknown"), # 매핑 시도
                                'domain': domain if domain else "Unknown",
                                'logon_type': logon_type if logon_type else "-",
                                'vhd': vhd_id
                            })

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
        결과를 CSV로 저장. folder_name 필드를 명단에 추가함.
        """
        if deduplicate:
            self.deduplicate_map()

        if not self.master_map:
            print("저장할 데이터가 없습니다.")
            return False

        try:
            # 출력 경로의 폴더가 없으면 생성
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                # [수정 포인트] folder_name을 fieldnames 리스트에 추가합니다.
                fieldnames = ['time', 'user', 'sid', 'folder_name', 'domain', 'logon_type', 'vhd']
                
                # extrasaction='ignore'를 추가하면 혹시 데이터에 없는 필드가 있어도 에러를 방지해줍니다.
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                
                writer.writeheader()
                writer.writerows(self.master_map)
            
            print(f"CSV 저장 성공: {output_path}")
            return True
        except Exception as e:
            print(f"CSV 저장 에러: {e}")
            return False