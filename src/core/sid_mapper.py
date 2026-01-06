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
        """Parse SOFTWARE hive to extract SID and user folder mappings"""
        if not os.path.exists(software_path):
            return

        try:
            reg = Registry.Registry(software_path)
            # ProfileList path
            key_path = r"Microsoft\Windows NT\CurrentVersion\ProfileList"
            profile_list_key = reg.open(key_path)

            for subkey in profile_list_key.subkeys():
                sid = subkey.name() # The key name is the SID
                try:
                    path_value = subkey.value("ProfileImagePath").value()
                    folder_name = os.path.basename(path_value.replace('\\', '/'))
                    self.sid_to_folder[sid] = folder_name

                    if folder_name.lower() in ["systemprofile", "localservice", "networkservice"]:
                        continue

                    if not any(item['sid'] == sid for item in self.master_map):
                        self.master_map.append({
                        'time': "No Log Found",
                        'user': "Unknown",
                        'sid': sid,
                        'folder_name': folder_name,
                        'vhd': os.path.basename(os.path.dirname(os.path.dirname(software_path)))
                    })

                    print(f"[DEBUG] Mapping added: {sid} -> {folder_name}")
                except:
                    continue
        except Exception as e:
            print(f"Error parsing SOFTWARE hive: {e}")

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

                    if domain == "NT AUTHORITY" or (user_id and user_id.endswith('$')):
                        continue

                    if user_id and user_sid:
                        if not (user_sid.startswith("S-1-5-21-") or user_sid.startswith("S-1-12-1-")):
                            continue

                        event_time = record.timestamp().strftime("%Y-%m-%d %H:%M:%S")
                        
                        exists = False
                        for item in self.master_map:
                            if item['sid'] == user_sid:
                                item['time'] = event_time
                                item['user'] = user_id
                                item['domain'] = domain
                                item['logon_type'] = logon_type
                                exists = True
                                break
                        
                        if not exists:
                            self.master_map.append({
                                'time': event_time,
                                'user': user_id,
                                'sid': user_sid,
                                'folder_name': self.sid_to_folder.get(user_sid, "Unknown"), 
                                'domain': domain if domain else "Unknown",
                                'logon_type': logon_type if logon_type else "-",
                                'vhd': vhd_id
                            })

            return True
        except Exception as e:
            print(f"Parsing failed: {e}")
            return False

    def deduplicate_map(self):
        if not self.master_map:
            return

        self.master_map.sort(key=lambda x: x['time'])

        unique_data = {}
        for entry in self.master_map:
            key = (entry['vhd'], entry['sid'], entry['user'])
            
            if key not in unique_data:
                unique_data[key] = entry

        self.master_map = list(unique_data.values())

    def save_to_csv(self, output_path, deduplicate=True):
        """
        Save results to CSV. Adds the folder_name field to the list.
        """
        if deduplicate:
            self.deduplicate_map()

        if not self.master_map:
            print("No data to save.")
            return False

        try:
            # Create the folder for the output path if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                # Add folder_name to the fieldnames list
                fieldnames = ['time', 'user', 'sid', 'folder_name', 'domain', 'logon_type', 'vhd']
                
                # Adding extrasaction='ignore' prevents errors if some fields are missing in the data
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                
                writer.writeheader()
                writer.writerows(self.master_map)
            
            print(f"CSV saved successfully: {output_path}")
            return True
        except Exception as e:
            print(f"CSV save error: {e}")
            return False