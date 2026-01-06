import os
import pytsk3
import pyewf
import logging
import traceback
from datetime import datetime

logger = logging.getLogger("ForensicAnalyzer")

class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
    def get_size(self):
        return self._ewf_handle.get_media_size()

class EvidenceManager:
    def __init__(self, image_path, workspace_base="workspace"):
        self.image_path = os.path.abspath(image_path)
        self.extension = os.path.splitext(self.image_path)[1].lower()
        self.workspace = os.path.abspath(os.path.join(workspace_base, os.path.basename(image_path).replace(".", "_")))
        os.makedirs(self.workspace, exist_ok=True)
        
        self.img_info = self._init_image_handle()
        self.fs_info = None

        if self.img_info:
            try:
                volume = pytsk3.Volume_Info(self.img_info)
                for partition in volume:
                    if partition.len < 2048 * 1024:
                        continue

                    offset = partition.start * 512
                    try:
                        temp_fs = pytsk3.FS_Info(self.img_info, offset=offset)
                        
                        root_dir = temp_fs.open_dir(path="/")
                        found_os = False
                        for entry in root_dir:
                            name = entry.info.name.name.decode('utf-8', 'replace')
                            if name.lower() in ["windows", "users"]:
                                found_os = True
                                break
                        
                        if found_os:
                            self.fs_info = temp_fs
                            print(f"[SUCCESS] OS Partition Found! Offset: {offset}")
                            break 
                            
                    except:
                        continue
                
                if not self.fs_info:
                    self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
                    
            except Exception as e:
                print(f"[DEBUG] Error analyzing partition: {e}")
                try: self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
                except: pass

    def _init_image_handle(self):
        try:
            if self.extension == '.e01':
                filenames = pyewf.glob(self.image_path)
                handle = pyewf.handle()
                handle.open(filenames)
                return EWFImgInfo(handle)
            return pytsk3.Img_Info(self.image_path)
        except Exception as e:
            return None

    def _get_user_list(self):
        users = []
        if not self.fs_info: return users
        try:
            users_dir = self.fs_info.open_dir(path="/Users")
            for entry in users_dir:
                name = entry.info.name.name.decode('utf-8', 'replace')
                # TODO consider cases which evidences are located in these folders
                if name in [".", "..", "Default", "Public", "All Users"]: continue
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    users.append(name)
        except: pass
        return users

    def extract_single_target(self, target_path):
        """Directly scan the Users folder to create and extract individual user paths"""
        clean_path = target_path.replace('\\', '/').lstrip('/')
        detailed_results = []

        # 1. Handle cases where the pattern 'Users/*' is included
        if 'Users/*' in target_path:
            base_after_user = clean_path.split('Users/*/')[-1]
            try:
                # Open the /Users directory to get the actual folder list
                users_dir = self.fs_info.open_dir(path="/Users")
                
                for entry in users_dir:
                    name = entry.info.name.name.decode('utf-8', 'replace')
                    if name in [".", "..", "Public", "All Users", "Default User"]:
                        continue 

                    # Check if it is a directory type (TSK_FS_META_TYPE_DIR = 2)
                    if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        user_specific_path = f"/Users/{name}/{base_after_user}"
                        
                        success = self._try_extract(user_specific_path)
                        detailed_results.append({
                            'path': user_specific_path,
                            'success': success,
                            'message': f"[{name}] Extraction successful" if success else f"[{name}] Extraction failed",
                            'user': name
                        })
            except Exception as e:
                return [{'path': target_path, 'success': False, 'message': f"Users scan failed: {e}"}]
        else:
            success = self._try_extract(clean_path)
            detailed_results.append({
                'path': clean_path,
                'success': success,
                'message': "Extraction successful" if success else "Extraction failed",
                'user': "System"
            })

        return detailed_results

    def _try_extract(self, path):
        """Attempt to extract a file or folder from the specified path"""
        clean_path = '/' + path.replace('\\', '/').lstrip('/')
        print(f"[DEBUG] Extraction attempt path: {clean_path}")
        try:
            # Check what is at the specified path in the filesystem (file, folder, or non-existent)
            entry = self.fs_info.open(clean_path)
            # Regular file case
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                return self._save_entry(entry, clean_path)
            # Directory case
            elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                self._extract_dir(entry.as_directory(), clean_path)
                return True
        except: return False

    def _extract_dir(self, directory, current_path):
        """Recursively extract all items within a directory"""
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'replace')
            if name in [".", ".."] or name.startswith('$'): continue
            this_path = f"{current_path}/{name}"
            try:
                if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    self._save_entry(entry, this_path)
                elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    self._extract_dir(entry.as_directory(), this_path)
            except: continue

    def _save_entry(self, entry, full_path):
        """Save a filesystem entry to the dedicated artifact folder within the workspace"""
        try:
            # 1. Extract and clean the parent folder path
            # Example: '/Windows/Prefetch/CMD.EXE-123.pf' -> 'Windows_Prefetch'
            dir_name = os.path.dirname(full_path).replace('\\', '/').strip('/')
            rel_dir = dir_name.replace('/', '_')
            
            target_dir = os.path.join(self.workspace, rel_dir)

            # 2. Create the folder
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)

            # 3. Save the file
            file_name = os.path.basename(full_path)
            save_path = os.path.join(target_dir, file_name)

            with open(save_path, "wb") as f:
                offset = 0
                size = entry.info.meta.size
                while offset < size:
                    chunk = min(1024 * 1024, size - offset)
                    f.write(entry.read_random(offset, chunk))
                    offset += chunk
            return True
        except Exception as e:
            logger.error(f"Save failed ({full_path}): {e}")
            return False