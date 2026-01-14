import os
import pytsk3
import pyewf
import logging
import pyvhdi
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
    
class VHDImgInfo(pytsk3.Img_Info):
    def __init__(self, vhd_handle):
        self._vhd_handle = vhd_handle
        super(VHDImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    
    def close(self):
        self._vhd_handle.close()
    
    def read(self, offset, size):
        self._vhd_handle.seek(offset)
        return self._vhd_handle.read(size)
    
    def get_size(self):
        return self._vhd_handle.get_media_size()

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
                print(f"[DEBUG] Analyzing partitions...")
                print(f"[DEBUG] Total image size: {self.img_info.get_size()} bytes")
                
                # 먼저 Volume (파티션 테이블) 읽기 시도
                try:
                    volume = pytsk3.Volume_Info(self.img_info)
                    partition_count = 0
                    
                    for partition in volume:
                        partition_count += 1
                        print(f"[DEBUG] Partition {partition_count}:")
                        print(f"  - Start: {partition.start} (bytes: {partition.start * 512})")
                        print(f"  - Length: {partition.len} sectors")
                        print(f"  - Description: {partition.desc.decode('utf-8', 'replace')}")
                        print(f"  - Flags: {partition.flags}")
                        
                        # 너무 작은 파티션 스킵
                        if partition.len < 2048:
                            print(f"  -> Skipping (too small)")
                            continue

                        offset = partition.start * 512
                        
                        try:
                            temp_fs = pytsk3.FS_Info(self.img_info, offset=offset)
                            print(f"  -> FS_Info created successfully")
                            
                            # Windows 디렉토리 확인
                            try:
                                temp_fs = pytsk3.FS_Info(self.img_info, offset=offset)
                                print(f"  -> FS_Info created successfully")
                                
                                # 파일시스템이 열리면 일단 사용 (Windows 디렉토리 체크 제거)
                                if not self.fs_info:
                                    self.fs_info = temp_fs
                                    print(f"[SUCCESS] Filesystem found at offset: {offset}")
                                    
                                    # 디렉토리 내용 확인 (디버그용)
                                    try:
                                        root_dir = temp_fs.open_dir(path="/")
                                        print(f"  -> Root directory contents:")
                                        for entry in root_dir:
                                            if not hasattr(entry, 'info') or not hasattr(entry.info, 'name'):
                                                continue
                                            name = entry.info.name.name.decode('utf-8', 'replace')
                                            if name not in ['.', '..']:
                                                print(f"     - {name}")
                                    except Exception as e:
                                        print(f"  -> Could not list directory: {e}")
                                    
                                    break  # 첫 번째 유효한 파일시스템을 찾으면 종료
                                    
                            except Exception as e:
                                print(f"  -> Failed to create FS_Info: {e}")
                                continue
                                
                        except Exception as e:
                            print(f"  -> Failed to create FS_Info: {e}")
                            continue
                    
                    if partition_count == 0:
                        print(f"[DEBUG] No partitions found in volume table")
                        raise Exception("No partitions")
                        
                except Exception as vol_err:
                    print(f"[DEBUG] Volume_Info failed: {vol_err}")
                    print(f"[DEBUG] Trying common offsets for VHD without partition table...")
                    
                    # VHD가 파티션 테이블 없이 직접 파일시스템일 수 있음
                    common_offsets = [
                        0,           # 파티션 테이블 없음
                        512,         # 1 섹터
                        1024,        # 2 섹터
                        2048,        # 4 섹터
                        32256,       # 63 섹터 (레거시 DOS)
                        1048576,     # 2048 섹터 (1MB, 현대적 정렬)
                    ]
                    
                    for offset in common_offsets:
                        print(f"[DEBUG] Trying offset: {offset} bytes ({offset//512} sectors)")
                        try:
                            temp_fs = pytsk3.FS_Info(self.img_info, offset=offset)
                            
                            # 루트 디렉토리 접근 시도
                            root_dir = temp_fs.open_dir(path="/")
                            found_os = False
                            
                            for entry in root_dir:
                                name = entry.info.name.name.decode('utf-8', 'replace')
                                print(f"  Found: {name}")
                                if name.lower() in ["windows", "users", "program files"]:
                                    found_os = True
                                    print(f"  -> Found OS indicator: {name}")
                            
                            if found_os:
                                self.fs_info = temp_fs
                                print(f"[SUCCESS] Filesystem found at offset: {offset}")
                                break
                            else:
                                print(f"  -> No OS directories found at this offset")
                                
                        except Exception as e:
                            print(f"  -> Failed: {str(e)[:100]}")
                            continue
                
                if not self.fs_info:
                    print(f"[ERROR] Could not find valid filesystem in VHD")
                    
            except Exception as e:
                print(f"[ERROR] Exception during partition analysis: {e}")
                print(traceback.format_exc())

    def _init_image_handle(self):
        try:
            if self.extension == '.e01':
                filenames = pyewf.glob(self.image_path)
                handle = pyewf.handle()
                handle.open(filenames)
                return EWFImgInfo(handle)
            elif self.extension in ['.vhd', '.vhdx']:
                handle = pyvhdi.file()
                handle.open(self.image_path)
                print(f"[DEBUG] VHD opened: {self.image_path}")
                print(f"[DEBUG] VHD media size: {handle.get_media_size()}")
                return VHDImgInfo(handle)
            else:
                return pytsk3.Img_Info(self.image_path)
        except Exception as e:
            print(f"[ERROR] Image initialization failed: {e}")
            print(traceback.format_exc())
            logger.error(f"Image initialization failed: {e}")
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

        # Windows 디렉토리 체크 제거 - 모든 경로 시도
        if not self.fs_info:
            print(f"[WARNING] No filesystem available")
            return [{'path': target_path, 'success': False, 'message': 'No filesystem loaded'}]

        # 1. Handle cases where the pattern 'Users/*' is included
        if 'Users/*' in target_path:
            base_after_user = clean_path.split('Users/*/')[-1]
            try:
                users_dir = self.fs_info.open_dir(path="/Users")
                for entry in users_dir:
                    if not hasattr(entry.info, 'name'): 
                        continue
                    name = entry.info.name.name.decode('utf-8', 'replace')
                    if name in ['.', '..'] or entry.info.meta is None: 
                        continue
                    
                    user_path = f"Users/{name}/{base_after_user}"
                    success = self._try_extract(user_path)
                    detailed_results.append({
                        'path': user_path,
                        'success': success,
                        'message': "Success" if success else "Not Found"
                    })
            except Exception as e:
                print(f"[ERROR] Failed to scan Users folder: {e}")
                detailed_results.append({
                    'path': target_path,
                    'success': False,
                    'message': f"Users folder not accessible: {str(e)}"
                })
        else:
            success = self._try_extract(clean_path)
            detailed_results.append({
                'path': clean_path,
                'success': success,
                'message': "Success" if success else "Not Found"
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