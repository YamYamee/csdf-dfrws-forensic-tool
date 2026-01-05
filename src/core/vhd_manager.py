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
                    # 1. 너무 작은 파티션은 건너뜀 (예: 1GB 미만)
                    if partition.len < 2048 * 1024: # 섹터 수 기준 (약 1GB)
                        continue

                    offset = partition.start * 512
                    try:
                        temp_fs = pytsk3.FS_Info(self.img_info, offset=offset)
                        
                        # 2. [검증 로직] 해당 파티션 루트에 Windows나 Users 폴더가 있는지 확인
                        root_dir = temp_fs.open_dir(path="/")
                        found_os = False
                        for entry in root_dir:
                            name = entry.info.name.name.decode('utf-8', 'replace')
                            if name.lower() in ["windows", "users"]:
                                found_os = True
                                break
                        
                        if found_os:
                            self.fs_info = temp_fs
                            print(f"[SUCCESS] OS 파티션 확정! Offset: {offset}")
                            break # 진짜를 찾았으므로 종료
                            
                    except:
                        continue
                
                # 끝까지 못 찾았을 경우 대비 (Logical Image 대응)
                if not self.fs_info:
                    self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
                    
            except Exception as e:
                print(f"[DEBUG] 파티션 분석 중 오류: {e}")
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
        """Users 폴더를 직접 스캔하여 개별 유저별 경로를 생성하고 추출"""
        clean_path = target_path.replace('\\', '/').lstrip('/')
        detailed_results = []

        # 1. 'Users/*' 패턴이 포함된 경우 처리
        if 'Users/*' in target_path:
            base_after_user = clean_path.split('Users/*/')[-1]
            try:
                # /Users 디렉토리를 열어 실제 폴더 목록 확보
                users_dir = self.fs_info.open_dir(path="/Users")
                
                for entry in users_dir:
                    name = entry.info.name.name.decode('utf-8', 'replace')
                    if name in [".", "..", "Public", "All Users", "Default User"]:
                        continue # 불필요한 시스템 링크 및 특수 폴더 제외

                    # 디렉토리 타입인지 확인 (TSK_FS_META_TYPE_DIR = 2)
                    if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        user_specific_path = f"/Users/{name}/{base_after_user}"
                        
                        success = self._try_extract(user_specific_path)
                        detailed_results.append({
                            'path': user_specific_path,
                            'success': success,
                            'message': f"[{name}] 추출 성공" if success else f"[{name}] 추출 실패",
                            'user': name
                        })
            except Exception as e:
                return [{'path': target_path, 'success': False, 'message': f"Users 스캔 실패: {e}"}]

        # 2. 일반 경로(와일드카드 없음) 처리
        else:
            success = self._try_extract(clean_path)
            detailed_results.append({
                'path': clean_path,
                'success': success,
                'message': "추출 성공" if success else "추출 실패",
                'user': "System"
            })

        return detailed_results

    def _try_extract(self, path):
        """지정된 경로에서 파일 또는 폴더 추출 시도"""
        clean_path = '/' + path.replace('\\', '/').lstrip('/')
        print(f"[DEBUG] 추출 시도 경로: {clean_path}")
        try:
            # 파일시스템 내에서 해당 경로에 무엇이 있는지(파일인지, 폴더인지, 아니면 없는 경로인지) 확인
            entry = self.fs_info.open(clean_path)
            # 일반 파일인 경우
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                return self._save_entry(entry, clean_path)
            # 경로인 경우
            elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                self._extract_dir(entry.as_directory(), clean_path)
                return True
        except: return False

    def _extract_dir(self, directory, current_path):
        """디렉토리 내 모든 항목 재귀 추출"""
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
        """파일시스템 항목을 워크스페이스 내의 해당 아티팩트 전용 폴더에 저장"""
        try:
            # 1. 상위 폴더 경로 추출 및 정리
            # 예: '/Windows/Prefetch/CMD.EXE-123.pf' -> 'Windows_Prefetch'
            dir_name = os.path.dirname(full_path).replace('\\', '/').strip('/')
            rel_dir = dir_name.replace('/', '_')
            
            target_dir = os.path.join(self.workspace, rel_dir)

            # 2. 폴더 생성
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)

            # 3. 파일 저장
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
            logger.error(f"저장 실패 ({full_path}): {e}")
            return False