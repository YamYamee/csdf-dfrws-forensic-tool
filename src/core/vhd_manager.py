import os
import pytsk3
import pyewf
import logging
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
        # extract fortmat from image path
        self.extension = os.path.splitext(self.image_path)[1].lower()
        self.workspace = os.path.abspath(os.path.join(workspace_base, os.path.basename(image_path).replace(".", "_")))
        os.makedirs(self.workspace, exist_ok=True)
        self.img_info = self._init_image_handle()
        # initialize filesystem info
        self.fs_info = None
        if self.img_info:
            try:
                # TODO start from offest 0, may need to adjust for partitioned images
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
            except:
                logger.error(f"파일시스템 로드 실패: {self.image_path}")

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
        """단일 타겟(와일드카드 포함) 추출 및 결과 반환"""
        if not self.fs_info:
            return False, "파일시스템 연결 불가"

        if '*' in target_path:
            users = self._get_user_list()
            if not users: return False, "사용자 폴더 없음"
            
            all_success = True
            for user in users:
                resolved = target_path.replace('*', user)
                if not self._try_extract(resolved):
                    all_success = False
            return all_success, f"{len(users)}명 사용자 시도 완료"
        else:
            success = self._try_extract(target_path)
            return success, "추출 완료" if success else "파일/폴더 없음"

    def _try_extract(self, path):
        """지정된 경로에서 파일 또는 폴더 추출 시도"""
        clean_path = '/' + path.replace('\\', '/').lstrip('/')
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
        """파일시스템 항목을 워크스페이스에 저장"""
        try:
            safe_name = full_path.replace('/', '_').lstrip('_')
            save_path = os.path.join(self.workspace, safe_name)
            with open(save_path, "wb") as f:
                offset = 0
                size = entry.info.meta.size
                while offset < size:
                    chunk = min(1024 * 1024, size - offset)
                    f.write(entry.read_random(offset, chunk))
                    offset += chunk
            return True
        except: return False