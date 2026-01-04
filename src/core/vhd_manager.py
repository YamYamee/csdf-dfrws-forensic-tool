import os
import sys
import pytsk3
import pyewf
import logging
from datetime import datetime

# [로그 설정] 분석 과정을 실시간으로 추적합니다.
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ForensicAnalyzer")

# --- 이미지 인터페이스 래퍼 클래스 ---

class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
    def get_size(self):
        return self._ewf_handle.get_media_size()

class VHDXImgInfo(pytsk3.Img_Info):
    """VHDX 라이브러리가 설치된 경우를 위한 래퍼"""
    def __init__(self, vhdx_handle):
        self._vhdx_handle = vhdx_handle
        super(VHDXImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    def read(self, offset, size):
        return self._vhdx_handle.read(offset, size)
    def get_size(self):
        return self._vhdx_handle.size

# --- 메인 관리 클래스 ---

class EvidenceManager:
    def __init__(self, image_path, workspace_base="workspace"):
        self.image_path = os.path.abspath(image_path)
        self.extension = os.path.splitext(self.image_path)[1].lower()
        self.workspace = os.path.abspath(os.path.join(workspace_base, os.path.basename(image_path).replace(".", "_")))
        os.makedirs(self.workspace, exist_ok=True)
        
        logger.info(f"🚀 분석 엔진 가동: {self.image_path}")
        self.img_info = self._init_image_handle()

    def _init_image_handle(self):
        """이미지 타입별 핸들링 (E01, VHDX, Raw)"""
        try:
            if self.extension == '.e01':
                filenames = pyewf.glob(self.image_path)
                handle = pyewf.handle()
                handle.open(filenames)
                logger.info(f"✅ E01 로드 성공 (세그먼트: {len(filenames)})")
                return EWFImgInfo(handle)
            
            elif self.extension == '.vhdx':
                try:
                    import vhdx
                    v_handle = vhdx.VHDX(self.image_path)
                    logger.info("✅ VHDX 직접 로드 성공")
                    return VHDXImgInfo(v_handle)
                except ImportError:
                    logger.warning("⚠️ vhdx 라이브러리 부재. Raw 변환본(.img)을 확인합니다.")
                    raw_path = self.image_path.replace(".vhdx", ".img")
                    if os.path.exists(raw_path):
                        return pytsk3.Img_Info(raw_path)
                    raise Exception("VHDX 처리를 위해선 'pip install vhdx'가 필요합니다.")
            
            else:
                logger.info(f"✅ Raw/DD 이미지로 처리 시작")
                return pytsk3.Img_Info(self.image_path)
        except Exception as e:
            logger.critical(f"❌ 이미지 로드 실패: {e}")
            return None

    def extract_artifacts(self, targets):
        """
        targets: ["Windows/System32/config/SOFTWARE", "target_file.txt"]
        """
        if not self.img_info: return
        
        # 1. 볼륨 분석 시도
        try:
            vs_info = pytsk3.Volume_Info(self.img_info)
            logger.debug(f"파티션 테이블 감지: {vs_info.info.vstype}")
            for partition in vs_info:
                if partition.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    offset = partition.start * vs_info.info.block_size
                    logger.info(f"📦 파티션 분석: {partition.desc.decode()} (Offset: {offset})")
                    self._process_filesystem(offset, targets)
        except Exception:
            # 2. 파티션 테이블이 없는 경우 (C드라이브 단일 덤프 등)
            logger.warning("🔍 파티션 테이블 없음. 오프셋 0에서 단일 파일시스템 분석을 시작합니다.")
            self._process_filesystem(0, targets)

    def _process_filesystem(self, offset, targets):
        try:
            fs_info = pytsk3.FS_Info(self.img_info, offset=offset)
            logger.info(f"📂 파일시스템 연결 성공 (Type: {fs_info.info.ftype})")

            for target in targets:
                # 경로 정규화 (역슬래시 -> 슬래시, 맨 앞 슬래시 보장)
                clean_target = target.replace('\\', '/').lstrip('/')
                full_target_path = '/' + clean_target
                
                logger.info(f"🔎 대상 탐색: {full_target_path}")

                # [방법 A] 직접 경로 접근 (Fast)
                try:
                    file_entry = fs_info.open(full_target_path)
                    logger.info(f"✨ 직접 접근 성공: {full_target_path}")
                    self._save_entry(file_entry, os.path.basename(clean_target))
                except Exception:
                    # [방법 B] 직접 접근 실패 시 재귀 검색 (Slow/Wildcard)
                    logger.debug(f"❓ 직접 접근 실패. '{os.path.basename(clean_target)}' 이름으로 전체 재귀 검색을 시작합니다.")
                    root_dir = fs_info.open_dir(path="/")
                    self._recursive_search(root_dir, os.path.basename(clean_target), "")
        except Exception as e:
            logger.error(f"❌ 파일시스템 처리 중 에러: {e}")

    def _recursive_search(self, directory, target_name, current_path):
        """이름 기반의 재귀적 탐색"""
        for entry in directory:
            if entry.info.name.name in [b".", b".."]: continue
            
            try:
                name = entry.info.name.name.decode('utf-8', 'replace')
                path = f"{current_path}/{name}"
                
                # 이름 매칭 확인 (대소문자 무시)
                if target_name.lower() in name.lower():
                    if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        logger.info(f"🎯 재귀 검색 발견: {path}")
                        self._save_entry(entry, name)

                # 디렉토리인 경우 깊게 진입
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    sub_dir = entry.as_directory()
                    self._recursive_search(sub_dir, target_name, path)
            except: continue

    def _save_entry(self, entry, file_name):
        """파일 메타데이터 기록 및 저장"""
        try:
            # 타임스탬프 변환 (MAC Time)
            mtime = datetime.fromtimestamp(entry.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            save_path = os.path.join(self.workspace, file_name)
            logger.debug(f"💾 추출 중... (Size: {entry.info.meta.size} bytes | M: {mtime})")
            
            with open(save_path, "wb") as f:
                offset = 0
                size = entry.info.meta.size
                while offset < size:
                    chunk = min(1024 * 1024, size - offset)
                    data = entry.read_random(offset, chunk)
                    f.write(data)
                    offset += len(data)
            logger.info(f"✅ 추출 완료: {save_path}")
        except Exception as e:
            logger.error(f"❌ 저장 실패: {e}")

# --- 실행부 ---
if __name__ == "__main__":
    # 실제 파일명에 맞춰 경로를 수정하세요.
    manager = EvidenceManager(r"C:\Users\cartc\Downloads\DFRWS_S5_BF0.E01")
    
    # 1. 전체 경로를 아는 경우 (직접 접근으로 매우 빠름)
    # 2. 파일명만 아는 경우 (재귀 검색으로 찾아냄)
    manager.extract_artifacts([
        "Windows/System32/config/SOFTWARE", 
        "Windows/System32/config/SYSTEM",
        "SAM",
        "NTUSER.DAT"
    ])