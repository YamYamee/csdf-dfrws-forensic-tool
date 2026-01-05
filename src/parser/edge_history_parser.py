import sqlite3
import os
import shutil
from datetime import datetime

class EdgeHistoryParser:
    def parse(self, file_path):
        """SQLite DB를 읽어 방문 기록 추출"""
        results = []
        if not os.path.exists(file_path):
            return results

        # DB가 사용 중일 수 있으므로 임시 복사본 생성 후 분석
        temp_db = file_path + "_temp"
        shutil.copy2(file_path, temp_db)

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            # Edge/Chrome 타임스탬프를 읽기 가능한 시간으로 변환하는 쿼리
            query = """
            SELECT 
                datetime(last_visit_time / 1000000 + (strftime('%s', '1601-01-01')), 'unixepoch', 'localtime') as visit_time,
                title, 
                url, 
                visit_count
            FROM urls 
            WHERE url LIKE 'http%'
            ORDER BY last_visit_time DESC
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                results.append({
                    'time': row[0],
                    'title': row[1],
                    'url': row[2],
                    'count': row[3]
                })
            conn.close()
        except Exception as e:
            print(f"[ERROR] Edge 파싱 중 오류: {e}")
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        
        return results