import sqlite3
import os
import shutil
from datetime import datetime

class EdgeHistoryParser:
    def parse(self, file_path):
        """Extract browsing history by reading the SQLite DB"""
        results = []
        if not os.path.exists(file_path):
            return results

        # Since the DB might be in use, create a temporary copy for analysis
        temp_db = file_path + "_temp"
        shutil.copy2(file_path, temp_db)

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            # Query to convert Edge/Chrome timestamps to readable datetime
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
            print(f"[ERROR] Error parsing Edge history: {e}")
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        
        return results