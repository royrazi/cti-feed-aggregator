from database import get_db_connection

def run_analytics():
    """שולף ומציג דוח אנליטיקה מפורט מטבלת ה-iocs"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # 1. סך הכל אינדיקטורים שנשמרו
                cursor.execute("SELECT COUNT(*) FROM iocs;")
                total_iocs = cursor.fetchone()[0]

                # 2. ממוצע ציון סיכון (Threat Score)
                cursor.execute("SELECT AVG(score) FROM iocs;")
                avg_score = cursor.fetchone()[0] or 0

                # 3. טופ 5 מדינות תוקפות (Group By + Order By)
                cursor.execute("""
                    SELECT country, COUNT(*) as count 
                    FROM iocs 
                    WHERE country IS NOT NULL AND country != 'Unknown'
                    GROUP BY country 
                    ORDER BY count DESC 
                    LIMIT 5;
                """)
                top_countries = cursor.fetchall()

                # הדפסת הדוח המעוצב לטרמינל
                print("\n========================================")
                print("       CTI SYSTEM ANALYTICS REPORT      ")
                print("========================================")
                print(f" Total Indicators Stored : {total_iocs}")
                print(f" Average Threat Score    : {avg_score:.2f} / 100")
                print("----------------------------------------")
                print(" Top 5 Threat Origin Countries:")
                if top_countries:
                    for country, count in top_countries:
                        print(f"   - {country}: {count} threats")
                else:
                    print("   No country data available yet.")
                print("========================================\n")

    except Exception as e:
        print(f"Error running analytics: {e}")

if __name__ == "__main__":
    run_analytics()