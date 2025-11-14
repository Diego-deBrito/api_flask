import sqlite3, json, os
DB='antt_data.db'
if not os.path.exists(DB):
    print(json.dumps({'error':'db not found: '+DB}))
else:
    conn=sqlite3.connect(DB)
    cur=conn.cursor()
    tables=[r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';").fetchall()]
    out={}
    for t in tables:
        cols=[c[1] for c in cur.execute(f"PRAGMA table_info('{t}')").fetchall()]
        try:
            rows=[dict(zip(cols,row)) for row in cur.execute(f"SELECT * FROM '{t}' LIMIT 3").fetchall()]
        except Exception as e:
            rows=[{'error':str(e)}]
        try:
            cnt=cur.execute(f"SELECT COUNT(*) FROM '{t}'").fetchone()[0]
        except:
            cnt=None
        out[t]={'columns':cols,'sample':rows,'count':cnt}
    conn.close()
    print(json.dumps(out,indent=2,ensure_ascii=False))
