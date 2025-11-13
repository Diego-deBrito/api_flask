import sqlite3
import os
import pandas as pd

# Tenta achar o banco na mesma pasta do script
DB_NAME = 'antt_data.db'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, DB_NAME)

print(f"📂 Procurando banco de dados em: {DB_PATH}")

if not os.path.exists(DB_PATH):
    print(f"❌ ERRO: O arquivo '{DB_NAME}' NÃO foi encontrado nesta pasta!")
    print("   -> Verifique se você moveu o arquivo .db para dentro de:", BASE_DIR)
else:
    print(f"✅ Banco de dados encontrado! Analisando conteúdo...\n")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 1. Listar todas as tabelas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        if not tables:
            print("⚠️ O banco existe, mas NÃO TEM TABELAS (está vazio).")
            print("   -> Você precisa rodar o script de carga de dados primeiro.")
        else:
            print(f"📊 Tabelas encontradas: {len(tables)}")
            for table in tables:
                table_name = table[0]
                print(f"\n   ➡️  Tabela: {table_name}")
                
                # 2. Contar linhas
                count = pd.read_sql_query(f"SELECT COUNT(*) as qtd FROM '{table_name}'", conn)
                qtd = count.iloc[0]['qtd']
                print(f"       Registros: {qtd}")
                
                # 3. Listar colunas
                df_head = pd.read_sql_query(f"SELECT * FROM '{table_name}' LIMIT 1", conn)
                colunas = list(df_head.columns)
                print(f"       Colunas: {colunas}")

        conn.close()
        
    except Exception as e:
        print(f"❌ Erro ao ler o banco: {e}")

print("\n🏁 Fim do diagnóstico.")