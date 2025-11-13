import pandas as pd
import sqlite3
import os

# Definir o nome do banco de dados
DB_NAME = 'antt_data.db'
# Definir o diretório de upload
UPLOAD_DIR = '/home/ubuntu/upload'
# Definir o diretório do projeto
PROJECT_DIR = '/home/ubuntu/flask_api_project'

# Mapeamento de arquivos para nomes de tabelas
file_to_table = {
    'ANTT-14a01(1).csv': 'FileServerMetrics',
    'Alerts_20250714_192505567_0.csv': 'SecurityAlerts',
    'ANTT-14d01.csv': 'ADMetrics'
}

def clean_column_name(col):
    # Remove caracteres especiais e substitui espaços por underscores
    col = col.replace('﻿', '').strip()
    col = col.replace(' ', '_').replace('.', '').replace('/', '_').replace('-', '_').replace('&', 'and').replace('(', '').replace(')', '').replace(':', '').replace('__', '_')
    # Remove GB do final
    if col.endswith('_GB'):
        col = col[:-3]
    # Converte para minúsculas
    return col.lower()

def process_csv_to_sqlite(file_path, table_name):
    print(f"Processando {file_path} para a tabela {table_name}...")
    try:
        # Tenta ler o CSV com diferentes encodings
        try:
            df = pd.read_csv(file_path, encoding='utf-8')
        except UnicodeDecodeError:
            df = pd.read_csv(file_path, encoding='latin1')
        
        # Limpar nomes das colunas
        df.columns = [clean_column_name(col) for col in df.columns]
        
        # Conectar ao banco de dados
        conn = sqlite3.connect(os.path.join(PROJECT_DIR, DB_NAME))
        
        # Inserir dados no SQLite. 'if_exists='replace'' para garantir um esquema limpo
        # Usamos 'dtype' para tentar inferir os tipos de dados do SQLite
        df.to_sql(table_name, conn, if_exists='replace', index=False)
        
        # Obter o esquema da tabela para verificação
        cursor = conn.execute(f"PRAGMA table_info({table_name})")
        schema = cursor.fetchall()
        print(f"Esquema da tabela {table_name}:")
        for col in schema:
            print(f"  {col[1]} ({col[2]})")
            
        conn.close()
        print(f"Processamento de {file_path} concluído.")
        return True
    except Exception as e:
        print(f"Erro ao processar {file_path}: {e}")
        return False

def main():
    # Criar o diretório do projeto se não existir
    if not os.path.exists(PROJECT_DIR):
        os.makedirs(PROJECT_DIR)
        
    all_successful = True
    for file_name, table_name in file_to_table.items():
        file_path = os.path.join(UPLOAD_DIR, file_name)
        if not os.path.exists(file_path):
            print(f"Arquivo não encontrado: {file_path}")
            all_successful = False
            continue
        
        if not process_csv_to_sqlite(file_path, table_name):
            all_successful = False
            
    if all_successful:
        print("Todos os arquivos CSV foram processados e o banco de dados foi criado com sucesso.")
    else:
        print("Ocorreram erros durante o processamento dos arquivos CSV.")

if __name__ == '__main__':
    main()
