# API de Métricas ANTT

Esta é uma API RESTful construída com **Python** e **Flask**, utilizando **SQLite** como banco de dados e documentada com **Swagger UI**.

## Estrutura do Projeto

- `app.py`: Aplicação principal Flask, define rotas, modelos SQLAlchemy e integrações.
- `antt_data.db`: Banco de dados SQLite populado com os dados dos arquivos CSV.
- `dashboard_data_processor.py`: Script para processar os dados do SQLite e gerar o JSON de métricas consolidadas para o Dashboard.
- `templates/dashboard.html`: Dashboard HTML com gráficos e métricas, que consome a API.
- `static/swagger.json`: Arquivo de especificação OpenAPI 2.0 para o Swagger UI.

## Acesso e Uso

A aplicação está rodando no seguinte endereço público temporário:
**https://5000-i1lf6qbattxerz6i5mhki-502932ce.manusvm.computer**

### 1. Dashboard (Interface Web)

Acesse a URL principal para visualizar o Dashboard com as métricas e gráficos consolidados:
**https://5000-i1lf6qbattxerz6i5mhki-502932ce.manusvm.computer**

### 2. Documentação da API (Swagger UI)

A documentação interativa da API, que permite testar todos os endpoints CRUD, está disponível em:
**https://5000-i1lf6qbattxerz6i5mhki-502932ce.manusvm.computer/swagger**

**Endpoints Principais:**

| Tabela | Endpoint Base | Descrição |
| :--- | :--- | :--- |
| **FileServerMetrics** | `/api/v1/fileservermetrics` | Métricas de Servidor de Arquivos (ANTT-14a01) |
| **SecurityAlerts** | `/api/v1/securityalerts` | Alertas de Segurança (Alerts) |
| **ADMetrics** | `/api/v1/admetrics` | Métricas do Active Directory (ANTT-14d01) |
| **Dashboard Data** | `/api/v1/dashboard_data` | Dados consolidados para o Dashboard |

**Métodos CRUD Suportados:**

- `GET /api/v1/{tabela}`: Lista todos os registros.
- `POST /api/v1/{tabela}`: Cria um novo registro.
- `GET /api/v1/{tabela}/{id}`: Obtém um registro específico.
- `PUT /api/v1/{tabela}/{id}`: Atualiza um registro.
- `DELETE /api/v1/{tabela}/{id}`: Deleta um registro.

### 3. Teste no Postman

Para testar a API no Postman, utilize a URL base **https://5000-i1lf6qbattxerz6i5mhki-502932ce.manusvm.computer** e os endpoints listados acima.

**Exemplo de GET (Listar Alertas):**
- **Método:** `GET`
- **URL:** `https://5000-i1lf6qbattxerz6i5mhki-502932ce.manusvm.computer/api/v1/securityalerts`

**Exemplo de POST (Criar Métrica - FileServerMetrics):**
- **Método:** `POST`
- **URL:** `https://5000-i1lf6qbattxerz6i5mhki-502932ce.manusvm.computer/api/v1/fileservermetrics`
- **Body (Raw - JSON):**
```json
{
    "date": "01.jan.2025",
    "file_server": "TEST_SERVER",
    "no_of_folders": 100,
    "no_of_files": 5000,
    "no_of_permission_entries": 1500,
    "size_of_all_files_and_folders_gb": 50.5
}
```

## Como Rodar Localmente (Opcional)

1.  **Pré-requisitos:** Python 3.x e `pip`.
2.  **Clone o projeto:** (Se fosse um repositório)
3.  **Crie e ative o ambiente virtual:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
4.  **Instale as dependências:**
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-RESTful Flask-Swagger-UI pandas
    ```
5.  **Execute o script de processamento de dados** (assumindo que os CSVs estão no diretório correto):
    ```bash
    python3 process_data.py
    ```
6.  **Inicie o servidor Flask:**
    ```bash
    export FLASK_APP=app.py
    flask run
    ```
    O servidor estará disponível em `http://127.0.0.1:5000`.
