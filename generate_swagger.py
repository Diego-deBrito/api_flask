import json
import os

def generate_swagger_spec():
    # Definições de Esquemas (Models)
    definitions = {
        "FileServerMetric": {
            "type": "object",
            "properties": {
                "id": {"type": "integer", "format": "int64", "readOnly": True},
                "date": {"type": "string", "description": "Data da métrica (ex: 01.jan.2024)"},
                "file_server": {"type": "string", "description": "Nome do servidor de arquivos"},
                "no_of_folders": {"type": "integer"},
                "no_of_files": {"type": "integer"},
                "no_of_permission_entries": {"type": "integer"},
                "size_of_all_files_and_folders_gb": {"type": "number", "format": "float", "description": "Tamanho total em GB"}
                # Adicionar mais propriedades conforme necessário
            },
            "required": ["date", "file_server", "no_of_folders", "no_of_files", "no_of_permission_entries", "size_of_all_files_and_folders_gb"]
        },
        "SecurityAlert": {
            "type": "object",
            "properties": {
                "id": {"type": "integer", "format": "int64", "readOnly": True},
                "threat_model_name": {"type": "string"},
                "alert_time": {"type": "string", "format": "date-time"},
                "file_server_domain": {"type": "string"},
                "user_name": {"type": "string"},
                "alert_severity": {"type": "string"},
                "alert_category": {"type": "string"},
                "status": {"type": "string"}
                # Adicionar mais propriedades conforme necessário
            },
            "required": ["threat_model_name", "alert_time", "file_server_domain", "user_name", "alert_severity", "alert_category", "status"]
        },
        "ADMetric": {
            "type": "object",
            "properties": {
                "id": {"type": "integer", "format": "int64", "readOnly": True},
                "date": {"type": "string", "description": "Data da métrica (ex: 01.jan.2024)"},
                "domain_name": {"type": "string"},
                "no_of_groups": {"type": "integer"},
                "no_of_users": {"type": "integer"},
                "no_of_computer_accounts": {"type": "integer"},
                "no_of_admin_accounts": {"type": "integer"},
                "no_of_disabled_users": {"type": "integer"}
                # Adicionar mais propriedades conforme necessário
            },
            "required": ["date", "domain_name", "no_of_groups", "no_of_users", "no_of_computer_accounts", "no_of_admin_accounts", "no_of_disabled_users"]
        }
    }

    # Definições de Caminhos (Paths)
    paths = {
        "/api/v1/fileservermetrics": {
            "get": {
                "tags": ["FileServerMetrics"],
                "summary": "Lista todas as métricas de servidor de arquivos",
                "responses": {
                    "200": {
                        "description": "Lista de métricas",
                        "schema": {"type": "array", "items": {"$ref": "#/definitions/FileServerMetric"}}
                    }
                }
            },
            "post": {
                "tags": ["FileServerMetrics"],
                "summary": "Cria uma nova métrica de servidor de arquivos",
                "parameters": [{
                    "in": "body",
                    "name": "body",
                    "description": "Objeto de métrica a ser adicionado",
                    "required": True,
                    "schema": {"$ref": "#/definitions/FileServerMetric"}
                }],
                "responses": {
                    "201": {"description": "Métrica criada", "schema": {"$ref": "#/definitions/FileServerMetric"}},
                    "400": {"description": "Requisição inválida"}
                }
            }
        },
        "/api/v1/fileservermetrics/{id}": {
            "get": {
                "tags": ["FileServerMetrics"],
                "summary": "Obtém uma métrica específica por ID",
                "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
                "responses": {
                    "200": {"description": "Métrica encontrada", "schema": {"$ref": "#/definitions/FileServerMetric"}},
                    "404": {"description": "Métrica não encontrada"}
                }
            },
            "put": {
                "tags": ["FileServerMetrics"],
                "summary": "Atualiza uma métrica existente por ID",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "type": "integer"},
                    {"in": "body", "name": "body", "description": "Objeto de métrica com campos a serem atualizados", "required": True, "schema": {"$ref": "#/definitions/FileServerMetric"}}
                ],
                "responses": {
                    "200": {"description": "Métrica atualizada", "schema": {"$ref": "#/definitions/FileServerMetric"}},
                    "404": {"description": "Métrica não encontrada"}
                }
            },
            "delete": {
                "tags": ["FileServerMetrics"],
                "summary": "Deleta uma métrica por ID",
                "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
                "responses": {
                    "204": {"description": "Métrica deletada com sucesso"},
                    "404": {"description": "Métrica não encontrada"}
                }
            }
        },
        # --- SecurityAlerts ---
        "/api/v1/securityalerts": {
            "get": {
                "tags": ["SecurityAlerts"],
                "summary": "Lista todos os alertas de segurança",
                "responses": {
                    "200": {
                        "description": "Lista de alertas",
                        "schema": {"type": "array", "items": {"$ref": "#/definitions/SecurityAlert"}}
                    }
                }
            },
            "post": {
                "tags": ["SecurityAlerts"],
                "summary": "Cria um novo alerta de segurança",
                "parameters": [{
                    "in": "body",
                    "name": "body",
                    "description": "Objeto de alerta a ser adicionado",
                    "required": True,
                    "schema": {"$ref": "#/definitions/SecurityAlert"}
                }],
                "responses": {
                    "201": {"description": "Alerta criado", "schema": {"$ref": "#/definitions/SecurityAlert"}},
                    "400": {"description": "Requisição inválida"}
                }
            }
        },
        "/api/v1/securityalerts/{id}": {
            "get": {
                "tags": ["SecurityAlerts"],
                "summary": "Obtém um alerta específico por ID",
                "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
                "responses": {
                    "200": {"description": "Alerta encontrado", "schema": {"$ref": "#/definitions/SecurityAlert"}},
                    "404": {"description": "Alerta não encontrado"}
                }
            },
            "put": {
                "tags": ["SecurityAlerts"],
                "summary": "Atualiza um alerta existente por ID",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "type": "integer"},
                    {"in": "body", "name": "body", "description": "Objeto de alerta com campos a serem atualizados", "required": True, "schema": {"$ref": "#/definitions/SecurityAlert"}}
                ],
                "responses": {
                    "200": {"description": "Alerta atualizado", "schema": {"$ref": "#/definitions/SecurityAlert"}},
                    "404": {"description": "Alerta não encontrado"}
                }
            },
            "delete": {
                "tags": ["SecurityAlerts"],
                "summary": "Deleta um alerta por ID",
                "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
                "responses": {
                    "204": {"description": "Alerta deletado com sucesso"},
                    "404": {"description": "Alerta não encontrado"}
                }
            }
        },
        # --- ADMetrics ---
        "/api/v1/admetrics": {
            "get": {
                "tags": ["ADMetrics"],
                "summary": "Lista todas as métricas do Active Directory",
                "responses": {
                    "200": {
                        "description": "Lista de métricas",
                        "schema": {"type": "array", "items": {"$ref": "#/definitions/ADMetric"}}
                    }
                }
            },
            "post": {
                "tags": ["ADMetrics"],
                "summary": "Cria uma nova métrica do Active Directory",
                "parameters": [{
                    "in": "body",
                    "name": "body",
                    "description": "Objeto de métrica a ser adicionado",
                    "required": True,
                    "schema": {"$ref": "#/definitions/ADMetric"}
                }],
                "responses": {
                    "201": {"description": "Métrica criada", "schema": {"$ref": "#/definitions/ADMetric"}},
                    "400": {"description": "Requisição inválida"}
                }
            }
        },
        "/api/v1/admetrics/{id}": {
            "get": {
                "tags": ["ADMetrics"],
                "summary": "Obtém uma métrica específica por ID",
                "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
                "responses": {
                    "200": {"description": "Métrica encontrada", "schema": {"$ref": "#/definitions/ADMetric"}},
                    "404": {"description": "Métrica não encontrada"}
                }
            },
            "put": {
                "tags": ["ADMetrics"],
                "summary": "Atualiza uma métrica existente por ID",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "type": "integer"},
                    {"in": "body", "name": "body", "description": "Objeto de métrica com campos a serem atualizados", "required": True, "schema": {"$ref": "#/definitions/ADMetric"}}
                ],
                "responses": {
                    "200": {"description": "Métrica atualizada", "schema": {"$ref": "#/definitions/ADMetric"}},
                    "404": {"description": "Métrica não encontrada"}
                }
            },
            "delete": {
                "tags": ["ADMetrics"],
                "summary": "Deleta uma métrica por ID",
                "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
                "responses": {
                    "204": {"description": "Métrica deletada com sucesso"},
                    "404": {"description": "Métrica não encontrada"}
                }
            }
        }
    }

    # Estrutura principal do Swagger
    swagger_spec = {
        "swagger": "2.0",
        "info": {
            "title": "API de Métricas ANTT",
            "description": "API RESTful para acesso aos dados de métricas de segurança e infraestrutura da ANTT. Inclui métodos CRUD completos para as tabelas FileServerMetrics, SecurityAlerts e ADMetrics.",
            "version": "1.0.0"
        },
        "host": "localhost:5000", # Será atualizado para o host real na execução
        "basePath": "/",
        "schemes": ["http"],
        "paths": paths,
        "definitions": definitions
    }

    # Salvar o arquivo swagger.json
    output_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'swagger.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(swagger_spec, f, indent=4)
    
    print(f"Arquivo swagger.json gerado em: {output_path}")

if __name__ == '__main__':
    generate_swagger_spec()
