import json
import os
from flask import Flask, jsonify, render_template, send_from_directory, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_swagger_ui import get_swaggerui_blueprint

# ==============================================================================
# 1. CONFIGURAÇÃO INICIAL
# ==============================================================================
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Configuração do Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'antt_data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'uma_chave_secreta_muito_segura'

db = SQLAlchemy(app)
api = Api(app)

# ==============================================================================
# 2. GERADOR DO ARQUIVO SWAGGER.JSON
# ==============================================================================
def generate_swagger_spec():
    # Definições de Esquemas (Models) - versão profissional e compacta
    definitions = {
        "FileServerMetric": {
            "type": "object",
            "properties": {
                "date": {"type": "string", "format": "date", "description": "Data da métrica"},
                "file_server": {"type": "string"},
                "no_of_folders": {"type": "integer"},
                "no_of_files": {"type": "integer"},
                "no_of_permission_entries": {"type": "integer"},
                "size_of_all_files_and_folders": {"type": "number", "format": "float", "description": "GB"}
            }
        },
        "SecurityAlert": {
            "type": "object",
            "properties": {
                "threat_model_name": {"type": "string"},
                "alert_time": {"type": "string", "format": "date-time"},
                "file_server_domain": {"type": "string"},
                "user_name": {"type": "string"},
                "alert_severity": {"type": "string"},
                "alert_category": {"type": "string"},
                "status": {"type": "string"}
            }
        },
        "ADMetric": {
            "type": "object",
            "properties": {
                "date": {"type": "string", "format": "date"},
                "domain_name": {"type": "string"},
                "no_of_users": {"type": "integer"},
                "no_of_disabled_users": {"type": "integer"},
                "no_of_admin_accounts": {"type": "integer"},
                "no_of_service_accounts": {"type": "integer"}
            }
        },
        "ADHealth": {
            "type": "object",
            "properties": {
                "evolution": {"type": "object", "description": "Série temporal de usuários e desabilitados"},
                "latest": {
                    "type": "object",
                    "properties": {
                        "users_total": {"type": "integer"},
                        "users_disabled": {"type": "integer"},
                        "admins_active": {"type": "integer"},
                        "disabled_pct": {"type": "number"},
                        "service_accounts": {"type": "integer"}
                    }
                }
            }
        },
        "SecurityData": {
            "type": "object",
            "properties": {
                "total_alerts": {"type": "integer"},
                "critical_open": {"type": "integer"},
                "admin_deletions": {"type": "integer"},
                "admin_tool_access": {"type": "integer"},
                "ransomware_indicators": {"type": "integer"},
                "krbtgt_reset_recommended": {"type": "boolean"},
                "itsm_integration": {"type": "boolean"},
                "access_antt": {"type": "integer"},
                "antt_step_meetings": {"type": "integer"},
                "timeline": {"type": "object"},
                "top_users": {"type": "object"},
                "top_threats": {"type": "object"},
                "severity_dist": {"type": "object"}
            }
        },
        "DashboardData": {
            "type": "object",
            "properties": {
                "ad_health": {"$ref": "#/definitions/ADHealth"},
                "security": {"$ref": "#/definitions/SecurityData"},
                "vulnerabilities": {"type": "object", "properties": {"enable_but_stale": {"type": "integer"}, "executive_accounts": {"type": "integer"}}},
                "varonis": {"type": "object", "properties": {"events": {"type": "integer"}, "remediation_needed": {"type": "boolean"}}},
                "ad_vulnerability_map": {"type": "array", "items": {"type":"object"}},
                "data_exposure": {"type": "object"},
                "governance": {"type": "object"}
            }
        }
    }

    # Paths com descrições, tags e resposta de exemplo
    paths = {
        "/api/v1/fileservermetrics": {
            "get": {
                "tags": ["FileServerMetrics"],
                "summary": "Retorna métricas de storage por servidor (últimos snapshots)",
                "parameters": [
                    {"name":"file_server","in":"query","required":False,"type":"string","description":"Filtra por nome do servidor"},
                    {"name":"date_from","in":"query","required":False,"type":"string","format":"date","description":"Data inicial (YYYY-MM-DD)"},
                    {"name":"date_to","in":"query","required":False,"type":"string","format":"date","description":"Data final (YYYY-MM-DD)"},
                    {"name":"page","in":"query","required":False,"type":"integer","format":"int32","description":"Página (para paginação)"},
                    {"name":"page_size","in":"query","required":False,"type":"integer","format":"int32","description":"Tamanho da página"}
                ],
                "responses": {
                    "200": {
                        "description": "Lista de métricas",
                        "schema": {"type": "array", "items": {"$ref": "#/definitions/FileServerMetric"}},
                        "examples": {
                            "application/json": [
                                {
                                    "date": "2025-01-01",
                                    "file_server": "SRVB403",
                                    "no_of_folders": 951533,
                                    "no_of_files": 8635629,
                                    "no_of_permission_entries": 2975571,
                                    "size_of_all_files_and_folders": 17153
                                }
                            ]
                        }
                    }
                }
            }
        },
        "/api/v1/securityalerts": {
            "get": {
                "tags": ["SecurityAlerts"],
                "summary": "Lista alertas (filtragem disponível pela API)",
                "parameters": [
                    {"name":"status","in":"query","required":False,"type":"string","description":"Filtra por status (ex: Open, Closed)"},
                    {"name":"severity","in":"query","required":False,"type":"string","description":"Filtra por severidade (Low, Medium, High)"},
                    {"name":"date_from","in":"query","required":False,"type":"string","format":"date","description":"Data inicial (YYYY-MM-DD)"},
                    {"name":"date_to","in":"query","required":False,"type":"string","format":"date","description":"Data final (YYYY-MM-DD)"},
                    {"name":"page","in":"query","required":False,"type":"integer","format":"int32","description":"Página (para paginação)"},
                    {"name":"page_size","in":"query","required":False,"type":"integer","format":"int32","description":"Tamanho da página"}
                ],
                "responses": {
                    "200": {
                        "description": "Lista de alertas",
                        "schema": {"type": "array", "items": {"$ref": "#/definitions/SecurityAlert"}},
                        "examples": {
                            "application/json": [
                                {
                                    "threat_model_name": "Activity performed by Admin user from a non-corporate IP address",
                                    "alert_time": "2025-04-14T15:31:00",
                                    "file_server_domain": "Exchange Online2",
                                    "user_name": "Márcia Ketlen Andrade Florêncio (antt.gov.br)",
                                    "alert_severity": "Medium",
                                    "alert_category": "Exploitation",
                                    "status": "Open"
                                }
                            ]
                        }
                    }
                }
            }
        },
        "/api/v1/admetrics": {
            "get": {
                "tags": ["ADMetrics"],
                "summary": "Métricas do Active Directory por domínio",
                "responses": {"200": {"description": "Lista de métricas AD", "schema": {"type": "array", "items": {"$ref": "#/definitions/ADMetric"}}}}
            }
        },
        "/api/v1/dashboard_data": {
            "get": {
                "tags": ["Dashboard"],
                "summary": "Dados agregados para o dashboard executivo",
                "description": "Retorna KPIs e séries temporais usadas pelo dashboard: usuários, admins, contas de serviço, alertas ativos, mapa de vulnerabilidade e exposição de dados.",
                "responses": {"200": {"description": "Objeto com dados do dashboard", "schema": {"$ref": "#/definitions/DashboardData"}}}
            }
        }
    }

    swagger_spec = {
        "swagger": "2.0",
        "info": {
            "title": "API de Métricas ANTT",
            "description": "API RESTful para acesso aos dados de métricas de segurança e infraestrutura. Fornece endpoints para file-server metrics, AD metrics, alerts e dados agregados para dashboard.",
            "version": "1.1.0",
            "contact": {"name": "Equipe Segurança ANTT", "email": "seguranca@antt.gov.br"},
            "license": {"name": "Proprietary", "url": "https://www.antt.gov.br"}
        },
        "host": "127.0.0.1:5000",
        "basePath": "/",
        "schemes": ["http"],
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "paths": paths,
        "definitions": definitions,
        "tags": [
            {"name":"Dashboard","description":"Endpoints para alimentar o dashboard executivo."},
            {"name":"ADMetrics","description":"Métricas do Active Directory por domínio."},
            {"name":"SecurityAlerts","description":"Alertas de segurança detectados nas fontes integradas."},
            {"name":"FileServerMetrics","description":"Métricas de servidores de ficheiros e exposição de dados."}
        ]
    }

    # Salvar na pasta 'static' que o Flask consegue ler
    static_folder = os.path.join(basedir, 'static')
    os.makedirs(static_folder, exist_ok=True)
    output_path = os.path.join(static_folder, 'swagger.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(swagger_spec, f, indent=2, ensure_ascii=False)

    print(f"📄 Swagger JSON profissional gerado em: {output_path}")

# ==============================================================================
# 3. MODELOS DE DADOS (SQLAlchemy)
# ==============================================================================
class FileServerMetrics(db.Model):
    __tablename__ = 'FileServerMetrics'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Text)
    file_server = db.Column(db.Text)
    no_of_folders = db.Column(db.Integer)
    no_of_files = db.Column(db.Integer)
    no_of_permission_entries = db.Column(db.Integer)
    size_of_all_files_and_folders = db.Column(db.Float)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date,
            'file_server': self.file_server,
            'no_of_folders': self.no_of_folders,
            'no_of_files': self.no_of_files,
            'no_of_permission_entries': self.no_of_permission_entries,
            'size_of_all_files_and_folders_gb': self.size_of_all_files_and_folders,
        }

class SecurityAlerts(db.Model):
    __tablename__ = 'SecurityAlerts'
    id = db.Column(db.Integer, primary_key=True)
    threat_model_name = db.Column(db.Text)
    alert_time = db.Column(db.Text)
    file_server_domain = db.Column(db.Text)
    user_name = db.Column(db.Text)
    alert_severity = db.Column(db.Text)
    alert_category = db.Column(db.Text)
    status = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'threat_model_name': self.threat_model_name,
            'alert_time': self.alert_time,
            'file_server_domain': self.file_server_domain,
            'user_name': self.user_name,
            'alert_severity': self.alert_severity,
            'alert_category': self.alert_category,
            'status': self.status,
        }

class ADMetrics(db.Model):
    __tablename__ = 'ADMetrics'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Text)
    domain_name = db.Column(db.Text)
    no_of_groups = db.Column(db.Integer)
    no_of_users = db.Column(db.Integer)
    no_of_computer_accounts = db.Column(db.Integer)
    no_of_admin_accounts = db.Column(db.Integer)
    no_of_disabled_users = db.Column(db.Integer)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date,
            'domain_name': self.domain_name,
            'no_of_groups': self.no_of_groups,
            'no_of_users': self.no_of_users,
            'no_of_computer_accounts': self.no_of_computer_accounts,
            'no_of_admin_accounts': self.no_of_admin_accounts,
            'no_of_disabled_users': self.no_of_disabled_users,
        }

# ==============================================================================
# 4. RECURSOS (Flask-RESTful)
# ==============================================================================
class FileServerMetricsList(Resource):
    def get(self):
        metrics = FileServerMetrics.query.all()
        return jsonify([m.to_dict() for m in metrics])

class FileServerMetricsResource(Resource):
    def get(self, id):
        metric = FileServerMetrics.query.get_or_404(id)
        return metric.to_dict()

class SecurityAlertsList(Resource):
    def get(self):
        alerts = SecurityAlerts.query.all()
        return jsonify([a.to_dict() for a in alerts])

class ADMetricsList(Resource):
    def get(self):
        metrics = ADMetrics.query.all()
        return jsonify([m.to_dict() for m in metrics])

# Adiciona os recursos à API
api.add_resource(FileServerMetricsList, '/api/v1/fileservermetrics')
api.add_resource(FileServerMetricsResource, '/api/v1/fileservermetrics/<int:id>')
api.add_resource(SecurityAlertsList, '/api/v1/securityalerts')
api.add_resource(ADMetricsList, '/api/v1/admetrics')

# ==============================================================================
# 5. CONFIGURAÇÃO DO SWAGGER UI E DASHBOARD
# ==============================================================================

# Configura o Swagger UI para ler da pasta 'static'
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json' 

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={'app_name': "API de Métricas ANTT"}
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Rota opcional para processar dados do dashboard
try:
    from dashboard_data_processor import get_dashboard_data
    class DashboardData(Resource):
        def get(self):
            data = get_dashboard_data()
            return jsonify(data)
    api.add_resource(DashboardData, '/api/v1/dashboard_data')
except ImportError:
    print("⚠️ Aviso: dashboard_data_processor.py não encontrado. Rota de dashboard desativada.")

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# ==============================================================================
# 6. EXECUÇÃO PRINCIPAL (AQUI ESTAVA O ERRO)
# ==============================================================================
if __name__ == '__main__':
    # 1. Gera o arquivo JSON do Swagger (Agora dentro da pasta static)
    generate_swagger_spec()
    
    # 2. Garante pastas necessárias
    os.makedirs(os.path.join(basedir, 'templates'), exist_ok=True)
    
    # 3. Inicializa o banco (se necessário)
    with app.app_context():
        # db.create_all() # Descomente se precisar criar tabelas do zero
        pass

    print("🚀 Servidor rodando!")
    print(f"👉 Swagger UI: http://127.0.0.1:5000{SWAGGER_URL}")
    print(f"👉 Dashboard:  http://127.0.0.1:5000/")
    
    # 4. Roda o servidor
    app.run(debug=True)