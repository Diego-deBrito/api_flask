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
    # Definições de Esquemas (Models)
    definitions = {
        "FileServerMetric": {
            "type": "object",
            "properties": {
                "id": {"type": "integer", "format": "int64", "readOnly": True},
                "date": {"type": "string", "description": "Data da métrica"},
                "file_server": {"type": "string"},
                "no_of_folders": {"type": "integer"},
                "no_of_files": {"type": "integer"},
                "no_of_permission_entries": {"type": "integer"},
                "size_of_all_files_and_folders_gb": {"type": "number", "format": "float"}
            },
            "required": ["date", "file_server", "no_of_folders", "no_of_files"]
        },
        "SecurityAlert": {
            "type": "object",
            "properties": {
                "id": {"type": "integer", "format": "int64", "readOnly": True},
                "threat_model_name": {"type": "string"},
                "alert_time": {"type": "string"},
                "alert_severity": {"type": "string"},
                "status": {"type": "string"}
            }
        },
        "ADMetric": {
            "type": "object",
            "properties": {
                "id": {"type": "integer", "format": "int64", "readOnly": True},
                "domain_name": {"type": "string"},
                "no_of_users": {"type": "integer"},
                "no_of_disabled_users": {"type": "integer"}
            }
        }
    }

    # Definições de Caminhos (Paths) - Simplificado para o exemplo
    # (Você pode manter o seu dicionário 'paths' gigante aqui se quiser)
    paths = {
        "/api/v1/fileservermetrics": {
            "get": {
                "tags": ["FileServerMetrics"],
                "summary": "Lista todas as métricas",
                "responses": { "200": { "description": "Sucesso", "schema": {"type": "array", "items": {"$ref": "#/definitions/FileServerMetric"}} } }
            }
        },
        "/api/v1/securityalerts": {
            "get": {
                "tags": ["SecurityAlerts"],
                "summary": "Lista alertas",
                "responses": { "200": { "description": "Sucesso", "schema": {"type": "array", "items": {"$ref": "#/definitions/SecurityAlert"}} } }
            }
        },
        "/api/v1/admetrics": {
             "get": {
                "tags": ["ADMetrics"],
                "summary": "Lista métricas AD",
                "responses": { "200": { "description": "Sucesso", "schema": {"type": "array", "items": {"$ref": "#/definitions/ADMetric"}} } }
            }
        }
    }

    swagger_spec = {
        "swagger": "2.0",
        "info": {
            "title": "API de Métricas ANTT",
            "description": "API RESTful para acesso aos dados de métricas de segurança e infraestrutura.",
            "version": "1.0.0"
        },
        "basePath": "/",
        "schemes": ["http"],
        "paths": paths,
        "definitions": definitions
    }

    # Salvar na pasta 'static' que o Flask consegue ler
    static_folder = os.path.join(basedir, 'static')
    os.makedirs(static_folder, exist_ok=True)
    
    output_path = os.path.join(static_folder, 'swagger.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(swagger_spec, f, indent=4)
    
    print(f"📄 Swagger JSON gerado em: {output_path}")

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