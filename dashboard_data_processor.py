import sqlite3
import pandas as pd
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'antt_data.db')

def get_dashboard_data():
    # Estrutura padrão para evitar erros no front-end
    response = {
        "ad_health": {
            "evolution": {"dates":[], "users":[], "disabled":[]}, 
            "latest": {"users_total":0, "users_disabled":0, "admins_active":0, "disabled_pct":0}
        },
        "security": {
            "total_alerts":0, "critical_open":0, 
            "timeline":{"labels":[], "data":[]}, 
            "top_users":{}, "top_threats":{}, "severity_dist":{}
        },
        "governance": {
            "storage": {"stale_percent":0, "active_tb":0, "stale_tb":0}, 
            "risks": {"unresolved_sids":0}
        }
    }

    if not os.path.exists(DB_PATH):
        return response

    try:
        conn = sqlite3.connect(DB_PATH)
        
        # --- 1. AD METRICS (CORREÇÃO DO ERRO NaN) ---
        try:
            df_ad = pd.read_sql_query("SELECT * FROM ADMetrics", conn)
            df_ad = df_ad.fillna(0)  # <--- AQUI ESTÁ A CORREÇÃO MÁGICA

            if not df_ad.empty:
                # Tenta ordenar por data
                try:
                    df_ad['date_obj'] = pd.to_datetime(df_ad['date'], dayfirst=True, errors='coerce')
                    df_ad = df_ad.sort_values('date_obj')
                except: pass

                latest = df_ad.iloc[-1]
                
                # Conversão segura
                total_users = int(latest['no_of_users'])
                disabled = int(latest['no_of_disabled_users'])
                admins_active = int(latest['no_of_admin_accounts']) - int(latest.get('no_of_disable_admin_accounts', 0))

                response['ad_health']['latest'] = {
                    "users_total": total_users,
                    "users_disabled": disabled,
                    "admins_active": admins_active,
                    "disabled_pct": round((disabled/total_users*100), 1) if total_users > 0 else 0
                }

                # Evolução
                df_evo = df_ad.groupby('date', sort=False)[['no_of_users', 'no_of_disabled_users']].sum().reset_index()
                # Ordenação cronológica para o gráfico
                try:
                   df_evo['date_obj'] = pd.to_datetime(df_evo['date'], dayfirst=True, errors='coerce')
                   df_evo = df_evo.sort_values('date_obj')
                except: pass

                response['ad_health']['evolution'] = {
                    "dates": df_evo['date'].tolist(),
                    "users": df_evo['no_of_users'].tolist(),
                    "disabled": df_evo['no_of_disabled_users'].tolist()
                }
        except Exception: pass

        # --- 2. SECURITY ALERTS ---
        try:
            df_sec = pd.read_sql_query("SELECT * FROM SecurityAlerts", conn)
            df_sec = df_sec.fillna(0)

            if not df_sec.empty:
                response['security']['total_alerts'] = len(df_sec)
                response['security']['critical_open'] = len(df_sec[(df_sec['alert_severity'] == 'High') & (df_sec['status'] == 'Open')])
                
                df_sec['dt'] = pd.to_datetime(df_sec['alert_time']).dt.strftime('%Y-%m-%d')
                daily = df_sec['dt'].value_counts().sort_index()
                response['security']['timeline'] = {"labels": daily.index.tolist(), "data": daily.values.tolist()}
                
                response['security']['top_users'] = df_sec['user_name'].value_counts().head(5).to_dict()
                response['security']['top_threats'] = df_sec['threat_model_name'].value_counts().head(5).to_dict()
                response['security']['severity_dist'] = df_sec['alert_severity'].value_counts().to_dict()
        except Exception: pass

        # --- 3. GOVERNANCE ---
        try:
            df_fs = pd.read_sql_query("SELECT * FROM FileServerMetrics", conn)
            df_fs = df_fs.fillna(0)

            if not df_fs.empty:
                latest_fs = df_fs.sort_values('date').groupby('file_server').tail(1)
                tot = latest_fs['size_of_all_files_and_folders'].sum()
                stale = latest_fs['size_of_folders_with_stale_data'].sum()
                sids = latest_fs['no_of_folders_with_unresolved_sids'].sum()

                response['governance']['storage'] = {
                    "total_tb": round(tot/1024, 2),
                    "stale_tb": round(stale/1024, 2),
                    "active_tb": round((tot-stale)/1024, 2),
                    "stale_percent": round((stale/tot*100), 1) if tot > 0 else 0
                }
                response['governance']['risks']['unresolved_sids'] = int(sids)
        except Exception: pass

        conn.close()
        return response

    except Exception:
        return response