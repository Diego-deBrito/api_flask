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
            "latest": {"users_total":0, "users_disabled":0, "admins_active":0, "disabled_pct":0, "service_accounts":0}
        },
        "security": {
            "total_alerts":0, "critical_open":0, 
            "timeline":{"labels":[], "data":[]}, 
            "top_users":{}, "top_threats":{}, "severity_dist":{}
        },
        "ad_vulnerability_map": [],
        "data_exposure": {"exposure_score":0, "servers":[]},
        "governance": {
            "storage": {"stale_percent":0, "active_tb":0, "stale_tb":0}, 
            "risks": {"unresolved_sids":0}
        }
    }

    if not os.path.exists(DB_PATH):
        return response

    try:
        conn = sqlite3.connect(DB_PATH)
        
        # --- 1. AD METRICS (agregação correta) ---
        try:
            df_ad = pd.read_sql_query("SELECT * FROM ADMetrics", conn)
            if df_ad is None or df_ad.empty:
                df_ad = pd.DataFrame()
            else:
                df_ad = df_ad.fillna(0)

            if not df_ad.empty:
                # Parse de datas robusto e ordenação
                try:
                    df_ad['date_obj'] = pd.to_datetime(df_ad['date'], dayfirst=True, errors='coerce', infer_datetime_format=True)
                except:
                    df_ad['date_obj'] = pd.to_datetime(df_ad['date'], errors='coerce')

                df_ad = df_ad.sort_values('date_obj')

                # Para métricas agregadas mostramos o snapshot mais recente por domínio,
                # depois somamos esses últimos snapshots para evitar misturar domínios.
                latest_per_domain = df_ad.groupby('domain_name', as_index=False).last()

                def safe_sum(col):
                    return int(latest_per_domain[col].fillna(0).astype(float).sum()) if col in latest_per_domain.columns else 0

                total_users = safe_sum('no_of_users')
                disabled = safe_sum('no_of_disabled_users')
                admins_total = safe_sum('no_of_admin_accounts')
                # tenta aplicar redução por administradores desativados se coluna existir
                disabled_admins = safe_sum('no_of_disable_admin_accounts') if 'no_of_disable_admin_accounts' in latest_per_domain.columns else 0
                admins_active = max(0, admins_total - disabled_admins)
                service_accounts = safe_sum('no_of_service_accounts') if 'no_of_service_accounts' in latest_per_domain.columns else 0

                response['ad_health']['latest'] = {
                    "users_total": total_users,
                    "users_disabled": disabled,
                    "admins_active": admins_active,
                    "disabled_pct": round((disabled/total_users*100), 1) if total_users > 0 else 0,
                    "service_accounts": service_accounts
                }

                # Evolução: somamos por data (across domains) usando a coluna 'date_obj'
                try:
                    df_evo = df_ad.dropna(subset=['date_obj']).groupby('date_obj')[['no_of_users', 'no_of_disabled_users']].sum().reset_index()
                    df_evo = df_evo.sort_values('date_obj')
                    dates = df_evo['date_obj'].dt.strftime('%Y-%m-%d').tolist()
                    users = df_evo['no_of_users'].astype(int).tolist()
                    disabled_series = df_evo['no_of_disabled_users'].astype(int).tolist()
                except Exception:
                    dates = df_ad['date'].tolist()
                    users = df_ad['no_of_users'].astype(int).tolist() if 'no_of_users' in df_ad.columns else []
                    disabled_series = df_ad['no_of_disabled_users'].astype(int).tolist() if 'no_of_disabled_users' in df_ad.columns else []

                response['ad_health']['evolution'] = {
                    "dates": dates,
                    "users": users,
                    "disabled": disabled_series
                }
        except Exception:
            pass

        # --- 2. SECURITY ALERTS ---
        try:
            df_sec = pd.read_sql_query("SELECT * FROM SecurityAlerts", conn)
            df_sec = df_sec.fillna(0)

            if not df_sec.empty:
                # Consideramos "ativos" os alertas cujo status não esteja em estados finais
                status_series = df_sec['status'].astype(str).str.lower()
                closed_states = ['closed', 'resolved', 'dismissed', 'mitigated', 'false positive']
                active_mask = ~status_series.isin(closed_states)
                df_active = df_sec[active_mask]

                response['security']['total_alerts'] = int(len(df_active))
                # contar críticos abertos a partir do conjunto ativo
                response['security']['critical_open'] = int(len(df_active[df_active['alert_severity'].astype(str).str.lower() == 'high']))

                # Timeline baseada em alertas ativos
                try:
                    df_active['dt'] = pd.to_datetime(df_active['alert_time'], errors='coerce').dt.strftime('%Y-%m-%d')
                    daily = df_active['dt'].value_counts().sort_index()
                    response['security']['timeline'] = {"labels": daily.index.tolist(), "data": daily.values.tolist()}
                except Exception:
                    response['security']['timeline'] = {"labels": [], "data": []}

                # Top usuários e ameaças em alertas ativos
                response['security']['top_users'] = df_active['user_name'].value_counts().head(5).to_dict() if 'user_name' in df_active.columns else {}
                response['security']['top_threats'] = df_active['threat_model_name'].value_counts().head(5).to_dict() if 'threat_model_name' in df_active.columns else {}
                response['security']['severity_dist'] = df_active['alert_severity'].value_counts().to_dict() if 'alert_severity' in df_active.columns else {}

                # Contagens adicionais úteis para o dashboard (aplicadas a alertas ativos)
                try:
                    cat = df_active['alert_category'].astype(str).str.lower()
                except:
                    cat = pd.Series(['']*len(df_active))

                txt = (df_active.get('threat_model_name') or pd.Series(['']*len(df_active))).astype(str).str.lower()

                deletions = df_active[cat.str.contains('delet') | cat.str.contains('desativ') | txt.str.contains('delet') | txt.str.contains('deactiv')]
                response['security']['admin_deletions'] = int(len(deletions))

                # Acesso a ferramentas administrativas (heurística)
                admin_tool_keywords = ['psexec', 'wmic', 'dcom', 'schtask', 'system administration tools', 'remote desktop', 'winrm']
                admin_tools_mask = cat.str.contains('admin') | txt.str.contains('admin')
                for k in admin_tool_keywords:
                    admin_tools_mask = admin_tools_mask | txt.str.contains(k, case=False, na=False)
                admin_tools = df_active[admin_tools_mask]
                response['security']['admin_tool_access'] = int(len(admin_tools))

                # Indícios de ransomware
                ransomware_mask = txt.str.contains('ransom|encrypt|crypto|ransomware', case=False, na=False) | cat.str.contains('ransom', case=False, na=False)
                ransomware = df_active[ransomware_mask]
                response['security']['ransomware_indicators'] = int(len(ransomware))
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

                # Exposição de dados por servidor (heurística)
                servers = []
                for _, row in latest_fs.iterrows():
                    server = str(row.get('file_server') or row.get('file_server_domain') or 'unknown')
                    perms = int(row.get('no_of_permission_entries', 0) or 0)
                    size = float(row.get('size_of_all_files_and_folders', 0) or 0)
                    # score simples: permissões e tamanho — escala para 0-100
                    score = min(100, int((perms / 1000.0) * 50 + (size / 1000.0) * 50))
                    servers.append({"server": server, "permission_entries": perms, "size_gb": size, "exposure_score": score})

                # média de exposição
                exp_score = int(sum(s.get('exposure_score', 0) for s in servers) / len(servers)) if servers else 0
                response['data_exposure'] = {"exposure_score": exp_score, "servers": servers}

                # Mapa de vulnerabilidade do AD (por domínio)
                try:
                    vuln_list = []
                    grp = df_ad.groupby('domain_name') if not df_ad.empty else []
                    for domain, g in (grp if hasattr(grp, 'groups') else []):
                        latest_dom = g.sort_values('date').iloc[-1]
                        users_dom = int(latest_dom.get('no_of_users', 0) or 0)
                        disabled_dom = int(latest_dom.get('no_of_disabled_users', 0) or 0)
                        admins_dom = int(latest_dom.get('no_of_admin_accounts', 0) or 0)

                        disabled_pct = (disabled_dom / users_dom * 100) if users_dom>0 else 0

                        # tentativa de mapear unresolved_sids por comparação com file_server names
                        matched = df_fs[(df_fs.get('file_server')==domain) | (df_fs.get('file_server_domain')==domain)] if not df_fs.empty else pd.DataFrame()
                        unresolved = int(matched['no_of_folders_with_unresolved_sids'].sum()) if not matched.empty and 'no_of_folders_with_unresolved_sids' in matched.columns else 0

                        # score ponderado e normalizado
                        score = min(100, int(unresolved * 2 + disabled_pct * 0.6 + (admins_dom / users_dom * 100 if users_dom>0 else 0) * 0.8))
                        vuln_list.append({"domain": domain, "vuln_score": score, "disabled_pct": round(disabled_pct,1), "admins": admins_dom, "unresolved_sids": unresolved})

                    response['ad_vulnerability_map'] = sorted(vuln_list, key=lambda x: x['vuln_score'], reverse=True)
                except Exception:
                    response['ad_vulnerability_map'] = []

                    # --- 4. Verificações adicionais (Varonis / AD Health extras) ---
                    # Varonis-related indicators (procuramos colunas típicas)
                    try:
                        varonis = {}
                        varonis_events = 0
                        cols = latest_fs.columns if hasattr(latest_fs, 'columns') else []
                        if 'no_of_events' in cols:
                            varonis_events += int(latest_fs['no_of_events'].sum())
                        if 'no_of_events_on_sensitive_files' in cols:
                            varonis_events += int(latest_fs['no_of_events_on_sensitive_files'].sum())
                        if 'no_of_files_with_hits_selected_rule' in cols:
                            varonis_events += int(latest_fs['no_of_files_with_hits_selected_rule'].sum())

                        if varonis_events > 0:
                            varonis['events'] = int(varonis_events)
                            # Remediação sugerida se houver muitos eventos
                            varonis['remediation_needed'] = varonis_events > 0
                            response['varonis'] = varonis
                    except Exception:
                        pass

                    # AD vulnerabilidades (enable but stale, executive accounts)
                    try:
                        vuln = {}
                        if not df_ad.empty:
                            # soma across latest_per_domain se disponível
                            if 'no_of_enabled_but_stale_users' in latest_per_domain.columns:
                                vuln['enable_but_stale'] = int(latest_per_domain['no_of_enabled_but_stale_users'].fillna(0).astype(int).sum())
                            if 'no_of_executive_accounts' in latest_per_domain.columns:
                                vuln['executive_accounts'] = int(latest_per_domain['no_of_executive_accounts'].fillna(0).astype(int).sum())
                        if vuln:
                            response['vulnerabilities'] = vuln
                    except Exception:
                        pass

                    # Krbtgt / Kerberos password reset recommendation + ITSM integration + access ANTT + ANTT STEP meetings
                    try:
                        # krbtgt recommendation: check AD metrics or security alerts for kerberos/krbtgt mentions
                        krbtgt_flag = False
                        if not df_ad.empty and 'no_of_domains_with_a_delinquent_kerberos_account_password' in latest_per_domain.columns:
                            if int(latest_per_domain['no_of_domains_with_a_delinquent_kerberos_account_password'].fillna(0).astype(int).sum()) > 0:
                                krbtgt_flag = True

                        # check SecurityAlerts text fields for krbtgt/kerberos
                        if 'df_sec' in locals() and not df_sec.empty:
                            txt_all = (df_sec.get('threat_model_name') .fillna('').astype(str).str.lower() + ' ' + df_sec.get('alert_category', '').fillna('').astype(str).str.lower() + ' ' + df_sec.get('asset', '').fillna('').astype(str).str.lower())
                            if txt_all.str.contains('krbtgt|kerberos', case=False, na=False).any():
                                krbtgt_flag = True

                        if krbtgt_flag:
                            response.setdefault('security', {})
                            response['security']['krbtgt_reset_recommended'] = True

                        # ITSM integration: check for close_reason or patterns
                        itsm = False
                        if 'df_sec' in locals() and not df_sec.empty and 'close_reason' in df_sec.columns:
                            cr = df_sec['close_reason'].astype(str).fillna('')
                            # heuristic: tickets often contain INC, SR-, # or numeric ticket ids
                            if cr.str.contains('inc|sr-|#|ticket|jira|servicenow', case=False, na=False).any() or cr.str.strip().replace('','') != '':
                                # presence of any non-empty close_reason indicates some integration/workflow
                                if cr.str.strip().astype(bool).any():
                                    itsm = True
                        if itsm:
                            response.setdefault('security', {})
                            response['security']['itsm_integration'] = True

                        # Acesso ao Ambiente ANTT: contar ocorrências nos alertas/asset/file_server_domain
                        access_count = 0
                        if 'df_sec' in locals() and not df_sec.empty:
                            asset_cols = []
                            for c in ['asset', 'file_server_domain', 'user_name']:
                                if c in df_sec.columns:
                                    asset_cols.append(df_sec[c].astype(str).fillna('').str.lower())
                            if asset_cols:
                                combined = asset_cols[0]
                                for c in asset_cols[1:]:
                                    combined = combined + ' ' + c
                                access_count = int(combined.str.contains('antt', case=False, na=False).sum())
                        if access_count > 0:
                            response.setdefault('security', {})
                            response['security']['access_antt'] = access_count

                        # Agendamento de Reuniões "ANTT STEP": buscar menções em alertas (heurística)
                        step_count = 0
                        if 'df_sec' in locals() and not df_sec.empty:
                            txt = (df_sec.get('threat_model_name') or pd.Series(['']*len(df_sec))).astype(str).str.lower()
                            step_count = int(txt.str.contains('step|antt step|meeting|calendar', case=False, na=False).sum())
                        if step_count > 0:
                            response.setdefault('security', {})
                            response['security']['antt_step_meetings'] = step_count
                    except Exception:
                        pass
        except Exception: pass

        conn.close()
        return response

    except Exception:
        return response