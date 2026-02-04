import configparser
import sys
import toml
import re

def parse_val(v):
    v = v.strip()
    if v.lower() == 'true':
        return True
    if v.lower() == 'false':
        return False
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v

def set_dotted_key(d, keys, val):
    """将嵌套路径转换为 dotted key 并设置值"""
    if not keys:
        return
    key = '.'.join(keys)
    d[key] = val

def parse_ranges(s):
    res = []
    for part in s.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = map(int, part.split('-'))
            res.extend(range(start, end + 1))
        else:
            res.append(int(part))
    return res

def parse_allow_ports(s):
    res = []
    for part in s.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = map(int, part.split('-'))
            res.append({'start': start, 'end': end})
        else:
            res.append({'single': int(part)})
    return res

def force_string_keys(data):
    """强制特定 key 为字符串"""
    string_keys = {
        'auth.token',
        'loadBalancer.groupKey',
        'secretKey',
        'groupKey',
    }
    for key in list(data.keys()):
        if key in string_keys and data[key] is not None:
            data[key] = str(data[key])
        elif isinstance(data[key], dict):
            force_string_keys(data[key])
    return data

def clean_toml_dotted_keys(text: str) -> str:
    """移除带引号的 dotted keys，转换为裸键格式"""
    pattern = r'"([a-zA-Z0-9_.-]+)"\s*='
    return re.sub(pattern, r'\1 =', text)

def handle_proxy_items(p, items, pmap, plmap, lkeys):
    plugin_type = items.pop('plugin', None)
    if plugin_type:
        p.setdefault('plugin', {})['type'] = plugin_type

    for ini_k, v in list(items.items()):
        if ini_k == 'role':
            continue
        if ini_k in pmap:
            path = pmap[ini_k].split('.')
            if path[-1] in lkeys:
                val = [x.strip() for x in v.split(',') if x.strip()]
            else:
                val = parse_val(v)
            set_dotted_key(p, path, val)
        elif ini_k.startswith('header_'):
            hkey = ini_k[7:].lower()
            val = parse_val(v)
            set_dotted_key(p, ['requestHeaders', 'set', hkey], val)
        elif ini_k.startswith('meta_'):
            mkey = ini_k[5:]
			# 强制字符串
            set_dotted_key(p, ['metadatas', mkey], str(v.strip()))
        elif ini_k.startswith('plugin_header_'):
            hkey = ini_k[14:].lower()
            val = parse_val(v)
            set_dotted_key(p.setdefault('plugin', {}), ['requestHeaders', 'set', hkey], val)
        elif ini_k.startswith('plugin_'):
            plugin_ini_k = ini_k[7:]
            val = parse_val(v)
            if plugin_ini_k in plmap:
                path = plmap[plugin_ini_k].split('.')
                set_dotted_key(p.setdefault('plugin', {}), path, val)
            else:
                p.setdefault('plugin', {})[plugin_ini_k] = val

def convert_frpc(cp):
    toml_dict = {}

    common_map = {
        'server_addr': 'serverAddr',
        'server_port': 'serverPort',
        'nat_hole_stun_server': 'natHoleStunServer',
        'dial_server_timeout': 'transport.dialServerTimeout',
        'dial_server_keepalive': 'transport.dialServerKeepalive',
        'http_proxy': 'transport.proxyURL',
        'log_file': 'log.to',
        'log_level': 'log.level',
        'log_max_days': 'log.maxDays',
        'disable_log_color': 'log.disablePrintColor',
        'admin_addr': 'webServer.addr',
        'admin_port': 'webServer.port',
        'admin_user': 'webServer.user',
        'admin_pwd': 'webServer.password',
        'assets_dir': 'webServer.assetsDir',
        'pool_count': 'transport.poolCount',
        'tcp_mux': 'transport.tcpMux',
        'tcp_mux_keepalive_interval': 'transport.tcpMuxKeepaliveInterval',
        'user': 'user',
        'login_fail_exit': 'loginFailExit',
        'protocol': 'transport.protocol',
        'connect_server_local_ip': 'transport.connectServerLocalIP',
        'quic_keepalive_period': 'transport.quic.keepalivePeriod',
        'quic_max_idle_timeout': 'transport.quic.maxIdleTimeout',
        'quic_max_incoming_streams': 'transport.quic.maxIncomingStreams',
        'tls_enable': 'transport.tls.enable',
        'tls_cert_file': 'transport.tls.certFile',
        'tls_key_file': 'transport.tls.keyFile',
        'tls_trusted_ca_file': 'transport.tls.trustedCaFile',
        'tls_server_name': 'transport.tls.serverName',
        'dns_server': 'dnsServer',
        'heartbeat_interval': 'transport.heartbeatInterval',
        'heartbeat_timeout': 'transport.heartbeatTimeout',
        'udp_packet_size': 'udpPacketSize',
        'disable_custom_tls_first_byte': 'transport.tls.disableCustomTLSFirstByte',
        'pprof_enable': 'webServer.pprofEnable',
        'oidc_client_id': 'auth.oidc.clientID',
        'oidc_client_secret': 'auth.oidc.clientSecret',
        'oidc_audience': 'auth.oidc.audience',
        'oidc_scope': 'auth.oidc.scope',
        'oidc_token_endpoint_url': 'auth.oidc.tokenEndpointURL',
        'token': 'auth.token',
    }

    if 'common' in cp:
        for ini_k, v in cp['common'].items():
            if ini_k in common_map:
                path = common_map[ini_k].split('.')
                val = parse_val(v)
                set_dotted_key(toml_dict, path, val)
            elif ini_k.startswith('meta_'):
                key = ini_k[5:]
				# 强制字符串
                set_dotted_key(toml_dict, ['metadatas', key], str(v.strip()))
            elif ini_k.startswith('oidc_additional_'):
                key = ini_k[16:]
                set_dotted_key(toml_dict, ['auth', 'oidc', 'additionalEndpointParams', key], parse_val(v))
            elif ini_k == 'start':
                toml_dict['start'] = [x.strip() for x in v.split(',') if x.strip()]
            elif ini_k == 'includes':
                toml_dict['includes'] = [x.strip() for x in v.split(',') if x.strip()]

    # auth.method
    method = cp['common'].get('authentication_method', '')
    if not method:
        if any(k.startswith('oidc_') for k in cp['common']):
            method = 'oidc'
        else:
            method = 'token'
    toml_dict['auth.method'] = method

    # auth.additionalScopes
    scopes = []
    if parse_val(cp['common'].get('authenticate_heartbeats', 'false')):
        scopes.append('HeartBeats')
    if parse_val(cp['common'].get('authenticate_new_work_conns', 'false')):
        scopes.append('NewWorkConns')
    if scopes:
        toml_dict['auth.additionalScopes'] = scopes

    # Proxy mappings
    proxy_map = {
        'type': 'type',
        'local_ip': 'localIP',
        'local_port': 'localPort',
        'remote_port': 'remotePort',
        'use_encryption': 'transport.useEncryption',
        'use_compression': 'transport.useCompression',
        'bandwidth_limit': 'transport.bandwidthLimit',
        'bandwidth_limit_mode': 'transport.bandwidthLimitMode',
        'group': 'loadBalancer.group',
        'group_key': 'loadBalancer.groupKey',
        'health_check_type': 'healthCheck.type',
        'health_check_timeout_s': 'healthCheck.timeoutSeconds',
        'health_check_max_failed': 'healthCheck.maxFailed',
        'health_check_interval_s': 'healthCheck.intervalSeconds',
        'health_check_url': 'healthCheck.path',
        'http_user': 'httpUser',
        'http_pwd': 'httpPassword',
        'http_passwd': 'httpPassword',
        'subdomain': 'subdomain',
        'custom_domains': 'customDomains',
        'locations': 'locations',
        'route_by_http_user': 'routeByHTTPUser',
        'host_header_rewrite': 'hostHeaderRewrite',
        'proxy_protocol_version': 'transport.proxyProtocolVersion',
        'sk': 'secretKey',
        'allow_users': 'allowUsers',
        'server_name': 'serverName',
        'server_user': 'serverUser',
        'bind_addr': 'bindAddr',
        'bind_port': 'bindPort',
        'keep_tunnel_open': 'keepTunnelOpen',
        'max_retries_an_hour': 'maxRetriesAnHour',
        'min_retry_interval': 'minRetryInterval',
        'fallback_to': 'fallbackTo',
        'fallback_timeout_ms': 'fallbackTimeoutMs',
        'multiplexer': 'multiplexer',
    }

    plugin_map = {
        'local_addr': 'localAddr',
        'crt_path': 'crtPath',
        'key_path': 'keyPath',
        'host_header_rewrite': 'hostHeaderRewrite',
        'local_path': 'localPath',
        'strip_prefix': 'stripPrefix',
        'http_user': 'httpUser',
        'http_passwd': 'httpPassword',
        'user': 'username',
        'passwd': 'password',
        'unix_path': 'unixPath',
    }

    list_keys = ['customDomains', 'locations', 'allowUsers']

    proxies = []
    visitors = []

    for section in cp.sections():
        if section == 'common':
            continue
        items = dict(cp[section])
        is_visitor = items.get('role') == 'visitor'

        if section.startswith('range:'):
            prefix = section[6:]
            local_ranges = items.pop('local_port', '')
            remote_ranges = items.pop('remote_port', '')
            locals_ = parse_ranges(local_ranges)
            remotes_ = parse_ranges(remote_ranges) if remote_ranges else locals_
            if len(locals_) != len(remotes_):
                print(f"Warning: Range mismatch in section [{section}]")
                continue
            for lp, rp in zip(locals_, remotes_):
                p = {'name': f"{prefix}_{lp}"}
                set_dotted_key(p, ['localPort'], lp)
                set_dotted_key(p, ['remotePort'], rp)
                handle_proxy_items(p, items, proxy_map, plugin_map, list_keys)
                if is_visitor:
                    visitors.append(p)
                else:
                    proxies.append(p)
        else:
            p = {'name': section}
            handle_proxy_items(p, items, proxy_map, plugin_map, list_keys)
            if is_visitor:
                visitors.append(p)
            else:
                proxies.append(p)

    if proxies:
        toml_dict['proxies'] = proxies
    if visitors:
        toml_dict['visitors'] = visitors

    # 处理全局 auth.token 为字符串
    if 'auth.token' in toml_dict:
        toml_dict['auth.token'] = str(toml_dict['auth.token'])

    # 输出全局部分
    global_dict = {k: v for k, v in toml_dict.items() if k not in ['proxies', 'visitors']}
    force_string_keys(global_dict)
    output_global = toml.dumps(global_dict).rstrip()
    output_global = clean_toml_dotted_keys(output_global)

    # 输出 proxies（手动处理 plugin 为 [proxies.plugin]）
    output_proxies = ''
    if 'proxies' in toml_dict:
        for p in toml_dict['proxies']:
            plugin = p.pop('plugin', None)
            force_string_keys(p)
            section = '[[proxies]]\n' + toml.dumps(p).strip()
            section = clean_toml_dotted_keys(section)
            if plugin:
                force_string_keys(plugin)
                section += '\n\n[proxies.plugin]\n' + toml.dumps(plugin).strip()
                section = clean_toml_dotted_keys(section)
            output_proxies += '\n\n' + section

    # 输出 visitors（如果有 plugin 也处理）
    output_visitors = ''
    if 'visitors' in toml_dict:
        for v in toml_dict['visitors']:
            plugin = v.pop('plugin', None)
            force_string_keys(v)
            section = '[[visitors]]\n' + toml.dumps(v).strip()
            section = clean_toml_dotted_keys(section)
            if plugin:
                force_string_keys(plugin)
                section += '\n\n[visitors.plugin]\n' + toml.dumps(plugin).strip()
                section = clean_toml_dotted_keys(section)
            output_visitors += '\n\n' + section

    output = output_global + output_proxies + output_visitors
    output = output.lstrip('\n')

    # 添加空行
    lines = output.splitlines()
    new_lines = []
    for line in lines:
        if line.startswith(('[[proxies]]', '[[visitors]]')):
            if new_lines and new_lines[-1].strip() != '':
                new_lines.append('')
        new_lines.append(line)

    return '\n'.join(new_lines) + '\n'


def convert_frps(cp):
    toml_dict = {}

    common_map = {
        'bind_addr': 'bindAddr',
        'bind_port': 'bindPort',
        'kcp_bind_port': 'kcpBindPort',
        'quic_bind_port': 'quicBindPort',
        'proxy_bind_addr': 'proxyBindAddr',
        'quic_keepalive_period': 'transport.quic.keepalivePeriod',
        'quic_max_idle_timeout': 'transport.quic.maxIdleTimeout',
        'quic_max_incoming_streams': 'transport.quic.maxIncomingStreams',
        'vhost_http_port': 'vhostHTTPPort',
        'vhost_https_port': 'vhostHTTPSPort',
        'vhost_http_timeout': 'vhostHTTPTimeout',
        'tcpmux_httpconnect_port': 'tcpmuxHTTPConnectPort',
        'tcpmux_passthrough': 'tcpmuxPassthrough',
        'dashboard_addr': 'webServer.addr',
        'dashboard_port': 'webServer.port',
        'dashboard_user': 'webServer.user',
        'dashboard_pwd': 'webServer.password',
        'dashboard_tls_mode': 'webServer.tls.enable',
        'dashboard_tls_cert_file': 'webServer.tls.certFile',
        'dashboard_tls_key_file': 'webServer.tls.keyFile',
        'enable_prometheus': 'enablePrometheus',
        'assets_dir': 'webServer.assetsDir',
        'log_file': 'log.to',
        'log_level': 'log.level',
        'log_max_days': 'log.maxDays',
        'disable_log_color': 'log.disablePrintColor',
        'detailed_errors_to_client': 'detailedErrorsToClient',
        'authentication_method': 'auth.method',
        'token': 'auth.token',
        'oidc_issuer': 'auth.oidc.issuer',
        'oidc_audience': 'auth.oidc.audience',
        'oidc_skip_expiry_check': 'auth.oidc.skipExpiryCheck',
        'oidc_skip_issuer_check': 'auth.oidc.skipIssuerCheck',
        'heartbeat_timeout': 'transport.heartbeatTimeout',
        'user_conn_timeout': 'userConnTimeout',
        'max_pool_count': 'transport.maxPoolCount',
        'max_ports_per_client': 'maxPortsPerClient',
        'tls_only': 'transport.tls.force',
        'tls_cert_file': 'transport.tls.certFile',
        'tls_key_file': 'transport.tls.keyFile',
        'tls_trusted_ca_file': 'transport.tls.trustedCaFile',
        'tcp_mux': 'transport.tcpMux',
        'tcp_mux_keepalive_interval': 'transport.tcpMuxKeepaliveInterval',
        'tcp_keepalive': 'transport.tcpKeepalive',
        'subdomain_host': 'subDomainHost',
        'custom_404_page': 'custom404Page',
        'udp_packet_size': 'udpPacketSize',
        'pprof_enable': 'webServer.pprofEnable',
        'nat_hole_analysis_data_reserve_hours': 'natholeAnalysisDataReserveHours',
    }

    if 'common' in cp:
        for ini_k, v in cp['common'].items():
            if ini_k in common_map:
                path = common_map[ini_k].split('.')
                val = parse_val(v)
                set_dotted_key(toml_dict, path, val)
            elif ini_k == 'allow_ports':
                toml_dict['allowPorts'] = parse_allow_ports(v)

    # auth.method
    method = cp['common'].get('authentication_method', 'token')
    toml_dict['auth.method'] = method

    # auth.additionalScopes
    scopes = []
    if parse_val(cp['common'].get('authenticate_heartbeats', 'false')):
        scopes.append('HeartBeats')
    if parse_val(cp['common'].get('authenticate_new_work_conns', 'false')):
        scopes.append('NewWorkConns')
    if scopes:
        toml_dict['auth.additionalScopes'] = scopes

    # 处理 auth.token 为字符串
    if 'auth.token' in toml_dict:
        toml_dict['auth.token'] = str(toml_dict['auth.token'])

    # httpPlugins
    http_plugins = []
    for section in cp.sections():
        if section.startswith('plugin.'):
            name = section[7:]
            items = dict(cp[section])
            p = {
                'name': name,
                'addr': items.get('addr'),
                'path': items.get('path'),
                'ops': [op.strip() for op in items.get('ops', '').split(',') if op.strip()]
            }
            http_plugins.append(p)

    if http_plugins:
        toml_dict['httpPlugins'] = http_plugins

    # 输出全局
    global_dict = {k: v for k, v in toml_dict.items() if k != 'httpPlugins'}
    force_string_keys(global_dict)
    output_global = toml.dumps(global_dict).rstrip()
    output_global = clean_toml_dotted_keys(output_global)

    # 输出 httpPlugins
    output_plugins = ''
    if 'httpPlugins' in toml_dict:
        output_plugins = '\n\n' + '\n\n'.join('[[httpPlugins]]\n' + toml.dumps(p).strip() for p in toml_dict['httpPlugins'])
        output_plugins = clean_toml_dotted_keys(output_plugins)

    output = output_global + output_plugins
    output = output.lstrip('\n')

    # 添加空行
    lines = output.splitlines()
    new_lines = []
    for line in lines:
        if line.startswith('[[httpPlugins]]'):
            if new_lines and new_lines[-1].strip() != '':
                new_lines.append('')
        new_lines.append(line)

    return '\n'.join(new_lines) + '\n'


if len(sys.argv) < 2:
    print("Usage: python convert_frp.py input.ini [output.toml] [--type=client|server]")
    sys.exit(1)

cp = configparser.ConfigParser()
cp.read(sys.argv[1])

config_type = 'client'
if len(sys.argv) > 3 and sys.argv[3].startswith('--type='):
    config_type = sys.argv[3][7:].lower()
elif 'common' in cp and ('vhost_http_port' in cp['common'] or 'dashboard_port' in cp['common']):
    config_type = 'server'

if config_type == 'server':
    output = convert_frps(cp)
else:
    output = convert_frpc(cp)

if len(sys.argv) > 2 and not sys.argv[2].startswith('--'):
    with open(sys.argv[2], 'w', encoding='utf-8') as f:
        f.write(output)
else:
    print(output)