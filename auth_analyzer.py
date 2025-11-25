import re
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json as _json
import urllib.request as _url
import re as _re

def parse_timestamp(month, day, time_str):
    now = datetime.now()
    ts = datetime.strptime(f"{now.year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    if ts > now + timedelta(days=7):
        ts = ts.replace(year=now.year - 1)
    return ts

GEO_CACHE = {}
ZH_MAP = {
    'India': '印度',
    'Maharashtra': '马哈拉施特拉邦',
    'Mumbai': '孟买',
    'United States': '美国',
    'California': '加利福尼亚州',
    'New York': '纽约州',
    'China': '中国',
    'Beijing': '北京',
    'Shanghai': '上海',
    'Shenzhen': '深圳',
    'Guangzhou': '广州',
    'Japan': '日本',
    'Tokyo': '东京',
    'Osaka': '大阪',
    'South Korea': '韩国',
    'Seoul': '首尔',
    'Singapore': '新加坡',
    'Hong Kong': '香港',
    'Taipei': '台北',
    'United Kingdom': '英国',
    'England': '英格兰',
    'France': '法国',
    'Germany': '德国',
    'Delhi': '德里',
    'Bengaluru': '班加罗尔',
    'Bangalore': '班加罗尔',
    'Hyderabad': '海得拉巴',
    'Chennai': '金奈',
    'Karnataka': '卡纳塔克邦',
}
def _to_zh(s):
    if not s:
        return s
    if s in ZH_MAP:
        return ZH_MAP[s]
    if _re.fullmatch(r"[A-Za-z .\-]+", s):
        return ZH_MAP.get(s, s)
    return s
def geo_lookup(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,query&lang=zh-CN"
        with _url.urlopen(url, timeout=3) as resp:
            data = _json.loads(resp.read().decode('utf-8', 'ignore'))
            if data.get('status') == 'success':
                res = {
                    'country': _to_zh(data.get('country')),
                    'region': _to_zh(data.get('regionName')),
                    'city': _to_zh(data.get('city')),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                }
                GEO_CACHE[ip] = res
                return res
    except Exception:
        pass
    GEO_CACHE[ip] = None
    return None

def parse_log(path, progress_cb=None):
    size = os.path.getsize(path)
    read_bytes = 0
    accepted = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\b")
    failed = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+Failed\s+password\s+for\s+(?:(?:invalid\s+user\s+)?)(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\b")
    useradd_detail = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+useradd(?:\[\d+\])?:\s+new\s+user:\s+name=(?P<user>[^,\s]+)(?:, UID=(?P<uid>\d+))?(?:, GID=(?P<gid>\d+))?(?:, home=(?P<home>[^,\s]+))?(?:, shell=(?P<shell>[^,\s]+))?.*")
    adduser_added = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+adduser(?:\[\d+\])?:\s+.*(?:added|adding)\s+user\s+(?P<user>\S+).*")
    groupadd_ops = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+groupadd(?:\[\d+\])?:\s+(?:group added to /etc/(?:group|gshadow): name=(?P<group1>[^,\s]+)(?:, GID=(?P<gid1>\d+))?|new group: name=(?P<group2>[^,\s]+)(?:, GID=(?P<gid2>\d+))?)")
    passwd_change = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+passwd(?:\[\d+\])?:.*password\s+changed\s+for\s+(?P<user>\S+)")
    usermod_add_group = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+usermod(?:\[\d+\])?:\s+add\s+'(?P<user>[^']+)'\s+to\s+(?:shadow\s+)?group\s+'(?P<group>[^']+)'")
    sudo_cmd = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s*:\s*TTY=.*;\s*PWD=.*;\s*USER=.*;\s*COMMAND=(?P<cmd>.+)$")
    events = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            read_bytes += len(line.encode('utf-8', 'ignore'))
            m = accepted.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                events.append({'type': 'accepted', 'timestamp': ts, 'user': m.group('user'), 'ip': m.group('ip'), 'port': m.group('port'), 'host': m.group('host'), 'raw': line.strip()})
                if progress_cb and size:
                    progress_cb(min(99, int(read_bytes * 100 / size)))
                continue
            m = failed.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                events.append({'type': 'failed', 'timestamp': ts, 'user': m.group('user'), 'ip': m.group('ip'), 'port': m.group('port'), 'host': m.group('host'), 'raw': line.strip()})
                if progress_cb and size:
                    progress_cb(min(99, int(read_bytes * 100 / size)))
                continue
            m = useradd_detail.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                events.append({'type': 'user_created_detail', 'timestamp': ts, 'user': m.group('user'), 'uid': m.group('uid'), 'gid': m.group('gid'), 'home': m.group('home'), 'shell': m.group('shell'), 'host': m.group('host'), 'raw': line.strip()})
                continue
            m = adduser_added.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                events.append({'type': 'user_created', 'timestamp': ts, 'user': m.group('user'), 'host': m.group('host'), 'raw': line.strip()})
                continue
            m = groupadd_ops.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                grp = m.group('group1') or m.group('group2')
                gid = m.group('gid1') or m.group('gid2')
                events.append({'type': 'group_created', 'timestamp': ts, 'group': grp, 'gid': gid, 'host': m.group('host'), 'raw': line.strip()})
                continue
            m = passwd_change.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                events.append({'type': 'user_password_changed', 'timestamp': ts, 'user': m.group('user'), 'host': m.group('host'), 'raw': line.strip()})
                continue
            m = usermod_add_group.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                events.append({'type': 'user_added_to_group', 'timestamp': ts, 'user': m.group('user'), 'group': m.group('group'), 'host': m.group('host'), 'raw': line.strip()})
                continue
            m = sudo_cmd.search(line)
            if m:
                ts = parse_timestamp(m.group('month'), m.group('day'), m.group('time'))
                events.append({'type': 'sudo_command', 'timestamp': ts, 'user': m.group('user'), 'cmd': m.group('cmd'), 'host': m.group('host'), 'raw': line.strip()})
                continue
    if progress_cb:
        progress_cb(100)
    return events

def detect_bruteforce(events, count_threshold, minutes_window):
    by_ip = defaultdict(list)
    for e in events:
        if e['type'] == 'failed':
            by_ip[e['ip']].append(e)
    incidents = []
    window = timedelta(minutes=minutes_window)
    for ip, lst in by_ip.items():
        lst.sort(key=lambda x: x['timestamp'])
        i = 0
        for j in range(len(lst)):
            while lst[j]['timestamp'] - lst[i]['timestamp'] > window:
                i += 1
            count = j - i + 1
            if count >= count_threshold:
                users = Counter(x['user'] for x in lst[i:j+1])
                incidents.append({'ip': ip, 'start': lst[i]['timestamp'], 'end': lst[j]['timestamp'], 'count': count, 'users': dict(users)})
    return incidents

def summarize_user_ops(events):
    ops = defaultdict(list)
    seen = defaultdict(set)
    seen_norm = defaultdict(set)
    for e in events:
        t = e.get('type')
        if t == 'user_created_detail':
            vals = []
            if e.get('uid'):
                vals.append(f"UID={e['uid']}")
            if e.get('gid'):
                vals.append(f"GID={e['gid']}")
            if e.get('home'):
                vals.append(f"HOME={e['home']}")
            if e.get('shell'):
                vals.append(f"SHELL={e['shell']}")
            explain = '创建用户' + (' (' + ', '.join(vals) + ')' if vals else '')
            u = e['user']
            if explain not in seen[u]:
                ops[u].append({'timestamp': e['timestamp'], 'raw': e.get('raw'), 'explain': explain})
                seen[u].add(explain)
        elif t == 'user_created':
            u = e['user']
            explain = '创建用户'
            if explain not in seen[u]:
                ops[u].append({'timestamp': e['timestamp'], 'raw': e.get('raw'), 'explain': explain})
                seen[u].add(explain)
        elif t == 'group_created':
            grp = e.get('group')
            gid = e.get('gid')
            explain = f"创建同名组 {grp}" + (f" (GID={gid})" if gid else '')
            norm = explain.replace(' (GID=' + str(gid) + ')', '') if gid else explain
            if norm not in seen_norm[grp]:
                ops[grp].append({'timestamp': e['timestamp'], 'raw': e.get('raw'), 'explain': explain})
                seen_norm[grp].add(norm)
        elif t == 'user_password_changed':
            u = e['user']
            explain = '设置/更改密码'
            if explain not in seen[u]:
                ops[u].append({'timestamp': e['timestamp'], 'raw': e.get('raw'), 'explain': explain})
                seen[u].add(explain)
        elif t == 'user_added_to_group':
            u = e['user']
            explain = f"加入组 {e.get('group')}"
            if explain not in seen[u]:
                ops[u].append({'timestamp': e['timestamp'], 'raw': e.get('raw'), 'explain': explain})
                seen[u].add(explain)
        elif t == 'sudo_command':
            u = e['user']
            cmd = e.get('cmd')
            explain = f"sudo命令 {cmd}"
            ops[u].append({'timestamp': e['timestamp'], 'raw': e.get('raw'), 'explain': explain})
    return ops

def analyze_file(path, progress_cb=None, params=None):
    params = params or {}
    count = int(params.get('count', 5))
    minutes = int(params.get('minutes', 5))
    limit = int(params.get('limit', 100))
    events = parse_log(path, progress_cb)
    incidents = detect_bruteforce(events, count, minutes)
    suspects = sorted(set(inc['ip'] for inc in incidents))
    incidents_by_ip = defaultdict(int)
    for inc in incidents:
        incidents_by_ip[inc['ip']] += inc['count']
    accepted = [e for e in events if e['type'] == 'accepted']
    failed = [e for e in events if e['type'] == 'failed']
    accepted_rows = []
    for e in accepted[:limit]:
        accepted_rows.append({'timestamp': e['timestamp'].strftime('%m-%d %H:%M:%S'), 'ip': e['ip'], 'user': e['user'], 'port': e['port']})
    ops = summarize_user_ops(events)
    ops_out = {}
    for u, lst in ops.items():
        ops_out[u] = [{'timestamp': item['timestamp'].strftime('%m-%d %H:%M:%S'), 'raw': item.get('raw'), 'explain': item.get('explain')} for item in sorted(lst, key=lambda x: x['timestamp'])]
    suspects_detail = []
    for ip in suspects:
        g = geo_lookup(ip)
        suspects_detail.append({
            'ip': ip,
            'attempts': incidents_by_ip.get(ip, 0),
            'country': g.get('country') if g else None,
            'region': g.get('region') if g else None,
            'city': g.get('city') if g else None,
            'lat': g.get('lat') if g else None,
            'lon': g.get('lon') if g else None,
        })
    return {
        'file': os.path.basename(path),
        'bruteforce': bool(incidents),
        'suspect_ips': suspects,
        'suspects_detail': suspects_detail,
        'accepted_events': accepted_rows,
        'stats': {
            'accepted_total': len(accepted),
            'failed_total': len(failed),
        },
        'incidents': [
            {
                'ip': inc['ip'],
                'count': inc['count'],
                'start': inc['start'].strftime('%m-%d %H:%M:%S'),
                'end': inc['end'].strftime('%m-%d %H:%M:%S'),
                'users': inc['users'],
            }
            for inc in incidents
        ],
        'user_operations': ops_out,
    }
