#!/usr/bin/env python3
"""Build domain-only DNS rule sets; reject address predicates by construction."""
import argparse, json, pathlib, subprocess, tempfile, urllib.request

QH = 'https://raw.githubusercontent.com/QuixoticHeart/rule-set/ruleset/singbox/version5/'
META = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/'
SOURCES = {
    'dns-hk-youtube': QH + 'youtube.json',
    'dns-hk-netflix': QH + 'netflix.json',
    'dns-hk-twitch': QH + 'twitch.json',
    'dns-hk-games': QH + 'games.json',
    'dns-hk-telegram': META + 'telegram.srs',
    'dns-hk-category-porn': META + 'category-porn.srs',
    'dns-hk-pornhub': META + 'pornhub.srs',
    'dns-steam-gfw': QH + 'gfw.json',
}
DOMAIN_KEYS = {'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'invert'}

def fetch(url, path):
    with urllib.request.urlopen(url, timeout=60) as response:
        path.write_bytes(response.read())

def clean_rule(rule, contains=None):
    if rule.get('type') == 'logical':
        children = [clean_rule(item, contains) for item in rule.get('rules', [])]
        children = [item for item in children if item]
        if not children:
            return None
        return {'type': 'logical', 'mode': rule.get('mode', 'and'), 'rules': children}
    result = {}
    for key in DOMAIN_KEYS:
        if key not in rule:
            continue
        value = rule[key]
        if contains and key != 'invert':
            values = value if isinstance(value, list) else [value]
            values = [item for item in values if contains in str(item).lower()]
            if not values:
                continue
            value = values if isinstance(rule[key], list) else values[0]
        result[key] = value
    return result or None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sing-box', required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    output = root / 'rules'
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        temp = pathlib.Path(temp)
        for tag, url in SOURCES.items():
            downloaded = temp / (tag + ('.srs' if url.endswith('.srs') else '.json'))
            fetch(url, downloaded)
            source = downloaded
            if downloaded.suffix == '.srs':
                source = temp / (tag + '.json')
                subprocess.run([args.sing_box, 'rule-set', 'decompile', str(downloaded), '-o', str(source)], check=True)
            data = json.loads(source.read_text(encoding='utf-8'))
            keyword = 'steam' if tag == 'dns-steam-gfw' else None
            data['rules'] = [item for rule in data.get('rules', []) if (item := clean_rule(rule, keyword))]
            cleaned = temp / (tag + '.clean.json')
            cleaned.write_text(json.dumps(data, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
            destination = output / (tag + '.srs')
            subprocess.run([args.sing_box, 'rule-set', 'compile', str(cleaned), '-o', str(destination)], check=True)
            audited = temp / (tag + '.audit.json')
            subprocess.run([args.sing_box, 'rule-set', 'decompile', str(destination), '-o', str(audited)], check=True)
            check = audited.read_text(encoding='utf-8')
            if any(key in check for key in ('"ip_cidr"', '"ip_is_private"', '"ip_accept_any"')):
                raise RuntimeError(f'{tag} contains a forbidden address predicate')

if __name__ == '__main__':
    main()
