#!/usr/bin/env python3
"""
从links.txt读取规则链接，结合white_links.txt白名单，处理为纯domain格式并输出到domain目录
"""
import re
import sys
import time
import json
import multiprocessing as mp
from pathlib import Path
from typing import Generator, Set, List, Optional, Tuple, Dict
import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed


# 配置常量
CHUNK_SIZE = 100_000
MAX_DOMAIN_LENGTH = 253
WORKER_COUNT = min(mp.cpu_count() * 2, 8)
DOWNLOAD_WORKERS = min(mp.cpu_count(), 4)  # 规则组下载线程数
RULEGROUP_WORKERS = min(mp.cpu_count(), 4)  # 规则组处理线程数
TIMEOUT = 30
RETRY_COUNT = 2
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
MAX_WHITELIST_SIZE = 512 * 1024 * 1024  # 512MB

# 正则表达式
DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
ADBLOCK_PATTERN = re.compile(r"^\|\|([a-z0-9\-\.]+)\^$", re.IGNORECASE)
RULE_PATTERN = re.compile(
    r"^(?:DOMAIN-SUFFIX|HOST-SUFFIX|host-suffix|DOMAIN|HOST|host|DOMAIN-KEYWORD|HOST-KEYWORD|host-keyword)[,\s]+(.+)$",
    re.IGNORECASE
)
INVALID_CHARS = re.compile(r'[\\/*?:"<>|]')
UNWANTED_PREFIX = re.compile(r"^(0\.0\.0\.0\s+|127\.0\.0\.1\s+|local=|\|\||\*\.|\+\.|@@\|\|)")
UNWANTED_SUFFIX = re.compile(r"[\^#].*$")


# 日志模块
def log(msg: str, critical: bool = False) -> None:
    """输出带时间戳的日志"""
    prefix = "![CRIT] " if critical else "[INFO] "
    print(f"{time.strftime('%H:%M:%S')}{prefix}{msg}", flush=True)


# 工具模块
def sanitize(name: str) -> str:
    """清理文件名非法字符"""
    return INVALID_CHARS.sub('_', name).strip()


# 域名处理模块
def is_valid(domain: str) -> bool:
    """严格验证域名合法性"""
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False
    
    # 必须包含点号且TLD至少2个字符
    if '.' not in domain or len(domain.split('.')[-1]) < 2:
        return False
    
    # 使用正则表达式验证完整域名格式
    return bool(DOMAIN_PATTERN.match(domain))


def clean_domain(domain: str) -> str:
    """清理域名：去除特定前缀/后缀字符"""
    # 去除特定前缀
    if m := UNWANTED_PREFIX.search(domain):
        domain = domain.replace(m.group(0), '', 1)
    
    # 去除特定后缀
    if m := UNWANTED_SUFFIX.search(domain):
        domain = domain[:m.start()]
    
    # 去除首尾空白和点号
    return domain.strip().strip('.').lower()


def extract(line: str) -> Optional[str]:
    """从行中提取域名（优化版）"""
    try:
        line = line.strip()
        if not line or line.startswith(('#', '!', '//')):
            return None

        # 清理行内容
        clean_line = clean_domain(line)
        if not clean_line:
            return None

        # Adblock格式
        if m := ADBLOCK_PATTERN.match(clean_line):
            domain = m.group(1)
            return domain if is_valid(domain) else None
        
        # 规则格式 (DOMAIN-SUFFIX, DOMAIN, etc.)
        if m := RULE_PATTERN.match(clean_line):
            domain = m.group(1).strip()
            if domain and is_valid(domain):
                return domain
        
        # 通配符格式
        if clean_line.startswith(("*.", "+.")):
            domain = clean_line[2:].strip()
            return domain if is_valid(domain) else None
        
        # 纯域名（最终检查）
        return clean_line if is_valid(clean_line) else None
    except Exception:
        return None


# 并行处理模块
def process_chunk(chunk: List[str]) -> Set[str]:
    """处理数据块"""
    return {d for line in chunk if (d := extract(line))}


def parallel_process(lines: List[str]) -> Generator[str, None, None]:
    """并行处理域名列表"""
    global_seen = set()
    chunks = [lines[i:i+CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    
    log(f"并行处理: {len(chunks)} 块 | 每块最多 {CHUNK_SIZE} 行")
    
    with mp.Pool(WORKER_COUNT) as pool:
        for result in pool.imap_unordered(process_chunk, chunks):
            for d in result:
                if d not in global_seen:
                    global_seen.add(d)
                    yield d


# 下载模块
def download(url: str, is_whitelist: bool = False) -> Tuple[List[str], int]:
    """下载URL内容"""
    headers = {"User-Agent": USER_AGENT}
    for attempt in range(RETRY_COUNT + 1):
        try:
            with requests.get(url, headers=headers, timeout=TIMEOUT, stream=True) as res:
                res.raise_for_status()
                
                content_length = int(res.headers.get('Content-Length', 0))
                if is_whitelist and content_length > MAX_WHITELIST_SIZE:
                    log(f"跳过大文件白名单 {url} ({content_length/1024/1024:.1f}MB)")
                    return [], 0
                
                # 处理YAML格式
                if url.endswith(('.yaml', '.yml')):
                    try:
                        content = yaml.safe_load(res.text)
                        # 提取payload中的域名
                        if 'payload' in content:
                            lines = content['payload']
                        # 处理纯文本格式的YAML
                        else:
                            lines = res.text.splitlines()
                        return lines, len(lines)
                    except yaml.YAMLError:
                        lines = res.text.splitlines()
                        return lines, len(lines)
                
                # 处理文本格式
                lines = res.text.splitlines()
                return lines, len(lines)
        except Exception as e:
            if attempt < RETRY_COUNT:
                time.sleep(2**attempt)
            else:
                if not is_whitelist:
                    log(f"下载失败 {url}: {str(e)[:100]}", critical=True)
                return [], 0


# 白名单模块（简化安全版）
def load_whitelist() -> dict:
    """加载白名单（安全处理大文件）"""
    wl_path = Path("white_links.txt")
    if not wl_path.exists():
        log("未找到white_links.txt，跳过白名单过滤")
        return {}

    try:
        with open(wl_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception:
        return {}

    whitelist = {}
    for name, urls in rules.items():
        if not isinstance(urls, list) or not urls:
            continue
        
        sanitized = sanitize(name)
        if not sanitized:
            continue

        # 下载白名单内容
        wl_domains = set()
        for url in urls:
            lines, _ = download(url, True)
            for line in lines:
                if domain := extract(line):
                    wl_domains.add(domain)
        
        whitelist[sanitized] = wl_domains
        log(f"白名单[{name}]加载完成 | {len(wl_domains):,} 域名")

    return whitelist


# 域名优化模块
def remove_subdomains(domains: Set[str]) -> Set[str]:
    """高效子域名去重算法"""
    if len(domains) <= 1:
        return domains

    # 按域名长度排序（短域名在前）
    sorted_domains = sorted(domains, key=len)
    keep = set()
    domain_set = set(domains)
    
    for domain in sorted_domains:
        # 生成所有可能的父域名
        parts = domain.split('.')
        parent_found = False
        
        # 检查是否存在父域名（从最直接的父域名开始检查）
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in domain_set:
                parent_found = True
                break
        
        # 只有当没有父域名存在时才保留
        if not parent_found:
            keep.add(domain)
    
    return keep


# 处理单个规则组
def process_rule_group(name: str, urls: List[str], whitelist: dict, output_dir: Path) -> None:
    """处理单个规则组"""
    sanitized = sanitize(name)
    if not sanitized:
        return

    output_path = output_dir / f"{sanitized}.txt"
    log(f"\n===== 处理规则组: {name} -> {output_path.name} =====")

    # 下载规则内容
    lines = []
    total_lines = 0
    for url in urls:
        l, cnt = download(url)
        lines.extend(l)
        total_lines += cnt

    log(f"规则组[{name}]下载完成 | 共 {total_lines:,} 行")
    
    # 提取原始域名
    raw = set()
    for domain in parallel_process(lines):
        raw.add(domain)
    
    log(f"原始域名: {len(raw):,} 个")

    # 白名单过滤
    group_name = output_path.stem
    if group_name in whitelist:
        filtered = raw - whitelist[group_name]
        log(f"过滤后: {len(filtered):,} 个 (移除 {len(raw) - len(filtered)} 个)")
    else:
        filtered = raw
        log("无匹配白名单，跳过过滤")

    # 子域名去重
    final = remove_subdomains(filtered)
    log(f"去重后: {len(final):,} 个 (移除 {len(filtered)-len(final)} 个子域名)")

    # 保存结果
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            # 排序后逐行写入
            for domain in sorted(final):
                f.write(f"{domain}\n")
        
        log(f"完成: {output_path} | 最终 {len(final):,} 个域名")
    except Exception:
        log(f"写入失败 {output_path}", critical=True)


# 主函数
def main():
    """主入口"""
    # 检查配置文件
    links_path = Path("links.txt")
    if not links_path.exists():
        log("未找到links.txt", critical=True)
        return

    # 初始化输出目录
    output_dir = Path("domain")
    output_dir.mkdir(exist_ok=True)

    # 加载规则配置
    try:
        with open(links_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception:
        log("规则配置错误", critical=True)
        return

    if not isinstance(rules, dict) or not rules:
        log("无效规则配置", critical=True)
        return

    # 加载白名单
    whitelist = load_whitelist()

    # 使用线程池处理规则组
    log(f"开始处理 {len(rules)} 个规则组，使用 {RULEGROUP_WORKERS} 线程")
    
    with ThreadPoolExecutor(max_workers=RULEGROUP_WORKERS) as executor:
        futures = []
        for name, urls in rules.items():
            if not isinstance(urls, list) or not urls:
                continue
            
            # 提交任务到线程池
            future = executor.submit(
                process_rule_group, 
                name, 
                urls, 
                whitelist, 
                output_dir
            )
            futures.append(future)
        
        # 等待所有任务完成
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log(f"规则组处理错误: {str(e)[:200]}", critical=True)

    log("\n所有规则处理完毕")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n用户中断", critical=True)
    except Exception as e:
        log(f"致命错误: {str(e)[:200]}", critical=True)
