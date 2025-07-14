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
from typing import Generator, Set, List, Optional, Tuple
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


# 配置常量
CHUNK_SIZE = 100_000
MAX_DOMAIN_LENGTH = 253
WORKER_COUNT = min(mp.cpu_count() * 2, 8)
DOWNLOAD_WORKERS = min(mp.cpu_count(), 4)
TIMEOUT = 30
RETRY_COUNT = 2
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

# 正则表达式
DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
ADBLOCK_PATTERN = re.compile(r"^\|\|([a-z0-9\-\.]+)\^$", re.IGNORECASE)
CLASH_PATTERN = re.compile(r"^(DOMAIN,|DOMAIN-SUFFIX,)", re.IGNORECASE)
INVALID_CHARS = re.compile(r'[\\/*?:"<>|]')


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
    """验证域名合法性"""
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False
    
    labels = domain.split('.')
    if len(labels) < 2 or len(labels[-1]) < 2:
        return False
    
    return all(
        1 <= len(l) <= 63 and l[0] != '-' and l[-1] != '-' and 
        all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in l.lower())
        for l in labels
    )


def extract(line: str) -> Optional[str]:
    """从行中提取域名"""
    line = line.strip().lower()
    if not line or line.startswith(('#', '!', '//')):
        return None

    # Adblock格式
    if m := ADBLOCK_PATTERN.match(line):
        return m.group(1) if is_valid(m.group(1)) else None
    
    # Clash格式
    if m := CLASH_PATTERN.match(line):
        parts = line.split(",", 1)
        domain = parts[1].strip() if len(parts) > 1 else ""
        return domain if is_valid(domain) else None
    
    # 通配符格式
    if line.startswith(("*.", "+.")):
        domain = line[2:].strip()
        return domain if is_valid(domain) else None
    
    # URL格式
    if line.startswith(("http://", "https://", "ftp://")):
        try:
            parsed = urlparse(line)
            if parsed.netloc:
                domain = parsed.netloc.split(':', 1)[0]
                return domain if is_valid(domain) else None
        except ValueError:
            pass
    
    # 纯域名
    return line if is_valid(line) else None


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
                lines = []
                for b in res.iter_lines():
                    if b:
                        try:
                            lines.append(b.decode('utf-8'))
                        except UnicodeDecodeError:
                            try:
                                lines.append(b.decode('latin-1'))
                            except UnicodeDecodeError:
                                continue
                log(f"{'白名单' if is_whitelist else ''}下载成功 {url} | {len(lines):,} 行")
                return lines, len(lines)
        except Exception as e:
            if attempt < RETRY_COUNT:
                log(f"{'白名单' if is_whitelist else ''}下载失败 {url}, 重试 {attempt+1}/{RETRY_COUNT}: {e}")
                time.sleep(2**attempt)
            else:
                log(f"{'白名单' if is_whitelist else ''}最终失败 {url}: {e}", critical=True)
                return [], 0


# 白名单模块
def load_whitelist() -> dict:
    """加载白名单"""
    wl_path = Path("white_links.txt")
    if not wl_path.exists():
        log("未找到white_links.txt，跳过白名单过滤")
        return {}

    try:
        with open(wl_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception as e:
        log(f"白名单配置错误: {e}", critical=True)
        return {}

    whitelist = {}
    for name, urls in rules.items():
        if not isinstance(urls, list) or not urls:
            continue
        
        sanitized = sanitize(name)
        if not sanitized:
            continue

        # 下载白名单内容
        lines = []
        with ThreadPoolExecutor(DOWNLOAD_WORKERS) as exe:
            futures = {exe.submit(download, u, True): u for u in urls}
            for f in as_completed(futures):
                try:
                    l, _ = f.result()
                    lines.extend(l)
                except Exception as e:
                    log(f"白名单URL错误 {futures[f]}: {e}", critical=True)

        # 提取白名单域名
        wl_domains = {line.strip().lower() for line in lines 
                     if line.strip() and not line.startswith(('#', '!', '//')) 
                     and is_valid(line.strip().lower())}
        
        whitelist[sanitized] = wl_domains
        log(f"白名单[{name}]加载完成 | {len(wl_domains):,} 域名")

    return whitelist


# 域名优化模块（核心优化点）
def remove_subdomains(domains: Set[str]) -> Set[str]:
    """优化子域名去重算法（降低时间复杂度）"""
    if len(domains) <= 1:
        return domains

    domain_set = domains
    keep = set()

    for domain in domains:
        # 生成所有可能的父域名（如a.b.c.com → b.c.com → c.com）
        parts = domain.split('.')
        parent_exists = False
        
        # 检查是否存在父域名
        for i in range(1, len(parts)-1):  # 从第1个部分开始剥离（保留至少2级域名）
            parent = '.'.join(parts[i:])
            if parent in domain_set:
                parent_exists = True
                break
        
        if not parent_exists:
            keep.add(domain)
    
    return keep


# 主处理模块（核心优化点）
def process_group(lines: List[str], output_path: Path, whitelist: dict) -> None:
    """处理单个规则组（优化大文件写入）"""
    log(f"处理规则: {output_path.name}")
    if not lines:
        log(f"无有效规则: {output_path.name}", critical=True)
        return

    # 提取原始域名
    raw = set(parallel_process(lines))
    log(f"原始域名: {len(raw):,} 个")

    # 白名单过滤
    group_name = output_path.stem
    filtered = raw - whitelist.get(group_name, set())
    log(f"过滤后: {len(filtered):,} 个 (移除 0 个)")

    # 子域名去重（添加进度日志）
    log(f"开始子域名去重（{len(filtered):,} 个域名）...")
    final = remove_subdomains(filtered)
    log(f"去重后: {len(final):,} 个 (移除 {len(filtered)-len(final)} 个子域名)")

    # 保存结果（优化：逐行写入，避免大字符串拼接）
    temp = output_path.with_suffix(".tmp")
    try:
        with open(temp, "w", encoding="utf-8") as f:
            # 排序后逐行写入，减少内存占用
            for domain in sorted(final):
                f.write(f"{domain}\n")
        
        temp.replace(output_path)
        log(f"完成: {output_path} | 最终 {len(final):,} 个域名")
    except Exception as e:
        log(f"处理失败 {output_path}: {e}", critical=True)
        if temp.exists():
            temp.unlink()


# 主函数
def main():
    """主入口"""
    # 检查配置文件
    links_path = Path("links.txt")
    if not links_path.exists():
        log("未找到links.txt", critical=True)
        sys.exit(1)

    # 初始化输出目录
    output_dir = Path("domain")
    output_dir.mkdir(exist_ok=True)

    # 加载规则配置
    try:
        with open(links_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception as e:
        log(f"规则配置错误: {e}", critical=True)
        sys.exit(1)

    if not isinstance(rules, dict) or not rules:
        log("无效规则配置", critical=True)
        sys.exit(1)

    # 加载白名单
    whitelist = load_whitelist()

    # 处理所有规则组
    for name, urls in rules.items():
        if not isinstance(urls, list) or not urls:
            continue
        
        sanitized = sanitize(name)
        if not sanitized:
            continue

        output_path = output_dir / f"{sanitized}.txt"
        log(f"\n===== 处理规则组: {name} -> {output_path.name} =====")

        # 下载规则内容
        lines = []
        total_lines = 0
        with ThreadPoolExecutor(DOWNLOAD_WORKERS) as exe:
            futures = {exe.submit(download, u): u for u in urls}
            for f in as_completed(futures):
                try:
                    l, cnt = f.result()
                    lines.extend(l)
                    total_lines += cnt
                except Exception as e:
                    log(f"URL错误 {futures[f]}: {e}", critical=True)

        log(f"规则组[{name}]下载完成 | 共 {total_lines:,} 行")
        process_group(lines, output_path, whitelist)

    log("\n所有规则处理完毕")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n用户中断", critical=True)
        sys.exit(1)
    except Exception as e:
        log(f"致命错误: {e}", critical=True)
        sys.exit(1)
