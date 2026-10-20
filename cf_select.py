#!/usr/bin/env python3
# Author: Pre
"""Create private VLESS/WS/TLS candidate links without changing a node.

The workflow is inspired by byJoey/cfy, reviewed at commit
83131b255e46e679d5951108262391b7dcb4c54c. This is an independent implementation;
no upstream code is embedded or executed. Candidates are not speed-test results.
Only fixed public data URLs are requested. Node links never leave this process.
"""

import argparse
from dataclasses import dataclass
import getpass
from html.parser import HTMLParser
import ipaddress
import os
from pathlib import Path
import random
import re
import secrets
import ssl
import stat
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings


CF_V4 = "https://www.cloudflare.com/ips-v4"
CF_V6 = "https://www.cloudflare.com/ips-v6"
WETEST_V4 = "https://www.wetest.vip/page/cloudflare/address_v4.html"
WETEST_V6 = "https://www.wetest.vip/page/cloudflare/address_v6.html"
PUBLIC_URLS = frozenset((CF_V4, CF_V6, WETEST_V4, WETEST_V6))
FILENAME = "cf-nodes.txt"
MAX_LINKS = 30
MAX_URI = 8192
MAX_DOWNLOAD = 1024 * 1024
MAX_SAVED = MAX_LINKS * (MAX_URI + 1)
HTTPS_PORTS = frozenset((443, 2053, 2083, 2087, 2096, 8443))
DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
KNOWN_KEYS = frozenset(("security", "type", "host", "sni", "path", "encryption", "flow",
                        "allowInsecure", "insecure", "skip-cert-verify", "skipCertVerify"))


class SelectionError(Exception):
    """Only fixed messages, never remote bodies or private input, are displayed."""


class Cancelled(Exception):
    pass


def has_controls(value):
    return any(unicodedata.category(char) in ("Cc", "Cf", "Cs", "Zl", "Zp") for char in value)


def safe_label(value, limit=48):
    value = " ".join("".join(char for char in value if not has_controls(char)).split())
    return value[:limit]


def domain_name(value, *, host_header=False):
    if host_header and ":" in value:
        name, separator, port = value.rpartition(":")
        if not separator or not 1 <= len(port) <= 5 or not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            return False
        value = name
    return bool(DOMAIN.fullmatch(value))


@dataclass(frozen=True)
class Template:
    user: str
    host: str
    port: int
    query: str
    label: str
    completed: tuple = ()

    def link(self, address, label):
        address = public_address(address)
        destination = f"[{address}]" if address.version == 6 else str(address)
        result = (f"vless://{self.user}@{destination}:{self.port}?{self.query}#"
                  + urllib.parse.quote(safe_label(label, 120), safe=""))
        if len(result.encode("utf-8")) > MAX_URI:
            raise SelectionError("生成后的链接过长，请使用较短的节点模板。")
        return result


def parse_vless(value):
    if (not isinstance(value, str) or has_controls(value) or len(value.encode("utf-8")) > MAX_URI
            or "\\" in value):
        raise SelectionError("节点链接格式无效，请粘贴完整的 VLESS 链接。")
    value = value.strip(" ")
    try:
        if not value.startswith("vless://") or INVALID_PERCENT.search(value):
            raise ValueError()
        parts = urllib.parse.urlsplit(value)
        if parts.path or parts.password is not None or parts.netloc.count("@") != 1:
            raise ValueError()
        user = parts.username
        if not user or str(uuid.UUID(user)).lower() != user.lower():
            raise ValueError()
        host = parts.hostname
        port = parts.port if parts.port is not None else 443
        if not host or port not in HTTPS_PORTS:
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not domain_name(host):
                raise ValueError()
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                                       encoding="utf-8", errors="strict", max_num_fields=64)
        params = {}
        for key, item in pairs:
            if not key or has_controls(key) or has_controls(item):
                raise ValueError()
            if key in KNOWN_KEYS and key in params:
                raise ValueError()
            params[key] = item
        if params.get("security") != "tls" or params.get("type") != "ws":
            raise SelectionError("仅支持 VLESS + WebSocket + TLS 节点，请先检查模板的传输与安全设置。")
        if params.get("encryption", "none") != "none" or params.get("flow", ""):
            raise SelectionError("此 VLESS 模板包含不兼容的加密或 Flow 设置，请先检查节点配置。")
        if any(params.get(key, "false").lower() not in ("", "0", "false")
               for key in ("allowInsecure", "insecure", "skip-cert-verify", "skipCertVerify")):
            raise SelectionError("模板关闭了 TLS 证书校验，请在客户端恢复校验后再生成优选。")
        path = params.get("path", "/")
        if path and not path.startswith("/"):
            raise ValueError()
        query, completed = parts.query, []
        for key in ("sni", "host"):
            if key not in params:
                if not domain_name(host):
                    raise SelectionError("IP 地址模板需要明确填写 SNI 和 WebSocket Host，无法从 IP 推断域名。")
                query += "&" + key + "=" + urllib.parse.quote(host, safe="")
                completed.append(key)
            elif not domain_name(params[key], host_header=key == "host"):
                raise SelectionError("模板的 SNI 或 WebSocket Host 不是有效域名，请先修正模板。")
        label = urllib.parse.unquote(parts.fragment, encoding="utf-8", errors="strict")
        return Template(user, host, port, query, safe_label(label) or "InstaBox-Tool", tuple(completed))
    except SelectionError:
        raise
    except (ValueError, TypeError, UnicodeError, AttributeError):
        raise SelectionError("节点链接格式无效；需要 UUID、WS/TLS 参数及 Cloudflare 支持的 HTTPS 端口。") from None


def public_address(value):
    try:
        if not isinstance(value, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
            raise ValueError()
        text = str(value)
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        if "%" in text:
            raise ValueError()
        address = ipaddress.ip_address(text)
        if (not address.is_global or address.is_multicast or address.is_reserved
                or address.is_unspecified or address.is_loopback or address.is_link_local):
            raise ValueError()
        return address
    except ValueError:
        raise SelectionError("优选必须是公网 IP 地址，不支持域名、端口、网段或本地地址。") from None


def belongs_to_cloudflare(address, networks):
    return any(address.version == network.version and address in network for network in networks)


def parse_networks(text, family):
    try:
        rows = text.splitlines()
        if not 1 <= len(rows) <= 128:
            raise ValueError()
        networks = []
        for row in rows:
            network = ipaddress.ip_network(row.strip(), strict=True)
            if (network.version != family or network.prefixlen < (8 if family == 4 else 16)
                    or not network.is_global):
                raise ValueError()
            public_address(network.network_address)
            public_address(network.broadcast_address)
            if network not in networks:
                networks.append(network)
        return networks
    except (ValueError, SelectionError, AttributeError):
        raise SelectionError("Cloudflare 官方网段响应无效，本次未生成优选。") from None


class PublicRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.rstrip("/") not in PUBLIC_URLS:
            raise SelectionError("公共数据源跳转到了未识别的地址，本次未继续访问。")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_text(url, *, opener=None):
    if url not in PUBLIC_URLS:
        raise SelectionError("不支持此公共数据源。")
    opener = opener or urllib.request.build_opener(
        PublicRedirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"User-Agent": "InstaBox-Tool-CF-Candidates/1", "Accept": "text/plain,text/html"})
    try:
        with opener.open(request, timeout=12) as response:
            if response.geturl().rstrip("/") not in PUBLIC_URLS:
                raise SelectionError("公共数据源地址无法确认，本次未使用其内容。")
            raw = response.read(MAX_DOWNLOAD + 1)
        if len(raw) > MAX_DOWNLOAD:
            raise SelectionError("公共数据源响应过大，本次未使用其内容。")
        return raw.decode("utf-8", errors="strict")
    except SelectionError:
        raise
    except urllib.error.HTTPError as error:
        raise SelectionError(f"公共数据源暂不可用（HTTP {error.code}），可稍后重试或更换来源。") from None
    except (urllib.error.URLError, OSError, UnicodeError, ValueError):
        raise SelectionError("公共数据源读取失败，请检查联网、系统时间与 CA 证书后重试。") from None


@dataclass(frozen=True)
class Candidate:
    address: str
    label: str = ""


class CandidateTable(HTMLParser):
    """Read labelled table cells, never script content, links or shell text."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows, self.row, self.column, self.parts = [], None, None, []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1
        if self.hidden:
            return
        if tag == "tr":
            self.row, self.column = {}, None
        elif tag in ("td", "th") and self.row is not None:
            label = dict(attrs).get("data-label")
            self.column = label if label in ("优选地址", "线路名称") else None
            self.parts = []

    def handle_data(self, data):
        if not self.hidden and self.column and sum(map(len, self.parts)) < 4096:
            self.parts.append(data[:4096])

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)
            return
        if self.hidden:
            return
        if tag in ("td", "th") and self.row is not None and self.column:
            self.row[self.column] = "".join(self.parts).strip()
            self.column = None
        elif tag == "tr" and self.row is not None:
            if len(self.rows) < 1000:
                self.rows.append(self.row)
            self.row, self.column = None, None


def cloud_candidates(text, networks, count=MAX_LINKS, *, rng=None):
    if not 1 <= count <= MAX_LINKS:
        raise SelectionError("生成数量必须为 1～30。")
    parser = CandidateTable()
    parser.feed(text)
    parser.close()
    candidates, seen = [], set()
    for row in parser.rows:
        try:
            address = public_address(row.get("优选地址", ""))
        except SelectionError:
            continue
        if not belongs_to_cloudflare(address, networks) or str(address) in seen:
            continue
        seen.add(str(address))
        candidates.append(Candidate(str(address), safe_label(row.get("线路名称", ""), 24)))
    if not candidates:
        raise SelectionError("第三方页面没有可验证的 Cloudflare 地址，请改用官方地址优选或手动 IP。")
    (rng or random.SystemRandom()).shuffle(candidates)
    return candidates[:count]


def random_candidates(networks, count, *, rng=None):
    if not 1 <= count <= MAX_LINKS or not networks:
        raise SelectionError("生成数量必须为 1～30。")
    rng = rng or random.SystemRandom()
    candidates, seen = [], set()
    # Bounded even if a future source contains only tiny ranges.
    for _ in range(MAX_LINKS * 100):
        network = rng.choice(networks)
        low = 1 if network.num_addresses > 2 else 0
        high = network.num_addresses - (1 if network.version == 4 and network.num_addresses > 2 else 0)
        address = network.network_address + rng.randrange(low, high)
        if str(address) not in seen:
            public_address(address)
            seen.add(str(address))
            candidates.append(Candidate(str(address)))
        if len(candidates) == count:
            return candidates
    raise SelectionError("官方网段中的独立优选数量不足，请减少生成数量。")


def manual_candidates(text, networks):
    parts = re.split(r"[\s,，]+", text.strip())
    if not 1 <= len(parts) <= MAX_LINKS:
        raise SelectionError("一次可输入 1～30 个 IP，以空格或逗号分隔。")
    result, seen = [], set()
    for part in parts:
        address = public_address(part)
        if not belongs_to_cloudflare(address, networks):
            raise SelectionError("输入包含 Cloudflare 官方网段之外的地址，本次未生成链接。")
        if str(address) not in seen:
            seen.add(str(address))
            result.append(Candidate(str(address)))
    return result


class Sources:
    def __init__(self, fetch=None):
        self.fetch = fetch or download_text
        self.cache = {}

    def networks(self, family):
        if family not in (4, 6):
            raise SelectionError("请选择 IPv4 或 IPv6。")
        if family not in self.cache:
            self.cache[family] = parse_networks(self.fetch(CF_V4 if family == 4 else CF_V6), family)
        return self.cache[family]

    def cloud(self, count, family=4):
        if family not in (0, 4, 6):
            raise SelectionError("请选择 IPv4、IPv6 或双栈。")
        families = (4, 6) if family == 0 else (family,)
        networks = [network for version in families for network in self.networks(version)]
        text = "\n".join(self.fetch(WETEST_V4 if version == 4 else WETEST_V6) for version in families)
        return cloud_candidates(text, networks, count)

    def official(self, family, count):
        return random_candidates(self.networks(family), count)

    def manual(self, text):
        parts = re.split(r"[\s,，]+", text.strip())
        if not 1 <= len(parts) <= MAX_LINKS:
            raise SelectionError("一次可输入 1～30 个 IP，以空格或逗号分隔。")
        families = {public_address(part).version for part in parts}
        networks = [network for family in sorted(families) for network in self.networks(family)]
        return manual_candidates(text, networks)


def local_template(kind, *, probe=None):
    import node_probe
    probe = probe or node_probe.Probe()
    try:
        before = probe.read_file("state.conf", 16384)
        before_config = probe.read_file("config.json")
        public, _ = probe.configuration()
        if public["status"] != "ok":
            raise SelectionError("本机节点配置不一致，请先在节点管理中检查配置。")
        state = dict(line.split("=", 1) for line in before.decode("utf-8").splitlines() if line)
        invocation = None
        if kind == "fixed":
            host, label = state.get("domain", ""), "InstaBox-Tool-Fixed"
            if not domain_name(host) or host.endswith(".trycloudflare.com"):
                raise SelectionError("本机尚未配置有效固定域名，可选择快捷节点或手动输入链接。")
        elif kind == "quick":
            deadline = probe.monotonic() + 4
            first = probe.services(deadline)[node_probe.QUICK_SERVICE]
            log = probe.tunnel_log()
            second = probe.services(deadline)[node_probe.QUICK_SERVICE]
            latest_log = probe.tunnel_log()
            if (not node_probe.same_running_instance(first, second) or not probe.log_current(log, second)
                    or not probe.log_current(latest_log, second) or not log.get("host")
                    or not node_probe.HOST_RE.fullmatch(log["host"])
                    or latest_log.get("host") != log["host"] or latest_log.get("_inode") != log.get("_inode")):
                raise SelectionError("无法确认当前快捷地址，请等待隧道启动完成后用 ibt show 查看，再重新生成。")
            host, label = log["host"], "IBT-Quick"
            invocation = (second["_invocation"], second["_pid"], second["_startedMono"], log.get("_inode"))
        else:
            raise SelectionError("模板来源无效。")
        if (probe.read_file("state.conf", 16384) != before
                or probe.read_file("config.json") != before_config):
            raise SelectionError("本机节点配置正在变化，请重新选择模板。")
        query = urllib.parse.urlencode({"encryption": "none", "security": "tls", "sni": host,
                                        "type": "ws", "host": host, "path": state["path"]})
        template = parse_vless(f"vless://{state['uuid']}@{host}:443?{query}#{label}")
        return template, (before, before_config, invocation)
    except SelectionError:
        raise
    except (node_probe.ProbeError, ValueError, KeyError, UnicodeError, OSError):
        raise SelectionError("本机节点记录无法安全读取，请先安装或检查节点，也可手动输入 VLESS 链接。") from None


class NodeStore:
    def __init__(self, home=None):
        self.home = Path(home) if home is not None else Path.home()

    @staticmethod
    def check_directory(fd, private=False):
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022)):
            raise SelectionError("优选保存目录的权限或归属异常，未修改文件。")

    def directory(self, create=False):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors = []
        try:
            descriptors.append(os.open(self.home, flags))
            self.check_directory(descriptors[-1])
            for name, private in ((".config", False), ("insta-box", True)):
                try:
                    child = os.open(name, flags, dir_fd=descriptors[-1])
                except FileNotFoundError:
                    if not create:
                        return None
                    try:
                        os.mkdir(name, 0o700, dir_fd=descriptors[-1])
                    except FileExistsError:
                        pass
                    child = os.open(name, flags, dir_fd=descriptors[-1])
                descriptors.append(child)
                self.check_directory(child, private)
            return descriptors.pop()
        except OSError:
            raise SelectionError("优选保存目录无法安全访问，未修改文件。") from None
        finally:
            for fd in descriptors:
                os.close(fd)

    @staticmethod
    def existing(directory):
        try:
            info = os.stat(FILENAME, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise SelectionError("优选记录必须是当前用户的独立私有文件，未读取或覆盖。")
        return info

    @staticmethod
    def validate(links):
        if not 1 <= len(links) <= MAX_LINKS:
            raise SelectionError("优选记录数量无效，请重新生成。")
        for link in links:
            parse_vless(link)

    def read(self):
        directory = self.directory()
        if directory is None:
            return None
        try:
            before = self.existing(directory)
            if before is None:
                return None
            fd = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                after = os.fstat(fd)
                if (not stat.S_ISREG(after.st_mode) or after.st_uid != os.getuid() or after.st_nlink != 1
                        or stat.S_IMODE(after.st_mode) & 0o077
                        or (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev)):
                    raise SelectionError("优选记录在读取时发生变化，请重试。")
                if after.st_size > MAX_SAVED:
                    raise SelectionError("优选记录内容过大，请重新生成。")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_SAVED + 1)
            finally:
                os.close(fd)
            if len(raw) > MAX_SAVED:
                raise SelectionError("优选记录内容过大，请重新生成。")
            links = raw.decode("utf-8").splitlines()
            self.validate(links)
            return links
        except (OSError, UnicodeError):
            raise SelectionError("优选记录无法安全读取，请重新生成。") from None
        finally:
            os.close(directory)

    def write(self, links):
        self.validate(links)
        directory = self.directory(create=True)
        temporary, created = ".cf-nodes-" + secrets.token_hex(12), False
        try:
            before = self.existing(directory)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            created = True
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(("\n".join(links) + "\n").encode("utf-8"))
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            current = self.existing(directory)
            identity = lambda item: None if item is None else (item.st_dev, item.st_ino, item.st_mtime_ns, item.st_size)
            if identity(before) != identity(current):
                raise SelectionError("优选记录被另一操作更改，请重试。")
            os.replace(temporary, FILENAME, src_dir_fd=directory, dst_dir_fd=directory)
            created = False
            os.fsync(directory)
        except OSError:
            raise SelectionError("优选结果保存失败，请检查本机空间与权限后重试。") from None
        finally:
            if created:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except OSError:
                    pass
            os.close(directory)


def ask_terminal(prompt, secret=False):
    try:
        # A buffered r+ text stream requires seeking and cannot wrap /dev/tty.
        # Separate streams also work when the launcher reads stdin from a pipe.
        with open("/dev/tty", "r", encoding="utf-8") as terminal_input, \
                open("/dev/tty", "w", encoding="utf-8") as terminal_output:
            if secret:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    return getpass.getpass(prompt, stream=terminal_output)
            terminal_output.write(prompt)
            terminal_output.flush()
            value = terminal_input.readline(MAX_URI + 2)
            if not value:
                raise Cancelled()
            if len(value) > MAX_URI + 1:
                raise SelectionError("输入内容过长，请重新运行并缩短输入。")
            return value.rstrip("\n\r")
    except getpass.GetPassWarning:
        raise SelectionError("终端无法关闭输入回显，未读取节点链接；请重新连接 SSH 终端。") from None
    except (OSError, EOFError):
        raise SelectionError("请在交互终端运行 ibt cf；查看已保存结果可用 ibt cf --show-last。") from None


def choose(ask, output, allowed, prompt="请选择：", default=None):
    while True:
        choice = ask("  " + prompt).strip()
        if not choice and default is not None:
            return default
        if choice in ("", "0"):
            raise Cancelled()
        if choice in allowed:
            return choice
        output("  输入提示： 请输入菜单序号，输入 0 返回。")


def quantity(ask, output):
    while True:
        value = ask("  生成数量（1～30，回车 10，0 取消）：").strip()
        if value == "0":
            raise Cancelled()
        if not value:
            return 10
        if 1 <= len(value) <= 2 and value.isascii() and value.isdigit() and 1 <= int(value) <= MAX_LINKS:
            return int(value)
        output("  输入提示： 生成数量必须为 1～30。")


def show_links(links, output):
    output("  使用说明： 复制整行链接到客户端使用。")
    output("  地址时效： 链接使用生成时的域名；Quick 重建后请重新生成并导入。")
    output("  保存位置： ~/.config/insta-box/cf-nodes.txt（仅当前用户可读）")
    output("  分享提醒： 链接含节点凭据，请勿公开。")
    for index, link in enumerate(links, 1):
        output(f"\n  优选节点： {index:02d}")
        output(link)


def show_last(store, output):
    links = store.read()
    if not links:
        output("  保存结果： 尚未生成优选链接。")
        return 0
    output(f"  保存结果： 共 {len(links)} 条优选链接。")
    show_links(links, output)
    return 0


def interactive(*, ask=ask_terminal, output=print, sources=None, store=None, local_loader=None):
    sources, store = sources or Sources(), store or NodeStore()
    local_loader = local_loader or local_template
    output("  CF 优选")
    output("  功能说明： 为现有 VLESS / WS / TLS 节点生成优选链接。")
    local_kind, fingerprint = None, None
    while True:
        output("\n   1. 本机固定节点\n   2. 本机快捷节点\n   3. 手动输入链接\n   4. 查看上次结果\n   0. 返回上级菜单")
        origin = choose(ask, output, ("1", "2", "3", "4"))
        if origin == "4":
            return show_last(store, output)
        try:
            if origin == "3":
                value = ask("  粘贴 VLESS 链接（输入隐藏，0 取消）：", secret=True)
                if value.strip() in ("", "0"):
                    raise Cancelled()
                template = parse_vless(value)
                local_kind = None
            else:
                local_kind = "fixed" if origin == "1" else "quick"
                template, fingerprint = local_loader(local_kind)
            break
        except SelectionError as error:
            output("  模板提示： " + str(error))
    output("  节点模板： " + template.label)
    if template.completed:
        output("  域名保留： 已将原连接域名补入缺少的 SNI / Host，保证换 IP 后仍使用原域名。")
    output("\n   1. 云端地址优选\n   2. 官方地址优选\n   3. 手动填写地址\n   0. 返回上级菜单")
    source = choose(ask, output, ("1", "2", "3"))
    if source == "1":
        output("\n   1. 使用IPv4地址\n   2. 使用IPv6地址\n   3. 使用双栈地址\n   0. 返回上级菜单")
        family = {"1": 4, "2": 6, "3": 0}[choose(ask, output, ("1", "2", "3"), "地址类型（回车 IPv4）：", "1")]
        count = quantity(ask, output)
        output("  获取进度： 读取云端地址及 Cloudflare 官方网段…")
        candidates = sources.cloud(count, family)
        suffix = "CF-云优选"
    elif source == "2":
        output("\n   1. 使用IPv4地址\n   2. 使用IPv6地址\n   0. 返回上级菜单")
        family = 4 if choose(ask, output, ("1", "2"), "地址类型（回车 IPv4）：", "1") == "1" else 6
        count = quantity(ask, output)
        output("  获取进度： 读取 Cloudflare 官方地址…")
        candidates = sources.official(family, count)
        suffix = "CF-官方优选"
    else:
        value = ask("  输入公网 IP（空格分隔，最多 30 个，0 取消）：")
        if value.strip() in ("", "0"):
            raise Cancelled()
        output("  获取进度： 按 Cloudflare 官方网段核对输入地址…")
        candidates = sources.manual(value)
        suffix = "CF-手动优选"
    if local_kind is not None:
        current, current_fingerprint = local_loader(local_kind)
        if current != template or current_fingerprint != fingerprint:
            raise SelectionError("生成期间本机节点或快捷隧道发生变化，请重新选择当前模板。")
    links = [template.link(candidate.address, f"{template.label}-{suffix}-{index:02d}"
                           + ("-" + candidate.label if candidate.label else ""))
             for index, candidate in enumerate(candidates, 1)]
    store.write(links)
    output(f"\n  生成结果： 已保存 {len(links)} 条优选链接。")
    show_links(links, output)
    return 0


def main(argv=None, *, ask=ask_terminal, output=print, store=None, sources=None, local_loader=None):
    parser = argparse.ArgumentParser(description="为 VLESS/WS/TLS 节点生成 Cloudflare 优选链接。")
    parser.add_argument("--show-last", action="store_true", help="显示上次保存的新链接，不请求网络")
    args = parser.parse_args(argv)
    try:
        if args.show_last:
            return show_last(store or NodeStore(), output)
        return interactive(ask=ask, output=output, store=store, sources=sources, local_loader=local_loader)
    except Cancelled:
        output("  操作结果： 已取消。")
        return 0
    except KeyboardInterrupt:
        output("\n  操作结果： 已取消。")
        return 130
    except SelectionError as error:
        output("  操作提示： " + str(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
