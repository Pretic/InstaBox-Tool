#!/usr/bin/env python3
# Author: Pre
"""Optional SSH token replacement; secrets stay in heartbeat's private config.

POST /ssh-tokens is NOT idempotent. A durable intent precedes every request;
an uncertain response blocks automatic reissuance. Received tokens are saved
before SSH verification, and only a verified token replaces the active one.
"""
import copy
import hashlib
import math
import sys
import time
import uuid

import heartbeat as hb


DEFAULT_TTL = 86400
DEFAULT_ADVANCE = 3600
MAX_TTL = 2592000
RETRY_DELAY = 900
MAX_REJECTED_ATTEMPTS = 3
COMMANDS = {"rotate-setup", "rotate-now", "rotate-off", "token-status"}
DEFINITE_REJECTIONS = {
    "unauthorized", "forbidden", "not_found", "conflict", "rate_limited",
    "key_missing", "key_invalid", "bad_request",
}
AMBIGUOUS_MESSAGE = (
    "上次签发结果未知，平台可能已经创建 token，但秘密未收到；后台不会重复签发。"
    "请运行 ibt keepalive rotate-now 明确处理，或在网页创建连接命令后用 renew 替换。"
)
SHORT_LIFETIME_MESSAGE = (
    "新 token 的平台返回期限已到期或进入提前轮换窗口，无法满足设置的提前量。"
    "当前 SSH 凭据保持不变，后台不再重复签发；请检查 API Key 的剩余期限或轮换提前量。"
    "待这枚 token 到期并修正授权后，可运行 rotate-now；也可从网页创建连接命令后用 renew。"
)


def outcome(status, message="", changed=False):
    return {"status": status, "message": message, "changed": changed}


def fingerprint(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def machine_id(value):
    return isinstance(value, str) and value.startswith("m_") and hb.ID_RE.fullmatch(value)


def rotation_valid(rotation):
    if not isinstance(rotation, dict) or not machine_id(rotation.get("machineId")):
        return False
    ttl, advance = rotation.get("ttlSeconds"), rotation.get("renewBeforeSeconds")
    return (type(ttl) is int and 60 <= ttl <= MAX_TTL and
            type(advance) is int and 1 <= advance < ttl)


def required_advance(config):
    # OnUnitInactiveSec starts after the whole round; targets can move within
    # the next round's queue. Include both round bounds and timer jitter.
    return hb.interval_value(config.get("intervalSeconds")) + 2 * getattr(hb, "ROUND_TIMEOUT_SECONDS", 650) + 16


def pending_valid(pending, machine):
    if not isinstance(pending, dict) or pending.get("machineId") != machine:
        return False
    ssh = pending.get("ssh")
    try:
        expiry = hb.parse_time(pending.get("expiresAt"))
    except (TypeError, ValueError, OverflowError):
        return False
    return (math.isfinite(expiry) and isinstance(pending.get("id"), str) and
            pending["id"].startswith("cn_") and hb.ID_RE.fullmatch(pending["id"]) and
            isinstance(ssh, dict) and isinstance(ssh.get("user"), str) and
            hb.TOKEN_RE.fullmatch(ssh["user"]) and ssh.get("host") == hb.GATEWAY and
            type(ssh.get("port")) is int and 1 <= ssh["port"] <= 65535 and
            ssh.get("family") in (None, "inet", "inet6"))


def received_token(response, target, intent):
    """Keep only the fields needed to verify a grant, never execute command."""
    if not isinstance(response, dict):
        raise ValueError("invalid response")
    ssh = hb.parse_ssh_command(response.get("command"))
    if (ssh["user"] != response.get("token") or ssh["host"] != response.get("host") or
            ssh["port"] != response.get("port") or response.get("name") != intent["body"]["name"]):
        raise ValueError("inconsistent response")
    ssh["family"] = target["ssh"].get("family")
    pending = {"id": response.get("id"), "machineId": response.get("machineId"),
               "ssh": ssh, "expiresAt": response.get("expiresAt")}
    if not pending_valid(pending, target["rotation"]["machineId"]):
        raise ValueError("invalid grant")
    pending["expiresAt"] = hb.iso_time(hb.parse_time(pending["expiresAt"]))
    return pending


def failure_message(code):
    if code in ("unauthorized", "forbidden", "key_missing", "key_invalid"):
        return ("SSH 自动轮换所需 API Key 缺失、失效或权限不足；需要 machines:write。"
                "更新授权后运行 rotate-now；也可从网页创建连接命令，再用 renew 手动替换。")
    if code == "rate_limited":
        return "SSH token 签发被平台限流；后台只做有限重试，当前 SSH 凭据保持不变。"
    return "SSH token 签发被平台拒绝；检查目标机器和权限，当前 SSH 凭据保持不变。"


def maybe_rotate(config, target, api, probe, save, *, now=None, force=False,
                 allow_ambiguous=False):
    """Run under the manager's process lock. save(target) must be atomic/private.

    api(method, route, body=None) must disable redirects and mutation retries.
    probe(candidate) returns a dict only after a real SSH command succeeds.
    Only status='rotated' proves that the new credential passed this round's
    SSH check. No errors or returned messages contain API response text.
    """
    rotation = target.get("rotation")
    if target.get("kind") != "ssh" or not isinstance(rotation, dict):
        return outcome("disabled")
    if not force and not (rotation.get("enabled") is True or rotation.get("armed") is True):
        return outcome("disabled")
    if not rotation_valid(rotation):
        return outcome("blocked", "自动轮换缺少明确的 API 机器绑定或有效期限；请重新运行 rotate-setup。")
    minimum = required_advance(config)
    if rotation["renewBeforeSeconds"] < minimum:
        return outcome("blocked", "当前检查间隔与整轮执行余量要求至少提前 " + str(minimum) + " 秒换新；请调整间隔或重新运行 rotate-setup，未自动签发。")
    now = time.time() if now is None else now
    work = copy.deepcopy(target)
    rotation = work["rotation"]

    def persist():
        saved = copy.deepcopy(work)
        save(saved)  # durable before publishing any local change or POST
        target.clear()
        target.update(copy.deepcopy(saved))

    def uncertain(code="request_unknown"):
        rotation["intent"]["state"] = "ambiguous"
        rotation["lastErrorCode"] = code
        persist()
        return outcome("ambiguous", AMBIGUOUS_MESSAGE)

    active_expiry = rotation.get("activeExpiresAt")
    if active_expiry:
        if rotation.get("activeFingerprint") != fingerprint(work["ssh"]["user"]):
            return outcome("blocked", "当前 SSH 凭据与轮换记录不一致；请重新明确绑定机器，未自动签发。")
        try:
            actual_expiry = hb.parse_time(active_expiry)
        except (TypeError, ValueError, OverflowError):
            return outcome("blocked", "平台到期记录无效；请重新检查轮换配置。")
        verified = {"kind": "verified", "expiresAt": hb.iso_time(actual_expiry)}
        if work.get("tokenExpiry") != verified:
            work["tokenExpiry"] = verified
            persist()  # a user estimate cannot replace the server's actual expiry
    else:
        actual_expiry = None

    if rotation.get("needsAction") == "short_lifetime" and not force:
        return outcome("blocked", SHORT_LIFETIME_MESSAGE)

    pending = rotation.get("pending")
    if pending is not None:
        if not pending_valid(pending, rotation["machineId"]):
            return outcome("blocked", "已保存的待验收 token 记录无效；未再次签发，请检查或手工更新授权。")
        if hb.parse_time(pending["expiresAt"]) <= now:
            # Its known bounded lifetime ended; there is no live unknown grant.
            rotation.pop("pending", None)
            rotation.pop("intent", None)
            rotation.pop("needsAction", None)
            persist()
            pending = None

    intent = rotation.get("intent")
    if pending is None and intent:
        if not isinstance(intent, dict) or intent.get("state") not in ("in_flight", "ambiguous", "rejected"):
            return outcome("blocked", "本地签发记录无效；未再次签发，请人工检查。")
        if intent["state"] in ("in_flight", "ambiguous"):
            if not allow_ambiguous:
                return uncertain()
            rotation.pop("intent", None)
            intent = None  # only an explicitly confirmed foreground action gets here
        elif not force:
            if intent.get("attempts", 0) >= MAX_REJECTED_ATTEMPTS:
                return outcome("blocked", failure_message(rotation.get("lastErrorCode")) + " 自动重试已暂停，请运行 rotate-now。")
            if intent.get("retryAt", 0) > now:
                return outcome("blocked", failure_message(rotation.get("lastErrorCode")))

    if pending is None:
        if not force and not intent and actual_expiry is not None and actual_expiry - now > rotation["renewBeforeSeconds"]:
            return outcome("not_due")
        # If the issuing key has an earlier deadline, new tokens may have the
        # same effective expiry. Avoid issuing again on every timer tick.
        if not force and rotation.get("nextRotationAt", 0) > now:
            return outcome("not_due")
        if intent is None:
            request_id = uuid.uuid4().hex
            intent = {"localId": request_id, "state": "in_flight", "attempts": 0,
                      "requestedAt": hb.iso_time(now),
                      "body": {"name": "ib-rotate-" + config["controllerId"][:8] + "-" + request_id,
                               "ttlSeconds": rotation["ttlSeconds"]}}
            rotation["intent"] = intent
        body = intent.get("body")
        if (not isinstance(body, dict) or set(body) != {"name", "ttlSeconds"} or
                not isinstance(body.get("name"), str) or not hb.ID_RE.fullmatch(body["name"]) or
                len(body["name"]) > 100 or body.get("ttlSeconds") != rotation["ttlSeconds"] or
                type(intent.get("attempts")) is not int or intent["attempts"] < 0):
            return outcome("blocked", "已保存的签发请求无效；未发送请求，请检查轮换配置。")
        intent["state"] = "in_flight"
        intent["attempts"] = int(intent.get("attempts", 0)) + 1
        rotation["lastAttemptAt"] = hb.iso_time(now)
        persist()
        route = "/v1/machines/" + rotation["machineId"] + "/ssh-tokens"
        try:
            response = api("POST", route, copy.deepcopy(intent["body"]))
        except Exception as error:
            code = getattr(error, "code", "request_unknown")
            if code not in DEFINITE_REJECTIONS:
                return uncertain()
            intent["state"] = "rejected"
            intent["retryAt"] = now + RETRY_DELAY
            rotation["lastErrorCode"] = code
            persist()
            return outcome("blocked", failure_message(code))
        try:
            pending = received_token(response, work, intent)
        except Exception:
            return uncertain("invalid_response")
        rotation["pending"] = pending
        rotation.pop("intent", None)
        rotation.pop("lastErrorCode", None)
        persist()  # do not lose the secret if SSH verification fails or we crash

    if hb.parse_time(pending["expiresAt"]) - now <= rotation["renewBeforeSeconds"]:
        rotation["needsAction"] = "short_lifetime"
        persist()
        return outcome("blocked", SHORT_LIFETIME_MESSAGE)
    candidate = copy.deepcopy(work)
    candidate["ssh"] = copy.deepcopy(pending["ssh"])
    candidate["tokenExpiry"] = {"kind": "verified", "expiresAt": pending["expiresAt"]}
    try:
        if not isinstance(probe(candidate), dict):
            raise ValueError("probe did not confirm success")
    except Exception:
        rotation["lastErrorCode"] = "verification_failed"
        persist()
        return outcome("pending", "新 token 已私有保存但 SSH 验收未成功；仍使用旧凭据，下轮只重试验收，不重复签发。")

    work["ssh"] = candidate["ssh"]
    work["tokenExpiry"] = candidate["tokenExpiry"]
    work["revision"] = uuid.uuid4().hex
    rotation["enabled"] = rotation.get("enabled") is True or rotation.get("armed") is True
    rotation["armed"] = False
    rotation["activeTokenId"] = pending["id"]
    rotation["activeExpiresAt"] = pending["expiresAt"]
    rotation["activeFingerprint"] = fingerprint(pending["ssh"]["user"])
    rotation["lastRotatedAt"] = hb.iso_time(now)
    remaining = max(1, hb.parse_time(pending["expiresAt"]) - now)
    rotation["nextRotationAt"] = now + min(RETRY_DELAY, max(1, remaining / 2))
    rotation.pop("pending", None)
    rotation.pop("intent", None)
    rotation.pop("lastErrorCode", None)
    rotation.pop("needsAction", None)
    persist()
    return outcome("rotated", "新 SSH token 已经实际连接验证并原子替换；平台返回到期时间为 " + hb.format_timestamp(work["tokenExpiry"]["expiresAt"]) + "。API Key 过期或撤销仍可能使其提前失效；旧 token 未撤销。", True)


def hours_value(text, default_seconds, maximum):
    if not text.strip():
        return default_seconds
    try:
        hours = float(text)
    except (TypeError, ValueError):
        hours = float("nan")
    if not math.isfinite(hours) or not 0 < hours <= maximum / 3600:
        raise hb.HeartbeatError("请输入有效的正数小时。", "rotation_config")
    seconds = int(hours * 3600)
    if seconds < 1:
        raise hb.HeartbeatError("期限至少为 1 秒。", "rotation_config")
    return seconds


def rotation_api(manager):
    return lambda method, route, body=None: manager.client.request(method, route, manager.read_key(), body)


def status_lines(target):
    rotation = target.get("rotation", {})
    if not isinstance(rotation, dict) or not rotation:
        return ["自动换新： 未配置；普通 SSH 保活不需要 API Key。"]
    state = "已启用" if rotation.get("enabled") is True else "首次验收待完成" if rotation.get("armed") is True else "已停用"
    lines = ["自动换新： " + state, "绑定机器： " + hb.clean(rotation.get("machineId", "未绑定"))]
    if rotation_valid(rotation):
        lines.append("申请时长： " + str(rotation["ttlSeconds"]) + " 秒")
        lines.append("提前换新： " + str(rotation["renewBeforeSeconds"]) + " 秒")
    if rotation.get("activeExpiresAt"):
        lines.append("当前到期： " + hb.format_timestamp(rotation["activeExpiresAt"]) + "（平台返回）")
        lines.append("授权说明： API Key 过期或撤销仍可能使 token 提前失效。")
    if rotation.get("pending"):
        lines.append("待验凭据： 已私有保存；验证成功前保持当前凭据，不重复签发。")
    if rotation.get("needsAction") == "short_lifetime":
        lines.append(SHORT_LIFETIME_MESSAGE)
    intent = rotation.get("intent", {})
    if isinstance(intent, dict) and intent.get("state") in ("in_flight", "ambiguous"):
        lines.append(AMBIGUOUS_MESSAGE)
    elif rotation.get("lastErrorCode"):
        code = rotation["lastErrorCode"]
        lines.append("上次新 token 连接验收失败，待重试。" if code == "verification_failed" else failure_message(code))
    return lines


def setup(manager, selector):
    previous = manager.load_config(required=True)
    selected = manager.select_target(previous, selector, kind="ssh")
    old_rotation = selected.get("rotation", {})
    if isinstance(old_rotation, dict) and (old_rotation.get("pending") or old_rotation.get("intent")):
        raise hb.HeartbeatError("已有待验收或结果未知的签发记录；先用 rotate-now 处理，或手工 renew 后重新配置。", "rotation_pending")
    key = manager.authorize()  # foreground setup only; background never prompts
    machines = manager.list_machines(key)
    if not machines:
        raise hb.HeartbeatError("当前 API Key 下没有可绑定的机器。", "selection")
    manager.say("SSH token 不包含可读取的机器 ID；请明确选择这个 SSH 目标要绑定的 API 机器。")
    from cloud import fit_text, table_lines
    rows = [[str(index), fit_text(hb.clean(machine["name"], 80), 24),
             hb.MACHINE_LABELS.get(machine["state"], "状态未知"), machine["id"]]
            for index, machine in enumerate(machines, 1)]
    for line in table_lines(["编号", "名称", "状态", "机器 ID"], rows):
        manager.say(line)
    answer = manager.prompt("绑定机器编号（空行取消）：").strip()
    if not answer or answer == "0":
        raise hb.Cancelled()
    if not answer.isdigit() or not 1 <= int(answer) <= len(machines):
        raise hb.HeartbeatError("机器编号无效；不会根据旧 token 猜测目标。", "selection")
    machine = machines[int(answer) - 1]
    if not machine_id(machine["id"]):
        raise hb.HeartbeatError("返回的机器 ID 无效。", "invalid_response")
    minimum = required_advance(previous)
    manager.say("当前调度至少需提前 " + str(minimum) + " 秒换新，以给整轮执行和排队留出余量；默认提前 1 小时。")
    ttl = hours_value(manager.prompt("新 token 有效小时 [24]："), DEFAULT_TTL, MAX_TTL)
    advance = hours_value(manager.prompt("提前多少小时轮换 [1]："), DEFAULT_ADVANCE, MAX_TTL)
    if ttl < 60 or advance >= ttl:
        raise hb.HeartbeatError("TTL 至少 60 秒，提前量必须小于 TTL。", "rotation_config")
    if advance < minimum:
        raise hb.HeartbeatError("提前量必须至少为 " + str(minimum) + " 秒，且 TTL 必须更长；未签发 token。", "rotation_config")
    manager.say("将为 " + selected["label"] + " 绑定 " + machine["name"] + " [" + machine["id"] + "]，签发并验证一个新 token 后替换。")
    if manager.prompt("确认绑定与替换？[y/N]：").strip().lower() not in ("y", "yes"):
        raise hb.Cancelled()
    with manager.lock() as acquired:
        if not acquired:
            raise hb.HeartbeatError("保活轮次正在运行，请稍后重试轮换配置。", "busy")
        config = manager.load_config(required=True)
        if config != previous:
            raise hb.HeartbeatError("配置已变化，请重新选择；未签发 token。", "config_changed")
        target = manager.select_target(config, selected["id"], kind="ssh")
        prepared = copy.deepcopy(target)
        prepared["rotation"] = {"enabled": False, "armed": True, "machineId": machine["id"],
                                "ttlSeconds": ttl, "renewBeforeSeconds": advance}
        manager.persist_target(config, prepared)
        target = next(row for row in config["targets"] if row["id"] == prepared["id"])
        result = maybe_rotate(config, target, rotation_api(manager), manager.check_ssh,
                              lambda updated: manager.persist_target(config, updated), now=manager.clock(), force=True)
    manager.say(result["message"])
    return 0 if result["status"] == "rotated" else 2


def rotate_now(manager, selector):
    previous = manager.load_config(required=True)
    selected = manager.select_target(previous, selector, kind="ssh")
    rotation = selected.get("rotation", {})
    if not rotation_valid(rotation):
        raise hb.HeartbeatError("请先运行 rotate-setup 明确绑定 API 机器。", "rotation_config")
    allow_ambiguous = False
    intent = rotation.get("intent", {})
    if isinstance(intent, dict) and intent.get("state") in ("in_flight", "ambiguous") and not rotation.get("pending"):
        manager.say(AMBIGUOUS_MESSAGE)
        allow_ambiguous = manager.prompt("重新创建会新增一个 grant，旧 grant 不会撤销。确认重新创建？[y/N]：").strip().lower() in ("y", "yes")
        if not allow_ambiguous:
            raise hb.Cancelled()
    with manager.lock() as acquired:
        if not acquired:
            raise hb.HeartbeatError("保活轮次正在运行，请稍后再轮换。", "busy")
        config = manager.load_config(required=True)
        if config != previous:
            raise hb.HeartbeatError("配置已变化，请重新选择；未签发 token。", "config_changed")
        target = manager.select_target(config, selected["id"], kind="ssh")
        result = maybe_rotate(config, target, rotation_api(manager), manager.check_ssh,
                              lambda updated: manager.persist_target(config, updated), now=manager.clock(),
                              force=True, allow_ambiguous=allow_ambiguous)
    manager.say(result["message"])
    return 0 if result["status"] == "rotated" else 2


def disable(manager, selector):
    previous = manager.load_config(required=True)
    selected = manager.select_target(previous, selector, kind="ssh")
    with manager.lock() as acquired:
        if not acquired:
            raise hb.HeartbeatError("保活轮次正在运行，请稍后停用轮换。", "busy")
        config = manager.load_config(required=True)
        if config != previous:
            raise hb.HeartbeatError("配置已变化，请重新选择。", "config_changed")
        target = copy.deepcopy(manager.select_target(config, selected["id"], kind="ssh"))
        if isinstance(target.get("rotation"), dict):
            target["rotation"].update(enabled=False, armed=False)
            manager.persist_target(config, target)
    manager.say("自动轮换已停用；当前 token 和待验收记录保留。未撤销任何 token，现有 SSH 会话不受此操作影响。")
    return 0


def token_status(manager, selector):
    config = manager.load_config(required=True)
    targets = [manager.select_target(config, selector, kind="ssh")] if selector else [row for row in config["targets"] if row["kind"] == "ssh"]
    for index, target in enumerate(targets, 1):
        if index > 1:
            manager.say("")
        manager.say(str(index) + ". " + hb.clean(target["label"], 80))
        for line in status_lines(target):
            manager.say("  " + line)
    return 0 if targets else 2


def dispatch(manager, args):
    if not args or args[0] not in COMMANDS or len(args) > 2:
        raise hb.HeartbeatError("使用 rotate-setup|rotate-now|rotate-off|token-status [目标名称或ID]。", "arguments")
    selector = args[1] if len(args) == 2 else None
    return {"rotate-setup": setup, "rotate-now": rotate_now,
            "rotate-off": disable, "token-status": token_status}[args[0]](manager, selector)


def main(args=None, manager=None):
    manager = manager or hb.Manager()
    try:
        return dispatch(manager, sys.argv[1:] if args is None else args)
    except KeyboardInterrupt:
        manager.say("操作被中断，签发结果尚未确认；已持久保存的记录会保留，请检查 token-status，后台不会盲目重复签发。")
        return 130
    except (hb.Cancelled, EOFError):
        manager.say("已取消；已持久保存的签发记录会保留，未自动重复签发。")
        return 0
    except hb.HeartbeatError as error:
        manager.say("[失败] " + str(error))
        return 2
    except Exception:
        manager.say("[失败] token 轮换未确认完成；检查 token-status，当前记录已保留，不会盲目重复签发。")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
