import time
import json
import re
import urllib.parse
import asyncio
from collections import defaultdict, deque

from astrbot import logger
from astrbot.api.star import Context, Star, register
from astrbot.api.event import filter
from astrbot.core.star.filter.event_message_type import EventMessageType
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent as AstrMessageEvent

# 新增：异步 HTTP 请求
try:
    import aiohttp
except Exception:  # 兜底：如果环境没装 aiohttp，这里给出占位提示
    aiohttp = None
    logger.error("未检测到 aiohttp，‘我要看美女’接口将无法调用，请安装 aiohttp。")


@register(
    "YouGroup-management",
    "You",
    "敏感词自动撤回插件(关键词匹配+刷屏检测+群管指令+查共群+查询违规+看美女)",
    "1.2.7",
    "https://github.com/QingBaoNie/YouGroup-management"
)
class AutoRecallKeywordPlugin(Star):
    # =========================================================
    # 初始化（成员变量、默认结构）
    # =========================================================
    def __init__(self, context: Context, config):
        super().__init__(context)
        self.config = config

        # 消息追踪（刷屏检测）
        self.user_message_times = defaultdict(lambda: deque(maxlen=5))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=5))

        # 权限/名单集合
        self.kick_black_list = set()
        self.target_user_list = set()
        self.sub_admin_list = set()
        self.whitelist = set()

        # 自动回复冷却
        self.auto_reply_last_time = {}
        self.auto_reply_cooldown = 10

        # 主人账号（从配置读取）
        self.owner_qq = ""

        # 看美女冷却（按群）
        self.beauty_last_time = {}
        self.beauty_cooldown = 10  # 秒（接口访问限频）

        # 视频发送限频（按群）
        self.video_last_time = {}
        self.video_cooldown = 60  # 秒（发送视频防刷屏）

        # 入群事件短期去重：记录 (group_id, user_id)
        self._join_seen = set()

    # =========================================================
    # 初始化配置（从外部 config 注入、解析开关、打印日志）
    # =========================================================
    async def initialize(self):
        config_data = self.config
        self.bad_words = config_data.get("bad_words", [])

        # --- 刷屏配置 ---
        spam_config = config_data.get("spam_config", {})
        self.spam_count = spam_config.get("spam_count", 5)
        self.spam_interval = spam_config.get("spam_interval", 3)
        self.spam_ban_duration = spam_config.get("spam_ban_duration", 60)

        # --- 群管配置 ---
        admin_config = config_data.get("admin_config", {})
        self.sub_admin_list = set(admin_config.get("sub_admin_list", []))
        self.kick_black_list = set(admin_config.get("kick_black_list", []))
        self.target_user_list = set(admin_config.get("target_user_list", []))
        self.whitelist = set(admin_config.get("whitelist", []))

        # 主人QQ从配置读取
        self.owner_qq = str(admin_config.get("owner_qq", "")).strip()

        # --- 自动回复规则（支持 {face:ID} 变量，发送时转换）---
        auto_replies_config = config_data.get("auto_replies", [])
        self.auto_replies = {}
        for item in auto_replies_config:
            if "-" in item:
                key, val = item.split("-", 1)
                self.auto_replies[key.strip()] = val.strip()

        # --- 功能开关：稳健布尔解析 ---
        def _to_bool(v):
            if isinstance(v, bool): return v
            if isinstance(v, (int, float)): return v != 0
            if isinstance(v, str): return v.strip().lower() in {"1", "true", "yes", "on"}
            return False

        self.recall_links   = _to_bool(admin_config.get("recall_links", False))    # 链接撤回
        self.recall_cards   = _to_bool(admin_config.get("recall_cards", False))    # 卡片撤回
        self.recall_numbers = _to_bool(admin_config.get("recall_numbers", False))  # 连续数字撤回
        self.recall_forward = _to_bool(admin_config.get("recall_forward", False))  # 合并转发/组合消息撤回

        # --- 超长文本撤回配置 ---
        self.recall_long_text = _to_bool(admin_config.get("recall_long_text", True))
        try:
            self.max_text_length = int(admin_config.get("max_text_length", 100))
        except Exception:
            self.max_text_length = 100

        # --- 入群邀请策略 ---
        self.auto_accept_owner_invite = _to_bool(admin_config.get("auto_accept_owner_invite", True))
        self.reject_non_owner_invite  = _to_bool(admin_config.get("reject_non_owner_invite", True))

        # --- 数据持久化 ---
        self.save_json_data()

        # --- 刷屏窗口长度根据配置重置 ---
        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        # --- 启动日志 ---
        logger.info(f"主人QQ: {self.owner_qq or '(未配置)'}")
        logger.info(f"敏感词列表: {self.bad_words}")
        logger.info(f"自动回复规则: {self.auto_replies}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s 禁言{self.spam_ban_duration}s")
        logger.info(f"子管理员: {self.sub_admin_list} 黑名单: {self.kick_black_list} 针对名单: {self.target_user_list} 白名单: {self.whitelist}")
        logger.info(f"撤回配置: links={self.recall_links}, cards={self.recall_cards}, numbers={self.recall_numbers}, forward={self.recall_forward}")
        logger.info(f"超长文本撤回: enable={self.recall_long_text}, max_text_length={self.max_text_length}")
        logger.info(f"入群邀请: auto_accept_owner_invite={self.auto_accept_owner_invite}, reject_non_owner_invite={self.reject_non_owner_invite}")

    # =========================================================
    # 工具函数：将内存数据保存到本地（名单类）
    # =========================================================
    def save_json_data(self):
        data = {
            'kick_black_list': list(self.kick_black_list),
            'target_user_list': list(self.target_user_list),
            'sub_admin_list': list(self.sub_admin_list),
            'whitelist': list(self.whitelist),
        }
        with open('cesn_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("已保存数据到 cesn_data.json")

    # =========================================================
    # 工具函数：延迟自动撤回指定 message_id
    # =========================================================
    async def _auto_delete_after(self, bot, message_id: int, delay: int = 60):
        try:
            await asyncio.sleep(delay)
            await bot.delete_msg(message_id=message_id)
        except Exception as e:
            logger.error(f"定时撤回失败 message_id={message_id}: {e}")

    # =========================================================
    # 工具函数：纯文本检测（避免 CQ 段落误判）
    # =========================================================
    def _is_pure_text(self, event: AstrMessageEvent, message_str: str) -> bool:
        try:
            segs = getattr(event.message_obj, 'message', None)
            if isinstance(segs, list) and segs:
                for seg in segs:
                    s_type = seg.get("type") if isinstance(seg, dict) else getattr(seg, "type", "")
                    s_type = (s_type or "").lower()
                    if s_type not in ("text", "text_plain", "plain"):
                        return False
                return True
        except Exception:
            pass
        cq_like_markers = ("[CQ:", "[引用消息]", "[At:", "[图片]", "[表情]", "[语音]", "[视频]")
        return not any(m in message_str for m in cq_like_markers)

    # =========================================================
    # 工具函数：检测 @ 或 回复段
    # =========================================================
    def _has_at_or_reply(self, event: AstrMessageEvent, message_str: str) -> bool:
        try:
            for seg in getattr(event.message_obj, 'message', []):
                s_type = seg.get("type") if isinstance(seg, dict) else getattr(seg, "type", "")
                s_type = (s_type or "").lower()
                if s_type in ("at", "reply"):
                    return True
        except Exception:
            pass
        return ("[CQ:at" in message_str) or ("[CQ:reply" in message_str)

    # =========================================================
    # 工具函数：号码标准化
    # =========================================================
    def _normalize_for_number_check(self, s: str) -> str:
        full = "０１２３４５６７８９"
        trans = {ord(full[i]): ord('0') + i for i in range(10)}
        s = s.translate(trans)
        s = re.sub(r"[\s\-\._]", "", s)
        s = s.replace("\u200b", "").replace("\u2060", "").replace("\u2061", "").replace("\u2062", "").replace("\u2063", "")
        return s

    # =========================================================
    # 工具函数：检测合并转发/组合消息
    # =========================================================
    def _has_forward_message(self, event: AstrMessageEvent, message_str: str) -> bool:
        try:
            for seg in getattr(event.message_obj, 'message', []):
                if isinstance(seg, dict):
                    s_type = (seg.get("type") or "").lower()
                else:
                    s_type = (getattr(seg, "type", "") or "").lower()
                if s_type in ("forward", "node", "merge_forward", "multi_msg", "multimsg", "multi-message"):
                    return True
        except Exception:
            pass
        if "[CQ:forward" in message_str:
            return True
        if "转发消息" in message_str:
            return True
        return False

    # =========================================================
    # 工具函数：提取“可见文本”长度（忽略CQ段与零宽等）
    # =========================================================
    def _visible_text_length(self, event: AstrMessageEvent, message_str: str) -> int:
        text_buf = []
        try:
            for seg in getattr(event.message_obj, 'message', []):
                if isinstance(seg, dict):
                    s_type = (seg.get("type") or "").lower()
                    if s_type in ("text", "text_plain", "plain"):
                        data = seg.get("data", {})
                        t = data.get("text", "")
                        if isinstance(t, str):
                            text_buf.append(t)
                else:
                    s_type = (getattr(seg, "type", "") or "").lower()
                    if s_type in ("text", "text_plain", "plain"):
                        t = getattr(getattr(seg, "data", None), "text", None) or getattr(seg, "text", "")
                        if isinstance(t, str):
                            text_buf.append(t)
        except Exception:
            pass
        if not text_buf:
            s = re.sub(r"\[CQ:[^\]]+\]", "", message_str)
        else:
            s = "".join(text_buf)
        s = s.replace("\u200b", "").replace("\u2060", "").replace("\u2061", "").replace("\u2062", "").replace("\u2063", "")
        s = s.strip()
        return len(s)

    # =========================================================
    # 权限相关
    # =========================================================
    async def _get_member_role(self, event: AstrMessageEvent, group_id: int, user_id: int) -> str:
        try:
            info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(user_id))
            return info.get("role", "member")
        except Exception as e:
            logger.error(f"获取用户 {user_id} 在群 {group_id} 角色失败: {e}")
            return "member"

    async def _is_operator(self, event: AstrMessageEvent, group_id: int, user_id: int) -> bool:
        if self.owner_qq and str(user_id) == self.owner_qq:
            return True
        role = await self._get_member_role(event, group_id, user_id)
        if role in ("owner", "admin"):
            return True
        if str(user_id) in self.sub_admin_list:
            return True
        return False

    async def _get_self_user_id(self, event: AstrMessageEvent):
        try:
            info = await event.bot.get_login_info()
            uid = info.get('user_id')
            return str(uid) if uid is not None else None
        except Exception:
            try:
                uid = getattr(event.bot, 'self_id', None) or \
                      getattr(getattr(event, 'message_obj', None), 'self_id', None) or \
                      getattr(event, 'self_id', None)
                return str(uid) if uid is not None else None
            except Exception:
                return None

    async def _bot_is_admin(self, event: AstrMessageEvent, group_id: int) -> bool:
        try:
            self_id = await self._get_self_user_id(event)
            if not self_id:
                return False
            info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(self_id))
            return info.get('role', 'member') in ('owner', 'admin')
        except Exception:
            return False

    # =========================================================
    # 入群邀请处理
    # =========================================================
    async def _approve_group_request(self, event: AstrMessageEvent, flag: str, sub_type: str, approve: bool, reason: str = ""):
        try:
            await event.bot.set_group_add_request(flag=flag, sub_type=sub_type, approve=approve, reason=reason)
        except Exception as e:
            logger.error(f"处理群请求失败 flag={flag} sub_type={sub_type} approve={approve}: {e}")

    @filter.event_message_type(getattr(EventMessageType, "REQUEST", EventMessageType.GROUP_MESSAGE))
    async def _on_group_request_owner_invite_v1(self, event: AstrMessageEvent):
        await self._handle_group_invite_common(event)

    @filter.event_message_type(getattr(EventMessageType, "GROUP_REQUEST", EventMessageType.GROUP_MESSAGE))
    async def _on_group_request_owner_invite_v2(self, event: AstrMessageEvent):
        await self._handle_group_invite_common(event)

    async def _handle_group_invite_common(self, event: AstrMessageEvent):
        try:
            raw = getattr(event.message_obj, "raw_message", {}) or {}
            request_type = (getattr(raw, "request_type", None) or raw.get("request_type"))
            sub_type = (getattr(raw, "sub_type", None) or raw.get("sub_type"))
            flag = (getattr(raw, "flag", None) or raw.get("flag"))
            group_id = (getattr(raw, "group_id", None) or raw.get("group_id"))
            user_id = (getattr(raw, "user_id", None) or raw.get("user_id"))
        except Exception as e:
            logger.error(f"解析群请求事件失败: {e}")
            return

        if request_type != "group" or not sub_type or not flag:
            return

        if sub_type == "invite":
            inviter = str(user_id) if user_id is not None else ""
            if self.auto_accept_owner_invite and self.owner_qq and inviter == self.owner_qq:
                if hasattr(event, "mark_action"):
                    event.mark_action("敏感词插件 - 自动同意主人邀请入群")
                logger.info(f"主人({self.owner_qq})邀请加入群 {group_id}，自动同意。")
                await self._approve_group_request(event, flag=flag, sub_type="invite", approve=True)
                return

            if self.reject_non_owner_invite:
                if hasattr(event, "mark_action"):
                    event.mark_action("敏感词插件 - 拒绝非主人邀请入群")
                logger.info(f"收到非主人({inviter})的邀请入群到 {group_id}，已拒绝并私聊提示。")
                await self._approve_group_request(event, flag=flag, sub_type="invite", approve=False, reason="不要拉我")
                try:
                    if inviter:
                        await event.bot.send_private_msg(user_id=int(inviter), message="不要拉我")
                except Exception as e:
                    logger.error(f"向邀请者({inviter})发送私聊提示失败: {e}")
            else:
                logger.info(f"收到非主人({inviter})邀请，配置为不处理，已忽略。")
            return

    # =========================================================
    # 入群即踢黑（唯一监听 + 10 秒去重）
    # =========================================================
    async def _expire_join_seen(self, key: tuple[int, int], ttl: int = 10):
        await asyncio.sleep(ttl)
        self._join_seen.discard(key)

    # 仅注册一次，向下兼容不同枚举：优先 NOTICE，缺了就退回 GROUP_MESSAGE
    @filter.event_message_type(getattr(EventMessageType, "NOTICE", EventMessageType.GROUP_MESSAGE))
    async def _on_group_increase(self, event: AstrMessageEvent):
        raw = getattr(event.message_obj, "raw_message", {}) or {}
        # 不是通知就不处理（若退回到了 GROUP_MESSAGE，这里会直接 return）
        if str(raw.get("post_type", "")) != "notice":
            return

        # 兼容多种“入群”标识
        ntype = str(raw.get("notice_type", ""))
        if ntype not in {"group_increase", "group_member_increase", "group_member"}:
            return

        try:
            group_id = int(raw["group_id"])
            user_id = int(raw.get("user_id") or raw.get("member_id") or raw.get("target_id") or 0)
        except Exception:
            return
        if not user_id:
            return

        # 10 秒内去重，避免同一个人入群多次触发
        key = (group_id, user_id)
        if key in self._join_seen:
            return
        self._join_seen.add(key)
        asyncio.create_task(self._expire_join_seen(key, ttl=10))

        # 命中黑名单则立刻踢
        await self._kick_if_in_blacklist(event, group_id, user_id)

    # =========================================================
    # 新增工具：如果在黑名单，立即踢出（用于入群通知）
    # =========================================================
    async def _kick_if_in_blacklist(self, event: AstrMessageEvent, group_id: int, user_id: int) -> bool:
        uid = str(user_id)
        if uid not in self.kick_black_list:
            return False

        # 需要机器人有管理权限
        if not await self._bot_is_admin(event, int(group_id)):
            logger.error(f"[入群踢黑] 发现黑名单 {uid} 但机器人非管理，无法踢出")
            return False

        try:
            # 优先尝试拒绝再次加群；适配器不支持该参数时兜底
            try:
                await event.bot.set_group_kick(group_id=int(group_id), user_id=int(user_id), reject_add_request=True)
            except TypeError:
                await event.bot.set_group_kick(group_id=int(group_id), user_id=int(user_id))

            logger.info(f"[入群踢黑] 黑名单用户 {uid} 已被踢出群 {group_id}")
            try:
                await event.bot.send_group_msg(group_id=int(group_id), message=f"检测到黑名单用户 {uid}，已自动踢出。")
            except Exception:
                pass
            return True
        except Exception as e:
            logger.error(f"[入群踢黑] 踢出黑名单 {uid} 失败：{e}")
            return False

    # =========================================================
    # 自动回复：支持 {face:ID} 自动转 CQ 表情段
    # =========================================================
    def _parse_message_with_faces(self, text: str):
        segments = []
        pos = 0
        for m in re.finditer(r"\{face:(\d+)\}", text):
            if m.start() > pos:
                segments.append({"type": "text", "data": {"text": text[pos:m.start()]}})
            face_id = int(m.group(1))
            segments.append({"type": "face", "data": {"id": face_id}})
            pos = m.end()
        if pos < len(text):
            segments.append({"type": "text", "data": {"text": text[pos:]}})
        return segments if segments else [{"type": "text", "data": {"text": text}}]

    # =========================================================
    # 主动退群命令
    # =========================================================
    async def handle_owner_leave_group(self, event: AstrMessageEvent, message_str: str) -> bool:
        sender = str(event.get_sender_id())
        logger.debug(f"[leave-cmd] owner_qq={self.owner_qq!r} sender={sender!r} msg={message_str!r}")
        if not (self.owner_qq and sender == self.owner_qq):
            return False
        text = message_str.strip()
        m = re.match(r"^(?:退群[#＃]|群号[#＃])\s*(\d{4,12})\s*$", text)
        if not m:
            m = re.match(r"^(?:退群|群号)\s+(\d{4,12})\s*$", text)
        if not m:
            logger.debug("[leave-cmd] pattern not matched")
            return False
        target_gid = m.group(1)
        cur_gid = event.get_group_id()
        try:
            await event.bot.send_group_msg(group_id=int(cur_gid), message=f"群号:{target_gid}\n已退群！！！")
        except Exception as e:
            logger.error(f"[leave-cmd] 回执失败（当前群={cur_gid} 目标群={target_gid}）：{e}")
        try:
            await event.bot.send_group_msg(group_id=int(target_gid), message="宝宝们,有缘再见~")
        except Exception as e:
            logger.error(f"[leave-cmd] 给目标群({target_gid})发送告别失败：{e}")
        try:
            try:
                await event.bot.set_group_leave(group_id=int(target_gid))
            except TypeError:
                await event.bot.set_group_leave(group_id=int(target_gid), is_dismiss=False)
            logger.info(f"[leave-cmd] 已退出群 {target_gid}")
        except Exception as e:
            logger.error(f"[leave-cmd] 退出群({target_gid})失败：{e}")
            try:
                await event.bot.send_group_msg(group_id=int(cur_gid), message=f"退出群 {target_gid} 失败：{e}")
            except Exception:
                pass
        return True

    # =========================================================
    # “我要看美女”视频 URL
    # =========================================================
    async def _fetch_beauty_video_url(self) -> str | None:
        if aiohttp is None:
            return None

        api_url = "http://api.xiaomei520.sbs/api/jk/"

        def _is_video_like_url(u: str) -> bool:
            u = (u or "").lower()
            return any(u.endswith(ext) for ext in (".mp4", ".m3u8", ".webm", ".mov", ".avi", ".flv"))

        try:
            timeout = aiohttp.ClientTimeout(total=12)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(api_url, allow_redirects=True) as resp:
                    hist = " -> ".join(str(h.url) for h in resp.history) if resp.history else "(no-redirect)"
                    final_url = str(resp.url)
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    clen  = resp.headers.get("Content-Length")

                    logger.debug(f"[美女接口] status={resp.status} history={hist} final={final_url} ctype={ctype} clen={clen}")

                    if "video/" in ctype or "application/octet-stream" in ctype or _is_video_like_url(final_url):
                        logger.debug(f"[美女接口] detected direct video link: {final_url}")
                        return final_url

                    raw = await resp.content.read(4096)
                    if not raw:
                        logger.warning("[美女接口] 空响应体（非视频）")
                        return None

                    def _smart_decode(b: bytes) -> str:
                        for enc in ("utf-8", "gbk", "gb2312", "big5", "latin-1"):
                            try:
                                return b.decode(enc)
                            except Exception:
                                continue
                        return b.decode("utf-8", errors="ignore")

                    preview = _smart_decode(raw)
                    logger.debug(f"[美女接口] body-preview={preview[:200]!r}")

                    try:
                        data = json.loads(preview)
                        if isinstance(data, dict):
                            for k in ("url", "video", "mp4", "data", "src"):
                                v = data.get(k)
                                if isinstance(v, str) and v.startswith("http"):
                                    logger.debug(f"[美女接口] json-hit: {k}={v}")
                                    return v
                            joined = json.dumps(data, ensure_ascii=False)
                            m = re.search(r"https?://[^\s\"'}<>]+", joined)
                            if m:
                                logger.debug(f"[美女接口] json-scan url={m.group(0)}")
                                return m.group(0)
                    except Exception:
                        pass

                    m = re.search(r"https?://[^\s\"'}<>]+", preview)
                    if m:
                        logger.debug(f"[美女接口] text-scan url={m.group(0)}")
                        return m.group(0)

        except Exception as e:
            logger.error(f"调用美女接口失败: {e}")

        logger.warn("[美女接口] 未解析到有效 URL（可能服务器直接 302 到视频但被拦/跨域/鉴权）")
        return None

    # =========================================================
    # 刷屏累加并视情况禁言 + 批量撤回（统一入口）
    # =========================================================
    async def _spam_bump_and_maybe_ban(self, event: AstrMessageEvent, group_id: int, sender_id: int, message_id: int, now: float = None):
        now = now or time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)
        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                if await self._bot_is_admin(event, int(group_id)):
                    try:
                        await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                        logger.error(f"触发【刷屏】已禁言 uid={sender_id} {self.spam_ban_duration}s，gid={group_id}")
                    except Exception as e:
                        logger.error(f"刷屏禁言失败 gid={group_id} uid={sender_id}: {e}")
                    for mid in list(self.user_message_ids[key]):  # 快照遍历
                        try:
                            await event.bot.delete_msg(message_id=mid)
                        except Exception as e:
                            logger.error(f"刷屏批量撤回失败 mid={mid}: {e}")
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

    # =========================================================
    # 核心入口：群消息自动处理
    # =========================================================
    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        if getattr(event.message_obj.raw_message, 'post_type', '') == 'notice':
            return

        group_id = event.get_group_id()
        sender_id = event.get_sender_id()
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id

        # ---------- 主人主动退群命令 ----------
        handled = await self.handle_owner_leave_group(event, message_str)
        if handled:
            return

        # ---------- 我要看美女 ----------
        if "我要看美女" in message_str:
            now = time.time()
            last_video = self.video_last_time.get(group_id, 0)
            if now - last_video < self.video_cooldown:
                try:
                    resp = await event.bot.send_group_msg(group_id=int(group_id), message="不发！少🦌行不行！")
                    if isinstance(resp, dict) and "message_id" in resp:
                        asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=8))
                except Exception as e:
                    logger.error(f"发送30秒限制提示失败: {e}")
                return

            last_api = self.beauty_last_time.get(group_id, 0)
            if now - last_api < self.beauty_cooldown:
                remain = int(self.beauty_cooldown - (now - last_api))
                try:
                    resp = await event.bot.send_group_msg(group_id=int(group_id), message=f"别急呀~ 冷却中 {remain}s")
                    if isinstance(resp, dict) and "message_id" in resp:
                        asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=8))
                except Exception as e:
                    logger.error(f"发送接口冷却提示失败: {e}")
                return

            video_url = await self._fetch_beauty_video_url()
            if not video_url:
                try:
                    await event.bot.send_group_msg(group_id=int(group_id), message="接口开小差了，一会儿再试下~")
                except Exception as e:
                    logger.error(f"发送接口失败提示异常: {e}")
                return

            logger.debug(f"[美女接口] final url={video_url}")

            try:
                if video_url.lower().endswith(".m3u8"):
                    await event.bot.send_group_msg(group_id=int(group_id), message=video_url)
                else:
                    msg_seg = [{"type": "video", "data": {"file": video_url}}]
                    await event.bot.send_group_msg(group_id=int(group_id), message=msg_seg)
            except Exception as e:
                logger.error(f"发送视频段失败，回退为链接: {e}")
                try:
                    await event.bot.send_group_msg(group_id=int(group_id), message=video_url)
                except Exception as e2:
                    logger.error(f"发送视频链接也失败: {e2}")
            finally:
                self.video_last_time[group_id] = now
                self.beauty_last_time[group_id] = now
            return

        # ---------- 自动回复（带冷却） ----------
        now_time = time.time()
        last_reply_time = self.auto_reply_last_time.get(group_id, 0)
        if now_time - last_reply_time >= self.auto_reply_cooldown:
            for key, reply in self.auto_replies.items():
                if key in message_str:
                    try:
                        await event.bot.send_group_msg(
                            group_id=int(group_id),
                            message=self._parse_message_with_faces(reply)
                        )
                        self.auto_reply_last_time[group_id] = now_time
                    except Exception as e:
                        logger.error(f"自动回复失败: {e}")
                    break

        # ---------- 指令：查询违规 ----------
        if message_str.startswith("查询违规"):
            await self.handle_check_violation(event)
            return

        # ---------- 指令：查共群 ----------
        if message_str.startswith("查共群"):
            await self.handle_check_common_groups(event)
            return

        # ---------- 群管命令分发 ----------
        command_keywords = (
            "禁言", "解禁", "解言", "踢黑", "解黑",
            "踢", "针对", "解针对", "设置管理员", "移除管理员", "撤回",
            "全体禁言", "全体解言",
            "加白", "移白", "白名单列表",
            "黑名单列表", "针对列表", "管理员列表",
        )
        if message_str.startswith(command_keywords):
            if not await self._is_operator(event, int(group_id), int(sender_id)):
                try:
                    resp = await event.bot.send_group_msg(group_id=int(group_id), message="你配指挥我吗？")
                    if isinstance(resp, dict) and "message_id" in resp:
                        asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=10))
                except Exception as e:
                    logger.error(f"发送无权限提示失败: {e}")
                return
            await self.handle_commands(event)
            return

        # ---------- 群主/管理员发言跳过撤回 ----------
        try:
            member_info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(sender_id))
            if member_info.get("role", "member") in ("owner", "admin"):
                return
        except Exception as e:
            logger.error(f"获取用户 {sender_id} 群身份失败: {e}")

        # ---------- 黑名单：发言触发兜底 ----------
        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            await event.bot.send_group_msg(group_id=int(group_id), message=f"检测到黑名单用户 {sender_id}，已踢出！")
            return

        # ---------- 白名单/针对名单 ----------
        is_whitelisted = str(sender_id) in self.whitelist
        if not is_whitelisted and (str(sender_id) in self.target_user_list):
            await self._spam_bump_and_maybe_ban(event, group_id, sender_id, message_id)
            await self.try_recall(event, message_id, group_id, sender_id)
            return

        # ---------- 超长文本撤回 ----------
        if (not is_whitelisted) and self.recall_long_text:
            try:
                vlen = self._visible_text_length(event, message_str)
                if vlen >= self.max_text_length:
                    logger.error(f"触发【超长文本】可见长度={vlen} 阈值={self.max_text_length}，已静默撤回 sender={sender_id} gid={group_id}")
                    await self.try_recall(event, message_id, group_id, sender_id)
                    return
            except Exception as e:
                logger.error(f"超长文本检测异常: {e}")

        # ---------- 违禁词撤回 ----------
        if not is_whitelisted:
            for word in self.bad_words:
                if word and word in message_str:
                    if await self._bot_is_admin(event, int(group_id)):
                        logger.error(f"触发违禁词【{word}】已撤回！")
                        await self.try_recall(event, message_id, group_id, sender_id)
                    return

        # ---------- 链接撤回 ----------
        if (not is_whitelisted) and self.recall_links and ("http://" in message_str or "https://" in message_str):
            logger.error(f"触发【链接】已撤回！")
            await self.try_recall(event, message_id, group_id, sender_id)
            return

        # ---------- 卡片撤回 ----------
        if (not is_whitelisted) and self.recall_cards:
            for segment in getattr(event.message_obj, 'message', []):
                seg_type = getattr(segment, 'type', '')
                if seg_type in ['Share', 'Card', 'Contact', 'Json', 'Xml', 'share', 'json', 'xml', 'contact']:
                    logger.error(f"触发【卡片】已撤回！")
                    await self.try_recall(event, message_id, group_id, sender_id)
                    return

        # ---------- 合并转发/组合消息撤回 ----------
        if (not is_whitelisted) and self.recall_forward:
            if self._has_forward_message(event, message_str):
                logger.error("触发【转发消息】已撤回！")
                await self.try_recall(event, message_id, group_id, sender_id)
                return

        # ---------- 连续数字撤回 ----------
        if (not is_whitelisted) and self.recall_numbers:
            has_at_or_reply = self._has_at_or_reply(event, message_str)
            logger.debug(
                f"num-check debug | gid={group_id} uid={sender_id} "
                f"whitelisted={is_whitelisted} recall_numbers={self.recall_numbers} "
                f"has_at_or_reply={has_at_or_reply} msg='{message_str}'"
            )
            if not has_at_or_reply:
                norm = self._normalize_for_number_check(message_str)
                if re.search(r"(?<!\d)\d{6,}(?!\d)", norm):
                    logger.error(f"检测到连续数字，已撤回 {sender_id} 的消息: 原='{message_str}' | 标准化='{norm}'")
                    await self.try_recall(event, message_id, group_id, sender_id)
                    return

        # ---------- 刷屏检测（禁言 + 批量撤回） ----------
        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)
        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                if await self._bot_is_admin(event, int(group_id)):
                    logger.error(f"触发【刷屏】已禁言并批量撤回！")
                    await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                    for msg_id in list(self.user_message_ids[key]):
                        try:
                            await event.bot.delete_msg(message_id=msg_id)
                        except Exception as e:
                            logger.error(f"刷屏批量撤回失败: {e}")
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

    # =========================================================
    # 撤回封装（输出失败原因/角色）
    # =========================================================
    async def try_recall(self, event: AstrMessageEvent, message_id: str, group_id: int, sender_id: int):
        try:
            await event.bot.delete_msg(message_id=message_id)
        except Exception as e:
            try:
                member_info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(sender_id))
                role = member_info.get('role', 'member')
                logger.error(f"撤回失败: {e}（用户角色: {role}）")
            except Exception as ex:
                logger.error(f"撤回失败且查询用户角色失败: {e} / 查询错误: {ex}")

    # =========================================================
    # 功能指令：查共群
    # =========================================================
    async def handle_check_common_groups(self, event: AstrMessageEvent):
        group_id = event.get_group_id()
        msg = event.message_str.strip()
        m = re.search(r"^查共群\s+(\d{5,12})$", msg)
        if not m:
            resp = await event.bot.send_group_msg(
                group_id=int(group_id),
                message="用法：查共群 <QQ号>（例如：查共群 123123）"
            )
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"]))
            return
        uin = m.group(1)
        base_url = f"https://ti.qq.com/friends/recall?uin={uin}"
        qr_api = "https://api.qrserver.com/v1/create-qr-code/"
        params = f"size=360x360&margin=0&data={urllib.parse.quote_plus(base_url)}"
        qr_url = f"{qr_api}?{params}"
        message_segments = [
            {"type": "text", "data": {"text": f"扫描以下二维码查询『{uin}』与你的共同群（60秒后自动撤回）\n"}},
            {"type": "image", "data": {"file": qr_url}},
        ]
        try:
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 查共群")
            resp = await event.bot.send_group_msg(group_id=int(group_id), message=message_segments)
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"]))
        except Exception as e:
            logger.error(f"发送二维码失败，退回文本方式: {e}")
            resp = await event.bot.send_group_msg(
                group_id=int(group_id),
                message=f"扫描以下二维码查询『{uin}』与你的共同群（120秒后自动撤回）：\n{base_url}"
            )
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"]))

    # =========================================================
    # 功能指令：查询违规
    # =========================================================
    async def handle_check_violation(self, event: AstrMessageEvent):
        group_id = event.get_group_id()
        base_url = "https://m.q.qq.com/a/s/07befc388911b30c2359bfa383f2d693"
        qr_api = "https://api.qrserver.com/v1/create-qr-code/"
        params = f"size=360x360&margin=0&data={urllib.parse.quote_plus(base_url)}"
        qr_url = f"{qr_api}?{params}"
        message_segments = [
            {"type": "text", "data": {"text": "扫描二维码『查询违规』\n"}},
            {"type": "image", "data": {"file": qr_url}},
        ]
        try:
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 查询违规")
            resp = await event.bot.send_group_msg(group_id=int(group_id), message=message_segments)
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=60))
        except Exception as e:
            logger.error(f"查询违规二维码发送失败，回退文本：{e}")
            resp = await event.bot.send_group_msg(
                group_id=int(group_id),
                message=f"查询违规链接（60秒后自动撤回）：\n{base_url}"
            )
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=60))

    # =========================================================
    # 工具：从消息里抽取目标QQ（优先 #QQ号，其次 @）
    # =========================================================
    def _extract_target_from_msg(self, event: AstrMessageEvent, msg: str) -> str | None:
        # 1) 先找 #QQ号
        m = re.search(r"#\s*(\d{5,12})", msg)
        if m:
            return m.group(1)

        # 2) 再从消息段里找 @
        at_list = []
        for segment in getattr(event.message_obj, 'message', []):
            seg_type = getattr(segment, 'type', '')
            if seg_type in ('At', 'at'):
                qq = getattr(segment, 'qq', None)
                if qq is None and isinstance(segment, dict):
                    qq = segment.get('data', {}).get('qq') or segment.get('qq')
                if qq:
                    at_list.append(str(qq))
        if at_list:
            return at_list[0]

        return None

    # =========================================================
    # 群管命令处理（支持 @ 与 #QQ号；禁言/撤回后缀数字）
    # =========================================================
    async def handle_commands(self, event: AstrMessageEvent):
        msg = event.message_str.strip()
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        # 权限校验
        if not await self._is_operator(event, int(group_id), int(sender_id)):
            try:
                resp = await event.bot.send_group_msg(group_id=int(group_id), message="你配指挥我吗？")
                if isinstance(resp, dict) and "message_id" in resp:
                    asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=10))
            except Exception as e:
                logger.error(f"发送无权限提示失败: {e}")
            return

        # 无需目标QQ的命令（保留原逻辑）
        if msg.startswith("全体禁言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 全体禁言")
            try:
                await event.bot.set_group_whole_ban(group_id=int(group_id), enable=True)
                await event.bot.send_group_msg(group_id=int(group_id), message="已开启全体禁言")
            except Exception as e:
                logger.error(f"开启全体禁言失败: {e}")
            return

        if msg.startswith("全体解言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 全体解言")
            try:
                await event.bot.set_group_whole_ban(group_id=int(group_id), enable=False)
                await event.bot.send_group_msg(group_id=int(group_id), message="已关闭全体禁言")
            except Exception as e:
                logger.error(f"关闭全体禁言失败: {e}")
            return

        if msg.startswith("白名单列表"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 白名单列表")
            items = sorted(self.whitelist, key=lambda x: int(x))
            count = len(items)
            text = "以下为 白名单QQ 总计{}\n{}".format(count, ("\n".join(items) if items else "（空）"))
            await event.bot.send_group_msg(group_id=int(group_id), message=text)
            return

        if msg.startswith("黑名单列表"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 黑名单列表")
            items = sorted(self.kick_black_list, key=lambda x: int(x))
            count = len(items)
            text = "以下为 黑名单QQ 总计{}\n{}".format(count, ("\n".join(items) if items else "（空）"))
            await event.bot.send_group_msg(group_id=int(group_id), message=text)
            return

        if msg.startswith("针对列表"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 针对列表")
            items = sorted(self.target_user_list, key=lambda x: int(x))
            count = len(items)
            text = "以下为 针对名单QQ 总计{}\n{}".format(count, ("\n".join(items) if items else "（空）"))
            await event.bot.send_group_msg(group_id=int(group_id), message=text)
            return

        if msg.startswith("管理员列表"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 管理员列表")
            try:
                items = sorted(self.sub_admin_list, key=lambda x: int(x))
            except Exception:
                items = sorted(self.sub_admin_list)
            count = len(items)
            text = "以下为 子管理员QQ 总计{}\n{}".format(count, ("\n".join(items) if items else "（空）"))
            await event.bot.send_group_msg(group_id=int(group_id), message=text)
            return

        # 需要目标QQ的命令：支持 @xx 与 #QQ号
        target_id = self._extract_target_from_msg(event, msg)
        if not target_id:
            logger.error("未检测到目标用户（缺少 @ 或 #QQ号）")
            await event.bot.send_group_msg(group_id=int(group_id), message="请使用 @或 #QQ号 指定目标")
            return

        logger.info(f"检测到命令针对 {target_id} | 原消息: {msg}")

        # 小工具：解析消息尾部的整数（如“ … 5”）
        def _parse_tail_int(_msg: str, default_val: int) -> int:
            m = re.search(r"(\d+)\s*$", _msg)
            return int(m.group(1)) if m else default_val

        if msg.startswith("禁言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 禁言")
            minutes = _parse_tail_int(msg, 10)  # 默认10分钟
            duration = minutes * 60
            try:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=duration)
                await event.bot.send_group_msg(group_id=int(group_id), message=f"已禁言 {target_id} {minutes} 分钟")
            except Exception as e:
                logger.error(f"禁言失败 gid={group_id} uid={target_id}: {e}")

        elif msg.startswith(("解禁", "解言")):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解禁")
            try:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=0)
                await event.bot.send_group_msg(group_id=int(group_id), message=f"已解除 {target_id} 禁言")
            except Exception as e:
                logger.error(f"解禁失败 gid={group_id} uid={target_id}: {e}")

        elif msg.startswith("踢黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢黑")
            try:
                if target_id in self.kick_black_list:
                    await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已在黑名单，无需重复添加。")
                else:
                    self.kick_black_list.add(target_id)
                    self.save_json_data()
                    try:
                        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id), reject_add_request=True)
                    except TypeError:
                        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
                    await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已加入踢黑名单并踢出")
            except Exception as e:
                logger.error(f"踢黑失败 gid={group_id} uid={target_id}: {e}")

        elif msg.startswith("解黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解黑")
            self.kick_black_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移出踢黑名单")

        elif msg.startswith("踢"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢")
            try:
                await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
                await event.bot.send_group_msg(group_id=int(group_id), message=f"已踢出 {target_id}")
            except Exception as e:
                logger.error(f"踢出失败 gid={group_id} uid={target_id}: {e}")

        elif msg.startswith("针对"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 针对")
            self.target_user_list.add(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已加入针对名单")

        elif msg.startswith("解针对"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解针对")
            self.target_user_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移出针对名单")

        elif msg.startswith("设置管理员"):
            # 修正：这里必须用 and，而不是意外的中文“和”
            if self.owner_qq and str(sender_id) != self.owner_qq:
                await event.bot.send_group_msg(group_id=int(group_id), message="只有主人才能设置管理员。")
                return
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 设置管理员")
            if target_id in self.sub_admin_list:
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已存在管理员无需新增！")
            else:
                self.sub_admin_list.add(target_id)
                self.save_json_data()
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已设为子管理员")

        elif msg.startswith("移除管理员"):
            # 修正：and
            if self.owner_qq and str(sender_id) != self.owner_qq:
                await event.bot.send_group_msg(group_id=int(group_id), message="只有主人才能移除管理员。")
                return
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 移除管理员")
            if target_id in self.sub_admin_list:
                self.sub_admin_list.discard(target_id)
                self.save_json_data()
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移除子管理员")
            else:
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 不在管理员列表中，无需移除。")

        elif msg.startswith("撤回"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 撤回")
            # 支持“撤回#QQ号 5”或“撤回@xx 5”，默认5条
            recall_count = _parse_tail_int(msg, 5)
            try:
                history = await event.bot.get_group_msg_history(group_id=int(group_id), count=100)
            except Exception as e:
                logger.error(f"获取历史消息失败: {e}")
                return
            deleted = 0
            for msg_data in reversed(history.get('messages', [])):
                if deleted >= recall_count:
                    break
                if str(msg_data.get('sender', {}).get('user_id')) == target_id:
                    try:
                        await event.bot.delete_msg(message_id=msg_data['message_id'])
                        deleted += 1
                    except Exception as e:
                        logger.error(f"撤回 {target_id} 消息 {msg_data.get('message_id')} 失败: {e}")
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已撤回 {target_id} 的 {deleted} 条消息")


    # =========================================================
    # 插件卸载钩子
    # =========================================================
    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
