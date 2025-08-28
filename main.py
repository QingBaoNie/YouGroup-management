import time
import os
import shutil
import json
import re
import urllib.parse
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta
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
try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_OK = True
except Exception:
    _PIL_OK = False
    logger.error("未检测到 Pillow（PIL），发言统计将只输出文本。建议 pip install pillow")

@register(
    "YouGroup-management",
    "You",
    "敏感词自动撤回插件：集关键词过滤、刷屏检测、群管指令、查共群、违规查询、看美女、身份认证于一体的多功能群管助手。",
    "1.3.0",
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

        # 踢/踢黑后撤回数量（可在配置覆盖）
        self.recall_on_kick_count = 10

        # —— 新增：权威映射（uid -> 标签），默认无条目即“无名小辈”
        self.authority_cert = {}  # { "123456": "自定义标签", ... }

        # —— 新增：独立文件
        self.auth_data_file = "auth_data.json"

        # —— 群成员索引（避免单人查询超时/误判）
        self._member_index: dict[int, dict[str, dict]] = {}      # { group_id: { uid: rec } }
        self._member_index_built_at: dict[int, float] = {}       # { group_id: ts }
        self._member_idx_ttl = 60  # 秒：索引过期时间，过期会自动重建
        # === 发言统计配置 ===
        self.talk_base_dir = "talk_stats"   # 根目录：talk_stats/<group_id>/stats.json
        self.talk_keep_days = 60            # 保留最近 60 天

    # =========================================================
    # 初始化配置（从外部 config 注入、解析开关、打印日志）
    # =========================================================
    async def initialize(self):
        # 先尝试加载本地持久化数据（若存在）
        self._load_json_data()
        # 加载独立文件（含旧数据迁移）
        self._load_auth_data()

        config_data = self.config
        self.bad_words = config_data.get("bad_words", [])

        # --- 刷屏配置 ---
        spam_config = config_data.get("spam_config", {})
        self.spam_count = spam_config.get("spam_count", 5)
        self.spam_interval = spam_config.get("spam_interval", 3)
        self.spam_ban_duration = spam_config.get("spam_ban_duration", 60)

        # --- 群管配置 ---
        admin_config = config_data.get("admin_config", {})
        # 合并配置与持久化（配置优先生效）
        self.sub_admin_list |= set(admin_config.get("sub_admin_list", []))
        self.kick_black_list |= set(admin_config.get("kick_black_list", []))
        self.target_user_list |= set(admin_config.get("target_user_list", []))
        self.whitelist |= set(admin_config.get("whitelist", []))

        # 主人QQ从配置读取
        self.owner_qq = str(admin_config.get("owner_qq", "")).strip() or self.owner_qq

        # 新增：踢出/踢黑时撤回最近 N 条（默认 10）
        try:
            self.recall_on_kick_count = int(admin_config.get("recall_on_kick_count", self.recall_on_kick_count))
        except Exception:
            pass

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

        # --- 数据持久化（名单类）
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
        logger.info(f"踢/踢黑后撤回最近条数: {self.recall_on_kick_count}")
        logger.info(f"权威条目: {len(self.authority_cert)}")
    # =========================================================
    # 发言统计工具函数 - 每群独立存储
    # =========================================================
    def _stats_dir_of(self, group_id: int) -> str:
        """返回某群的统计目录路径"""
        return os.path.join(self.talk_base_dir, str(group_id))

    def _stats_file_of(self, group_id: int) -> str:
        """返回某群的统计文件路径"""
        return os.path.join(self._stats_dir_of(group_id), "stats.json")

    def _load_group_stats(self, group_id: int) -> dict:
        """加载某群的统计文件"""
        path = self._stats_file_of(group_id)
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = {"by_day": {}}
        except Exception as e:
            logger.error(f"[talk] 加载失败 gid={group_id}: {e}")
            data = {"by_day": {}}
        data.setdefault("by_day", {})
        return data

    def _save_group_stats(self, group_id: int, stats: dict):
        """保存某群的统计文件"""
        try:
            os.makedirs(self._stats_dir_of(group_id), exist_ok=True)
            with open(self._stats_file_of(group_id), "w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"[talk] 保存失败 gid={group_id}: {e}")

    def _prune_old_days_inplace(self, stats: dict, keep_days: int):
        """删除超出保留天数的旧数据"""
        try:
            by_day = stats.get("by_day", {})
            days = sorted(by_day.keys())
            if len(days) > keep_days:
                for d in days[:-keep_days]:
                    by_day.pop(d, None)
        except Exception as e:
            logger.error(f"[talk] 清理历史失败: {e}")

    def _today_str(self) -> str:
        """返回今天的日期字符串 YYYYMMDD"""
        return time.strftime("%Y%m%d", time.localtime())

    def _bump_talk_today(self, group_id: int, user_id: int):
        """对指定群今日发言 +1"""
        stats = self._load_group_stats(group_id)
        by_day = stats.setdefault("by_day", {})
        d = self._today_str()
        day_map = by_day.setdefault(d, {})
        uid = str(user_id)
        day_map[uid] = int(day_map.get(uid, 0)) + 1
        self._prune_old_days_inplace(stats, self.talk_keep_days)
        self._save_group_stats(group_id, stats)

    def _query_day_counts(self, group_id: int, day_str: str) -> dict[str, int]:
        """返回某群某天的 {uid: count}"""
        stats = self._load_group_stats(group_id)
        return dict(stats.get("by_day", {}).get(day_str, {}))

    def _query_last_n_days_sum(self, group_id: int, n: int) -> dict[str, int]:
        """返回某群最近 n 天的汇总 {uid: sum}"""
        stats = self._load_group_stats(group_id)
        by_day = stats.get("by_day", {})
        res: dict[str, int] = {}
        try:
            today = datetime.fromtimestamp(time.time())
            for i in range(n):
                d = (today - timedelta(days=i)).strftime("%Y%m%d")
                for uid, c in by_day.get(d, {}).items():
                    res[uid] = res.get(uid, 0) + int(c)
        except Exception as e:
            logger.error(f"[talk] 聚合失败 gid={group_id}: {e}")
        return res

    def _delete_group_talk_data(self, group_id: int):
        """清空某群的统计数据"""
        try:
            d = self._stats_dir_of(group_id)
            if os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)
                logger.info(f"[talk] 已清空群 {group_id} 的统计数据")
        except Exception as e:
            logger.error(f"[talk] 删除群统计目录失败 gid={group_id}: {e}")


# =========================================================
# 工具函数：从本地 JSON 恢复（若存在）—— 仅名单类
# =========================================================
def _load_json_data(self):
    try:
        with open('cesn_data.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.kick_black_list = set(data.get('kick_black_list', []))
        self.target_user_list = set(data.get('target_user_list', []))
        self.sub_admin_list = set(data.get('sub_admin_list', []))
        self.whitelist = set(data.get('whitelist', []))
        logger.info("已从 cesn_data.json 加载名单类数据")
    except FileNotFoundError:
        logger.info("首次运行：未发现 cesn_data.json，将在后续保存时创建。")
    except Exception as e:
        logger.error(f"读取 cesn_data.json 失败：{e}")

    # =========================================================
    # 新增：数据独立读写 + 旧数据迁移
    # =========================================================
    def _load_auth_data(self):
        # 1) 尝试直接读 auth_data.json
        try:
            with open(self.auth_data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.authority_cert = dict(data.get("authority_cert", {}))
            logger.info(f"已从 {self.auth_data_file} 加载认证数据，条目={len(self.authority_cert)}")
            return
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.error(f"读取 {self.auth_data_file} 失败：{e}")

        # 2) 不存在则尝试从旧 cesn_data.json 迁移
        try:
            with open("cesn_data.json", "r", encoding="utf-8") as f:
                old = json.load(f)
            old_map = dict(old.get("authority_cert", {}))
            if old_map:
                self.authority_cert = old_map
                self.save_auth_data()
                # 清理旧文件内的 authority_cert 字段，避免重复
                try:
                    del old["authority_cert"]
                    with open("cesn_data.json", "w", encoding="utf-8") as f:
                        json.dump(old, f, ensure_ascii=False, indent=2)
                except Exception:
                    pass
                logger.info("已从 cesn_data.json 迁移认证数据到 auth_data.json")
            else:
                logger.info("未发现旧认证数据，创建全新 auth_data.json")
                self.save_auth_data()
        except FileNotFoundError:
            logger.info("未发现旧 cesn_data.json，创建空的 auth_data.json")
            self.save_auth_data()
        except Exception as e:
            logger.error(f"迁移旧认证数据失败：{e}")
            # 兜底：写一个空文件
            self.save_auth_data()

    def save_auth_data(self):
        data = {"authority_cert": self.authority_cert}
        try:
            with open(self.auth_data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"已保存认证数据到 {self.auth_data_file}")
        except Exception as e:
            logger.error(f"保存 {self.auth_data_file} 失败：{e}")

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
        logger.info("已保存名单类数据到 cesn_data.json")
    async def _safe_call(self, bot, action: str, **params):
        """统一调用 API，失败时只打日志不抛异常"""
        try:
            return await bot.call_action(action, **params)
        except Exception as e:
            logger.error(f"[safe-call] action={action} params={params} 失败: {e}")
            return None

    async def _safe_send_group_msg(self, bot, group_id: int, message):
        return await self._safe_call(bot, "send_group_msg", group_id=int(group_id), message=message)

    async def _safe_delete_msg(self, bot, message_id: int):
        return await self._safe_call(bot, "delete_msg", message_id=message_id)

    async def _safe_set_group_ban(self, bot, group_id: int, user_id: int, duration: int):
        return await self._safe_call(bot, "set_group_ban", group_id=int(group_id), user_id=int(user_id), duration=duration)

    async def _safe_set_group_kick(self, bot, group_id: int, user_id: int, reject_add_request: bool = False):
        return await self._safe_call(bot, "set_group_kick", group_id=int(group_id), user_id=int(user_id), reject_add_request=reject_add_request)
    
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
    # 权限相关（基于群成员索引）
    # =========================================================
    def _role_of(self, rec: dict | None) -> str:
        return (rec or {}).get("role", "member")

    async def _get_member_role(self, event: AstrMessageEvent, group_id: int, user_id: int) -> str:
        # 先查索引，不在则强刷一次后再判定
        try:
            rec = await self.get_member_record(event, int(group_id), int(user_id))
            return self._role_of(rec)
        except Exception as e:
            logger.error(f"获取用户 {user_id} 在群 {group_id} 角色失败(索引): {e}")
            return "member"

    async def _is_operator(self, event: AstrMessageEvent, group_id: int, user_id: int) -> bool:
        # 主人直接放行
        if self.owner_qq and str(user_id) == self.owner_qq:
            return True
        # 群主/管理 或 子管理员
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
            # 用索引判断机器人在该群的角色，避免 get_group_member_info 超时导致“假不存在”
            rec = await self.get_member_record(event, int(group_id), int(self_id))
            return self._role_of(rec) in ('owner', 'admin')
        except Exception as e:
            logger.error(f"判断机器人是否为管理员失败 gid={group_id}: {e}")
            return False

    # =========================================================
    # 群成员索引：一次性拉全量 → 本地字典查找，避免“成员不存在/超时”
    # =========================================================
    async def _refresh_group_member_index(self, event: AstrMessageEvent, group_id: int) -> dict[str, dict]:
        """
        拉取群成员列表并构建 {uid(str): member_info(dict)} 的索引。
        某些适配器没有分页；有分页的可自行在这里做 while 翻页。
        """
        try:
            raw = await event.bot.get_group_member_list(group_id=int(group_id))
            # 兼容多种返回结构
            if isinstance(raw, list):
                members = raw
            else:
                members = raw.get("members") or raw.get("data") or []
        except Exception as e:
            logger.error(f"[member-index] 拉取群 {group_id} 成员列表失败: {e}")
            members = []

        index: dict[str, dict] = {}
        for m in members:
            try:
                uid = str(m.get("user_id") or m.get("uid") or m.get("uin") or "")
                if not uid:
                    continue
                index[uid] = m
            except Exception:
                continue

        self._member_index[int(group_id)] = index
        self._member_index_built_at[int(group_id)] = time.time()
        logger.debug(f"[member-index] 群 {group_id} 已建索引，成员数={len(index)}")
        return index

    def _maybe_expired_member_index(self, group_id: int) -> bool:
        ts = self._member_index_built_at.get(int(group_id), 0)
        return (time.time() - ts) > self._member_idx_ttl

    async def _ensure_member_index(self, event: AstrMessageEvent, group_id: int) -> dict[str, dict]:
        """
        返回可用的成员索引；如不存在或过期则自动重建。
        """
        if int(group_id) not in self._member_index or self._maybe_expired_member_index(group_id):
            return await self._refresh_group_member_index(event, group_id)
        return self._member_index[int(group_id)]

    async def get_member_record(self, event: AstrMessageEvent, group_id: int, user_id: int) -> dict | None:
        """
        优先从索引取；没有则强制刷新一次再取。
        """
        idx = await self._ensure_member_index(event, group_id)
        rec = idx.get(str(user_id))
        if rec is not None:
            return rec

        # 可能是刚进群/改名导致缓存未命中 → 强刷一次
        idx = await self._refresh_group_member_index(event, group_id)
        return idx.get(str(user_id))
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

            # 踢出成功：仅对当前群撤回其最近 N 条
            try:
                removed = await self._recall_recent_messages_of_user(event, int(group_id), uid, self.recall_on_kick_count)
                if removed > 0:
                    try:
                        await event.bot.send_group_msg(group_id=int(group_id), message=f"已撤回 {uid} 最近 {removed} 条消息")
                    except Exception:
                        pass
            except Exception as e:
                logger.error(f"[入群踢黑撤回] 异常: {e}")

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
    # 发言排行榜渲染为图片（使用 Pillow）
    # =========================================================
    def _render_talk_rank_image(self, title: str, items: list[tuple[str, str, int]]) -> str | None:
        """
        渲染排行榜为图片并保存到临时文件。
        items: [(rank_str, name, count), ...]
        return: 文件路径，失败则返回 None
        """
        if not _PIL_OK:
            return None

        try:
            # 字体（Windows/Linux/Mac 可能不同，这里用内置 DejaVuSans 兜底）
            try:
                font = ImageFont.truetype("msyh.ttc", 28)  # 微软雅黑
            except Exception:
                font = ImageFont.load_default()

            title_font = ImageFont.truetype("msyh.ttc", 36) if font else ImageFont.load_default()

            padding = 20
            line_height = 50
            width = 700
            height = padding * 2 + line_height * (len(items) + 2)

            img = Image.new("RGB", (width, height), (245, 245, 245))
            draw = ImageDraw.Draw(img)

            # 标题
            draw.text((padding, padding), title, font=title_font, fill=(30, 30, 30))

            # 表头
            y = padding + line_height
            draw.text((padding, y), "排名", font=font, fill=(50, 50, 50))
            draw.text((padding + 100, y), "昵称", font=font, fill=(50, 50, 50))
            draw.text((padding + 450, y), "发言数", font=font, fill=(50, 50, 50))

            # 数据行
            for i, (rank_str, name, cnt) in enumerate(items, start=1):
                y = padding + line_height * (i + 1)
                draw.text((padding, y), rank_str, font=font, fill=(20, 20, 20))
                draw.text((padding + 100, y), str(name), font=font, fill=(20, 20, 20))
                draw.text((padding + 450, y), str(cnt), font=font, fill=(20, 20, 20))

            # 保存文件
            os.makedirs("talk_stats/tmp", exist_ok=True)
            file_path = f"talk_stats/tmp/rank_{int(time.time())}.png"
            img.save(file_path, "PNG")
            return file_path
        except Exception as e:
            logger.error(f"[排行榜渲染] 失败: {e}")
            return None

    # =========================================================
    # 主动退群命令（仅主人）
    # =========================================================
    async def handle_owner_leave_group(self, event: AstrMessageEvent, message_str: str) -> bool:
        sender = str(event.get_sender_id())
        if not (self.owner_qq and sender == self.owner_qq):
            return False

        text = message_str.strip()
        m = re.match(r"^(?:退群[#＃]?|群号[#＃]?)\s*(\d{4,12})\s*$", text)
        if not m:
            return False

        target_gid = m.group(1)
        cur_gid = event.get_group_id()

        # 提示回执
        try:
            await event.bot.send_group_msg(group_id=int(cur_gid), message=f"群号:{target_gid}\n已退群！！！")
        except Exception as e:
            logger.error(f"[退群命令] 回执失败：{e}")

        # 在目标群发送告别
        try:
            await event.bot.send_group_msg(group_id=int(target_gid), message="宝宝们,有缘再见~")
        except Exception as e:
            logger.error(f"[退群命令] 给目标群({target_gid})发送告别失败：{e}")

        # 执行退群
        try:
            try:
                await event.bot.set_group_leave(group_id=int(target_gid))
            except TypeError:
                await event.bot.set_group_leave(group_id=int(target_gid), is_dismiss=False)
            logger.info(f"[退群命令] 已退出群 {target_gid}")

            # === 新增：退群后清理统计数据 ===
            self._delete_group_talk_data(int(target_gid))
            logger.info(f"[退群清理] 主人命令退群 {target_gid}，已清理数据。")

        except Exception as e:
            logger.error(f"[退群命令] 退出群({target_gid})失败：{e}")
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

        logger.warning("[美女接口] 未解析到有效 URL（可能服务器直接 302 到视频但被拦/跨域/鉴权）")
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
                        await self._safe_set_group_ban(event.bot, group_id, sender_id, self.spam_ban_duration)
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
    # 娱乐功能：封杀倒计时（跳着撤回）+ 最终尝试禁言60秒
    # =========================================================
    async def _perform_fake_ban_countdown(self, event: AstrMessageEvent, group_id: int, target_id: str):
        # 工具：发送并返回 message_id（失败返回 None）
        async def _send(text: str) -> int | None:
            try:
                resp = await self._safe_send_group_msg(event.bot, group_id, text)
                if isinstance(resp, dict) and "message_id" in resp:
                    return resp["message_id"]
            except Exception as e:
                logger.error(f"[封杀] 发送失败: {e} | 文本={text!r}")
            return None

        # 工具：安全撤回
        async def _recall(mid: int | None):
            if not mid:
                return
            try:
                await event.bot.delete_msg(message_id=mid)
            except Exception as e:
                logger.error(f"[封杀] 撤回失败 mid={mid}: {e}")

        # 取群内显示名
        display_name = await self._get_group_display_name(event, group_id, int(target_id))

        # 头条通告（不撤回）
        head = (
            f"目标:{target_id}\n"
            f"名称:{display_name}\n"
            f"原因:调戏/激怒管理员\n"
            f"处理:对其进行永久封杀;\n"
            f"您现在还要一分钟的时间留下遗言！！！"
        )
        await _send(head)

        # 需要被撤回的：50、40、30、10
        m50 = m40 = m30 = m10 = None

        await asyncio.sleep(10); m50 = await _send("还剩下50秒！")
        await asyncio.sleep(10); m40 = await _send("剩下40秒！")
        await asyncio.sleep(10); m30 = await _send("30秒！"); await _recall(m50)
        await asyncio.sleep(20); m10 = await _send("10秒！"); await _recall(m40)
        await asyncio.sleep(5);  _ =  await _send("5秒！");   await _recall(m30)
        await asyncio.sleep(2);  _ =  await _send("3秒!")
        await asyncio.sleep(1);  _ =  await _send("2秒!")
        await asyncio.sleep(1);  _ =  await _send("1秒!")

        await asyncio.sleep(3)
        try:
            await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=60)
        except Exception as e:
            logger.error(f"[封杀] 实际禁言失败（可能无管理权限）: {e}")

        final_msg = f"处罚已下达！{display_name}已被永久封杀！！！ "
        await _send(final_msg)
    # =========================================================
    # 获取群内显示名（群名片优先，其次昵称，兜底用QQ号）
    # =========================================================
    async def _get_group_display_name(self, event: AstrMessageEvent, group_id: int, user_id: int) -> str:
        try:
            rec = await self.get_member_record(event, int(group_id), int(user_id))
            if rec:
                name = (rec.get("card") or "").strip() or (rec.get("nickname") or "").strip()
                return name or str(user_id)
        except Exception:
            pass
        return str(user_id)

    # 获取全局昵称（不在群内时用）
    async def _get_global_nickname(self, event: AstrMessageEvent, user_id: int | str) -> str:
        try:
            info = await event.bot.get_stranger_info(user_id=int(user_id))
            return (info.get("nickname") or info.get("name") or "").strip() or str(user_id)
        except Exception:
            return str(user_id)

    # 优先群内显示名，失败就退回全局昵称
    async def _resolve_display_name_anywhere(
        self,
        event: AstrMessageEvent,
        group_id: int,
        user_id: int | str
    ) -> str:
        """
        优先用本群成员索引拿显示名（群名片优先，其次昵称）；
        若不在群或索引暂不可用，则退回全局昵称；
        最终兜底返回 user_id 字符串。
        """
        uid_str = str(user_id)
        try:
            # 先走成员索引（避免 get_group_member_info 超时）
            rec = await self.get_member_record(event, int(group_id), int(uid_str))
            if rec:
                name = (rec.get("card") or "").strip() or (rec.get("nickname") or "").strip()
                if name:
                    return name
        except Exception as e:
            logger.error(f"_resolve_display_name_anywhere | 索引查询失败 gid={group_id} uid={uid_str}: {e}")

        # 不在群里或索引没命中 → 查全局昵称
        try:
            global_name = await self._get_global_nickname(event, uid_str)
            return global_name or uid_str
        except Exception as e:
            logger.error(f"_resolve_display_name_anywhere | 全局昵称查询失败 uid={uid_str}: {e}")
            return uid_str

    # 格式化列表 ["123","456"] → ["123(忧)","456(某某)"]
    async def _format_id_list_with_names(self, event: AstrMessageEvent, group_id: int, ids: list[str]) -> list[str]:
        try:
            ordered = sorted(ids, key=lambda x: int(x))
        except Exception:
            ordered = sorted(ids)

        coros = [self._resolve_display_name_anywhere(event, int(group_id), i) for i in ordered]
        names = await asyncio.gather(*coros, return_exceptions=True)

        lines = []
        for uid, nm in zip(ordered, names):
            name = nm if isinstance(nm, str) and nm else str(uid)
            lines.append(f"{uid}({name})")
        return lines

    # =========================================================
    # 工具：角色中文名
    # =========================================================
    def _role_label(self, role: str) -> str:
        role = (role or "").lower()
        if role == "owner":
            return "高贵的群主"
        if role == "admin":
            return "尊贵的管理"
        return "低贱的群员"
    # =========================================================
    # 群减少事件：机器人退群/被踢 → 清理该群统计数据
    # =========================================================
    @filter.event_message_type(getattr(EventMessageType, "NOTICE", EventMessageType.GROUP_MESSAGE))
    async def _on_group_decrease(self, event: AstrMessageEvent):
        raw = getattr(event.message_obj, "raw_message", {}) or {}
        if str(raw.get("post_type", "")) != "notice":
            return

        ntype = str(raw.get("notice_type", ""))
        if ntype not in {"group_decrease", "group_member_decrease", "member_decrease"}:
            return

        try:
            group_id = int(raw["group_id"])
            user_id = int(raw.get("user_id") or raw.get("member_id") or raw.get("target_id") or 0)
        except Exception:
            return

        if not user_id:
            return

        # 判断是不是机器人自己
        self_id = await self._get_self_user_id(event)
        if self_id and str(user_id) == str(self_id):
            # 机器人退群/被踢，清理该群统计数据
            self._delete_group_talk_data(group_id)
            logger.info(f"[退群清理] 机器人已退出群 {group_id}，清理数据完成。")

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

        # ---------- 新增：发言计数（排除机器人自身） ----------
        try:
            self_id = await self._get_self_user_id(event)
        except Exception:
            self_id = None
        if not self_id or str(sender_id) != str(self_id):
            self._bump_talk_today(int(group_id), int(sender_id))

        # ---------- 主人主动退群命令 ----------
        handled = await self.handle_owner_leave_group(event, message_str)
        if handled:
            try:
                target_gid = re.search(r"(\d{4,12})", message_str).group(1)
                self._delete_group_talk_data(int(target_gid))
                logger.info(f"[退群清理] 主人命令退群 {target_gid}，已清理数据。")
            except Exception as e:
                logger.error(f"[退群清理] 失败: {e}")
            return


        # ---------- 新增：我的身份 ----------
        if message_str == "我的身份":
            name = await self._get_group_display_name(event, int(group_id), int(sender_id))
            role = await self._get_member_role(event, int(group_id), int(sender_id))
            role_cn = self._role_label(role)
            auth = self.authority_cert.get(str(sender_id), "无名小辈")
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            text = (
                "👑 我的身份\n"
                "━━━━━━━━━\n"
                f"👤 名称：{name}\n"
                f"🆔 QQ账号：{sender_id}\n"
                f"🎭 群内身份：{role_cn}\n"
                f"🏅 权威认证：{auth}\n"
                "━━━━━━━━━\n"
                f"⏰ 查询时间：\n"
                f"{ts}\n"
                "━━━━━━━━━"
            )
            await self._safe_send_group_msg(event.bot, group_id, text)
            return

        # ---------- 发言日榜 ----------
        if message_str == "发言日榜":
            today = self._today_str()
            counts = self._query_day_counts(int(group_id), today)
            if not counts:
                await self._safe_send_group_msg(event.bot, group_id, "今天还没有任何发言记录。")
                return

            top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
            items = []
            for rank, (uid, cnt) in enumerate(top, 1):
                name = await self._resolve_display_name_anywhere(event, int(group_id), uid)
                items.append((str(rank), name, cnt))

            img_path = self._render_talk_rank_image("📊 今日发言日榜（前10）", items)
            if img_path:
                msg = [{"type": "image", "data": {"file": img_path}}]
                await event.bot.send_group_msg(group_id=int(group_id), message=msg)
            else:
                lines = [f"{r}. {n}({u}) - {c}条" for r, (u, c) in enumerate(top, 1)
                         for n in [await self._resolve_display_name_anywhere(event, int(group_id), u)]]
                text = "📊 今日发言日榜（前10）\n" + "\n".join(lines)
                await self._safe_send_group_msg(event.bot, group_id, text)
            return

        # ---------- 发言周榜 ----------
        if message_str == "发言周榜":
            counts = self._query_last_n_days_sum(int(group_id), 7)
            if not counts:
                await self._safe_send_group_msg(event.bot, group_id, "最近7天没有任何发言记录。")
                return

            top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
            items = []
            for rank, (uid, cnt) in enumerate(top, 1):
                name = await self._resolve_display_name_anywhere(event, int(group_id), uid)
                items.append((str(rank), name, cnt))

            img_path = self._render_talk_rank_image("📊 最近7天发言周榜（前10）", items)
            if img_path:
                msg = [{"type": "image", "data": {"file": img_path}}]
                await event.bot.send_group_msg(group_id=int(group_id), message=msg)
            else:
                lines = [f"{r}. {n}({u}) - {c}条" for r, (u, c) in enumerate(top, 1)
                         for n in [await self._resolve_display_name_anywhere(event, int(group_id), u)]]
                text = "📊 最近7天发言周榜（前10）\n" + "\n".join(lines)
                await self._safe_send_group_msg(event.bot, group_id, text)
            return

        # ---------- 我的发言 ----------
        if message_str == "我的发言":
            today = self._today_str()
            counts = self._query_day_counts(int(group_id), today)
            cnt = int(counts.get(str(sender_id), 0))
            name = await self._resolve_display_name_anywhere(event, int(group_id), sender_id)

            img_path = self._render_talk_rank_image("👤 我的发言", [( "1", name, cnt )])
            if img_path:
                msg = [{"type": "image", "data": {"file": img_path}}]
                await event.bot.send_group_msg(group_id=int(group_id), message=msg)
            else:
                text = f"👤 {name}({sender_id})\n今日发言：{cnt} 条"
                await self._safe_send_group_msg(event.bot, group_id, text)
            return


        # ---------- 我要看美女 ----------
        if "我要看美女" in message_str:
            now = time.time()
            last_video = self.video_last_time.get(group_id, 0)
            if now - last_video < self.video_cooldown:
                resp = await event.bot.send_group_msg(group_id=int(group_id), message="不发！少🦌行不行！")
                if isinstance(resp, dict) and "message_id" in resp:
                    asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=8))
                return
            last_api = self.beauty_last_time.get(group_id, 0)
            if now - last_api < self.beauty_cooldown:
                remain = int(self.beauty_cooldown - (now - last_api))
                resp = await event.bot.send_group_msg(group_id=int(group_id), message=f"别急呀~ 冷却中 {remain}s")
                if isinstance(resp, dict) and "message_id" in resp:
                    asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=8))
                return
            video_url = await self._fetch_beauty_video_url()
            if not video_url:
                await event.bot.send_group_msg(group_id=int(group_id), message="接口开小差了，一会儿再试下~")
                return
            try:
                if video_url.lower().endswith(".m3u8"):
                    await event.bot.send_group_msg(group_id=int(group_id), message=video_url)
                else:
                    msg_seg = [{"type": "video", "data": {"file": video_url}}]
                    await event.bot.send_group_msg(group_id=int(group_id), message=msg_seg)
            except Exception:
                await event.bot.send_group_msg(group_id=int(group_id), message=video_url)
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
                    await event.bot.send_group_msg(group_id=int(group_id), message=self._parse_message_with_faces(reply))
                    self.auto_reply_last_time[group_id] = now_time
                    break

        # ---------- 查询违规 ----------
        if message_str.startswith("查询违规"):
            await self.handle_check_violation(event)
            return

        # ---------- 查共群 ----------
        if message_str.startswith("查共群"):
            await self.handle_check_common_groups(event)
            return

        # ---------- 群管命令 ----------
        command_keywords = (
            "禁言", "解禁", "解言", "踢黑", "解黑",
            "踢", "针对", "解针对", "设置管理员", "移除管理员", "撤回",
            "全体禁言", "全体解言",
            "加白", "移白", "白名单列表",
            "黑名单列表", "针对列表", "管理员列表",
            "封杀",
            "认证", "移除认证",
            "清空白名单",
        )
        if message_str.startswith(command_keywords):
            if message_str.startswith("认证") or message_str.startswith("移除认证"):
                await self.handle_certify(event)
                return
            if not await self._is_operator(event, int(group_id), int(sender_id)):
                resp = await event.bot.send_group_msg(group_id=int(group_id), message="你配指挥我吗？")
                if isinstance(resp, dict) and "message_id" in resp:
                    asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=10))
                return
            await self.handle_commands(event)
            return

        # ---------- 群主/管理员发言跳过撤回 ----------
        try:
            rec = await self.get_member_record(event, int(group_id), int(sender_id))
            if self._role_of(rec) in ("owner", "admin"):
                return
        except Exception:
            pass

        # ---------- 黑名单：发言触发兜底（只在当前群处理+撤回） ----------
        if str(sender_id) in self.kick_black_list:
            if await self._bot_is_admin(event, int(group_id)):
                try:
                    try:
                        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id), reject_add_request=True)
                    except TypeError:
                        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
                    await event.bot.send_group_msg(group_id=int(group_id), message=f"检测到黑名单用户 {sender_id}，已踢出！")

                    # 只在当前群撤回其最近 N 条
                    try:
                        removed = await self._recall_recent_messages_of_user(event, int(group_id), str(sender_id), self.recall_on_kick_count)
                        if removed > 0:
                            try:
                                await event.bot.send_group_msg(group_id=int(group_id), message=f"已撤回 {sender_id} 最近 {removed} 条消息")
                            except Exception:
                                pass
                    except Exception as e:
                        logger.error(f"[黑名单兜底撤回] 异常: {e}")

                except Exception as e:
                    logger.error(f"[黑名单兜底] 踢出失败 gid={group_id} uid={sender_id}: {e}")
            else:
                logger.info(f"[黑名单兜底] 发现黑名单 {sender_id} 在群 {group_id} 发言，但机器人非管理，忽略。")
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
                    await self._safe_set_group_ban(event.bot, group_id, sender_id, self.spam_ban_duration)
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
                rec = await self.get_member_record(event, int(group_id), int(sender_id))
                role = self._role_of(rec)
                logger.error(f"撤回失败: {e}（用户角色: {role}）")
            except Exception as ex:
                logger.error(f"撤回失败且查询用户角色失败: {e} / 查询错误: {ex}")

    # =========================================================
    # 工具：仅在指定群撤回某个用户最近 N 条消息（从新到旧）
    # =========================================================
    async def _recall_recent_messages_of_user(self, event: AstrMessageEvent, group_id: int, target_id: str, limit: int | None = None) -> int:
        limit = limit or self.recall_on_kick_count
        removed = 0
        try:
            history = await event.bot.get_group_msg_history(group_id=int(group_id), count=200)
            msgs = history.get('messages', []) or []
        except Exception as e:
            logger.error(f"[撤回最近N条] 获取历史失败 gid={group_id}: {e}")
            return 0

        # 假定返回为新->旧；若你的适配器是旧->新，可改为 reversed(msgs)
        for msg_data in msgs:
            if removed >= limit:
                break
            try:
                if str(msg_data.get('sender', {}).get('user_id')) != str(target_id):
                    continue
                mid = msg_data.get('message_id')
                if mid is None:
                    continue
                try:
                    await event.bot.delete_msg(message_id=mid)
                    removed += 1
                except Exception as e:
                    logger.error(f"[撤回最近N条] 撤回失败 mid={mid}: {e}")
            except Exception as e:
                logger.error(f"[撤回最近N条] 扫描失败: {e}")
        return removed

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
    # 兜底：在所有管理中的群里踢出黑名单目标（静默，只记日志）
    # 只踢，不撤回（避免影响非触发群）
    # =========================================================
    async def _kick_blacklist_in_all_admin_groups(self, event: AstrMessageEvent, target_id: str):
        try:
            raw = await event.bot.get_group_list()
            if isinstance(raw, list):
                groups = raw
            else:
                groups = raw.get("data") or raw.get("groups") or []
        except Exception as e:
            logger.error(f"[踢黑兜底] 获取群列表失败：{e}")
            return

        for g in groups:
            try:
                gid = int(g.get("group_id") or g.get("gid") or g.get("group") or 0)
            except Exception:
                gid = 0
            if not gid:
                continue

            try:
                member_info = await event.bot.get_group_member_info(group_id=gid, user_id=int(target_id))
                target_role = str(member_info.get("role", "member"))
            except Exception:
                continue

            try:
                bot_is_admin = await self._bot_is_admin(event, gid)
            except Exception:
                bot_is_admin = False

            if not bot_is_admin:
                logger.info(f"[踢黑兜底] 发现黑名单 {target_id} 在群 {gid}，但机器人非管理，忽略。")
                continue

            if target_role in ("owner", "admin"):
                logger.info(f"[踢黑兜底] 发现黑名单 {target_id} 在群 {gid} 且其为 {target_role}，按规则忽略。")
                continue

            try:
                try:
                    await event.bot.set_group_kick(group_id=gid, user_id=int(target_id), reject_add_request=True)
                except TypeError:
                    await event.bot.set_group_kick(group_id=gid, user_id=int(target_id))
                logger.info(f"[踢黑兜底] 已在群 {gid} 踢出黑名单 {target_id}")
            except Exception as e:
                logger.error(f"[踢黑兜底] 在群 {gid} 踢出 {target_id} 失败：{e}")

    # =========================================================
    # 工具：从消息里抽取目标QQ（优先 #QQ号，其次 @）
    # =========================================================
    def _extract_target_from_msg(self, event: AstrMessageEvent, msg: str) -> str | None:
        m = re.search(r"#\s*(\d{5,12})", msg)
        if m:
            return m.group(1)

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
    # 新增：提取“认证标签”
    # =========================================================
    def _extract_cert_label(self, event: AstrMessageEvent, msg: str, target_id: str) -> str:
        # 去掉开头关键词
        raw = msg.strip()
        raw = re.sub(r"^\s*(认证|移除认证)\s*", "", raw)

        # 1) 结构化优先：基于 CQ 段，找到目标 @ 段后，收集其后的文本段作为标签
        try:
            segs = getattr(event.message_obj, 'message', []) or []
            after = False
            parts = []
            for seg in segs:
                s_type = (seg.get("type") if isinstance(seg, dict) else getattr(seg, "type", "")).lower()
                if s_type == "at":
                    qq = None
                    if isinstance(seg, dict):
                        qq = seg.get("data", {}).get("qq") or seg.get("qq")
                    else:
                        data = getattr(seg, "data", None)
                        qq = (getattr(data, "qq", None) if data else None) or getattr(seg, "qq", None)
                    if str(qq) == str(target_id):
                        after = True
                    continue  # 跳过 @ 段本身

                if s_type in ("text", "text_plain", "plain"):
                    if isinstance(seg, dict):
                        t = seg.get("data", {}).get("text", "") or ""
                    else:
                        data = getattr(seg, "data", None)
                        t = (getattr(data, "text", None) if data else None) or getattr(seg, "text", "") or ""

                    if not after:
                        # 处理 '#QQ' 在同一 text 段里的情况
                        m = re.search(r"#\s*" + re.escape(str(target_id)), t)
                        if m:
                            parts.append(t[m.end():])
                            after = True
                    else:
                        parts.append(t)

            if after:
                label = "".join(parts)
            else:
                label = raw  # 没识别到 @ 段，退回原始清洗
        except Exception:
            label = raw

        # 2) 兜底清洗：移除一次 @昵称 / [CQ:at,...] / #QQ
        label = re.sub(r"\[CQ:at,[^\]]+\]", "", label, count=1)
        label = re.sub(r"@[^\s\(\)]+(?:\([^\)]*\))?", "", label, count=1)  # 支持 @忧 或 @忧(123456)
        label = re.sub(r"#\s*\d{5,12}", "", label, count=1)

        # 3) 统一空白并裁剪
        label = re.sub(r"\s+", " ", label).strip()
        return label

    # =========================================================
    # 新增：主人专用的权威认证命令
    # =========================================================
    async def handle_certify(self, event: AstrMessageEvent):
        msg = event.message_str.strip()
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        # 仅主人可用
        if not (self.owner_qq and str(sender_id) == self.owner_qq):
            await event.bot.send_group_msg(group_id=int(group_id), message="只有主人才能进行权威认证。")
            return

        # 提取目标
        target_id = self._extract_target_from_msg(event, msg)
        if not target_id:
            await event.bot.send_group_msg(group_id=int(group_id), message="请使用 @或 #QQ号 指定认证对象。")
            return

        # 移除认证
        if msg.startswith("移除认证"):
            if str(target_id) in self.authority_cert:
                del self.authority_cert[str(target_id)]
                self.save_auth_data()
                await event.bot.send_group_msg(group_id=int(group_id), message=f"已移除 {target_id} 的认证。")
            else:
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 没有认证，无需移除。")
            return

        # 解析标签并保存
        label = self._extract_cert_label(event, msg, target_id)
        if not label:
            await event.bot.send_group_msg(group_id=int(group_id), message="请在目标后面写上认证标签，例如：认证 @他 王牌狙击手")
            return

        # 限长 12（可自行调整）
        if len(label) > 12:
            label = label[:12]

        self.authority_cert[str(target_id)] = label
        self.save_auth_data()
        try:
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 权威认证")
        except Exception:
            pass
        await event.bot.send_group_msg(group_id=int(group_id), message=f"已将 {target_id} 认证为『{label}』")

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

        # 无需目标QQ的命令
        if msg.startswith("全体禁言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 全体禁言")
            try:
                await event.bot.set_group_whole_ban(group_id=int(group_id), enable=True)
                await event.bot.send_group_msg(group_id=int(group_id), message="已开启全体禁言")
            except Exception as e:
                logger.error(f"开启全体禁言失败: {e}")
            return

        # —— 特权命令：清空白名单（仅主人），放在权限校验之前确保非主人统一得到“无权使用”
        if msg.startswith("清空白名单"):
            if not self.owner_qq or str(sender_id) != self.owner_qq:
                try:
                    resp = await event.bot.send_group_msg(group_id=int(group_id), message="无权使用")
                    if isinstance(resp, dict) and "message_id" in resp:
                        asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=10))
                except Exception as e:
                    logger.error(f"发送无权使用提示失败: {e}")
                return

            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 清空白名单")
            try:
                self.whitelist.clear()
                self.save_json_data()
                await event.bot.send_group_msg(group_id=int(group_id), message="已清空白名单！")
            except Exception as e:
                logger.error(f"清空白名单失败: {e}")
                try:
                    await event.bot.send_group_msg(group_id=int(group_id), message="清空白名单失败，请查看日志")
                except Exception:
                    pass
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
            items = list(self.whitelist)
            lines = await self._format_id_list_with_names(event, int(group_id), items)
            text = "以下为 白名单QQ 总计{}\n{}".format(len(items), ("\n".join(lines) if lines else "（空）"))
            await self._safe_send_group_msg(event.bot, group_id, text)
            return

        if msg.startswith("黑名单列表"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 黑名单列表")
            items = list(self.kick_black_list)
            lines = await self._format_id_list_with_names(event, int(group_id), items)
            text = "以下为 黑名单QQ 总计{}\n{}".format(len(items), ("\n".join(lines) if lines else "（空）"))
            await self._safe_send_group_msg(event.bot, group_id, text)
            return

        if msg.startswith("针对列表"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 针对列表")
            items = list(self.target_user_list)
            lines = await self._format_id_list_with_names(event, int(group_id), items)
            text = "以下为 针对名单QQ 总计{}\n{}".format(len(items), ("\n".join(lines) if lines else "（空）"))
            await self._safe_send_group_msg(event.bot, group_id, text)
            return

        if msg.startswith("管理员列表"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 管理员列表")
            items = list(self.sub_admin_list)
            lines = await self._format_id_list_with_names(event, int(group_id), items)
            text = "以下为 子管理员QQ 总计{}\n{}".format(len(items), ("\n".join(lines) if lines else "（空）"))
            await self._safe_send_group_msg(event.bot, group_id, text)
            return

        # 需要目标QQ的命令：支持 @ 与 #QQ号
        target_id = self._extract_target_from_msg(event, msg)
        if not target_id:
            logger.error("未检测到目标用户（缺少 @ 或 #QQ号）")
            await event.bot.send_group_msg(group_id=int(group_id), message="请使用 @或 #QQ号 指定目标")
            return

        logger.info(f"检测到命令针对 {target_id} | 原消息: {msg}")

        # 解析消息尾部整数
        def _parse_tail_int(_msg: str, default_val: int) -> int:
            m = re.search(r"(\d+)\s*$", _msg)
            return int(m.group(1)) if m else default_val

        if msg.startswith("禁言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 禁言")
            minutes = _parse_tail_int(msg, 10)
            duration = minutes * 60
            try:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=duration)
                await event.bot.send_group_msg(group_id=int(group_id), message=f"已禁言 『{target_id}』 {minutes} 分钟")
            except Exception as e:
                logger.error(f"禁言失败 gid={group_id} uid={target_id}: {e}")

        elif msg.startswith(("解禁", "解言")):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解禁")
            try:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=0)
                await event.bot.send_group_msg(group_id=int(group_id), message=f"已解除 『{target_id}』 禁言")
            except Exception as e:
                logger.error(f"解禁失败 gid={group_id} uid={target_id}: {e}")

        elif msg.startswith("踢黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢黑")
            try:
                # 防误操作：禁止把机器人或主人加入黑名单
                self_id = await self._get_self_user_id(event)
                if target_id in {self_id, str(self.owner_qq)}:
                    await event.bot.send_group_msg(group_id=int(group_id), message="目标是机器人或主人，已忽略。")
                    return

                if target_id in self.kick_black_list:
                    await event.bot.send_group_msg(group_id=int(group_id), message=f"『{target_id}』 已在黑名单，无需重复添加。")
                else:
                    # 先加入黑名单并持久化
                    self.kick_black_list.add(target_id)
                    self.save_json_data()

                # 当前群按规则处理
                try:
                    rec = await self.get_member_record(event, int(group_id), int(target_id))
                    t_role = str((rec or {}).get("role", "member"))
                except Exception:
                    t_role = "member"

                bot_is_admin = await self._bot_is_admin(event, int(group_id))

                if not bot_is_admin:
                    logger.info(f"[踢黑命令] 机器人在群 {group_id} 非管理，无法踢当前群目标 {target_id}。")
                elif t_role in ("owner", "admin"):
                    logger.info(f"[踢黑命令] 目标 {target_id} 在群 {group_id} 为 {t_role}，按规则忽略当前群踢出。")
                else:
                    try:
                        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id), reject_add_request=True)
                    except TypeError:
                        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
                    await event.bot.send_group_msg(group_id=int(group_id), message=f"『{target_id}』 已加入踢黑名单并踢出")

                # 仅在当前群撤回其最近 N 条
                try:
                    removed = await self._recall_recent_messages_of_user(event, int(group_id), target_id, self.recall_on_kick_count)
                    if removed > 0:
                        try:
                            await event.bot.send_group_msg(group_id=int(group_id), message=f"已撤回 『{target_id}』 最近 {removed} 条消息")
                        except Exception:
                            pass
                except Exception as e:
                    logger.error(f"[踢黑后撤回] 异常: {e}")

                # 兜底：其他群只静默踢，不撤回
                asyncio.create_task(self._kick_blacklist_in_all_admin_groups(event, target_id))

            except Exception as e:
                logger.error(f"踢黑失败 gid={group_id} uid={target_id}: {e}")

        elif msg.startswith("解黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解黑")
            self.kick_black_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"『{target_id}』 已移出踢黑名单")

        elif msg.startswith("踢"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢")
            try:
                await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
                await event.bot.send_group_msg(group_id=int(group_id), message=f"已踢出 『{target_id}』")
            except Exception as e:
                logger.error(f"踢出失败 gid={group_id} uid={target_id}: {e}")
            else:
                # 踢出成功后，仅在当前群撤回其最近 N 条
                try:
                    removed = await self._recall_recent_messages_of_user(event, int(group_id), target_id, self.recall_on_kick_count)
                    if removed > 0:
                        try:
                            await event.bot.send_group_msg(group_id=int(group_id), message=f"已撤回 『{target_id}』 最近 {removed} 条消息")
                        except Exception:
                            pass
                except Exception as e:
                    logger.error(f"[踢出后撤回] 异常: {e}")

        elif msg.startswith("针对"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 针对")
            self.target_user_list.add(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"『{target_id}』 已加入针对名单")

        elif msg.startswith("解针对"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解针对")
            self.target_user_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"『{target_id}』 已移出针对名单")

        elif msg.startswith("设置管理员"):
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

        elif msg.startswith("加白"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 加白")
            self.whitelist.add(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"『{target_id}』 已加入白名单")

        elif msg.startswith("移白"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 移白")
            self.whitelist.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已从白名单移除")

        elif msg.startswith("撤回"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 撤回")
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
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已撤回 『{target_id}』 的 {deleted} 条消息")

        elif msg.startswith("封杀"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 娱乐封杀倒计时")
            # 异步执行，不阻塞命令处理
            asyncio.create_task(self._perform_fake_ban_countdown(event, int(group_id), target_id))

    # =========================================================
    # 插件卸载钩子
    # =========================================================
    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
