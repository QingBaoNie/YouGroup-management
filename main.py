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

# ================== 全局主人 ==================
OWNER_QQ = "3212549884"


@register(
    "YouGroup-management",
    "You",
    "敏感词自动撤回插件(关键词匹配+刷屏检测+群管指令+查共群+查询违规)",
    "1.2.1",
    "https://github.com/QingBaoNie/YouGroup-management"
)
class AutoRecallKeywordPlugin(Star):
    def __init__(self, context: Context, config):
        super().__init__(context)
        self.config = config
        self.user_message_times = defaultdict(lambda: deque(maxlen=5))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=5))
        self.kick_black_list = set()
        self.target_user_list = set()
        self.sub_admin_list = set()
        self.whitelist = set()

        # 自动回复冷却
        self.auto_reply_last_time = {}
        self.auto_reply_cooldown = 60

    async def initialize(self):
        config_data = self.config
        self.bad_words = config_data.get("bad_words", [])
        spam_config = config_data.get("spam_config", {})
        admin_config = config_data.get("admin_config", {})

        # 自动回复
        auto_replies_config = config_data.get("auto_replies", [])
        self.auto_replies = {}
        for item in auto_replies_config:
            if "-" in item:
                key, val = item.split("-", 1)
                self.auto_replies[key.strip()] = val.strip()

        self.spam_count = spam_config.get("spam_count", 5)
        self.spam_interval = spam_config.get("spam_interval", 3)
        self.spam_ban_duration = spam_config.get("spam_ban_duration", 60)

        self.sub_admin_list = set(admin_config.get("sub_admin_list", []))
        self.kick_black_list = set(admin_config.get("kick_black_list", []))
        self.target_user_list = set(admin_config.get("target_user_list", []))
        self.whitelist = set(admin_config.get("whitelist", []))

        # ---- 关键：稳健化布尔解析 ----
        def _to_bool(v):
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)):
                return v != 0
            if isinstance(v, str):
                return v.strip().lower() in {"1", "true", "yes", "on"}
            return False

        self.recall_links = _to_bool(admin_config.get("recall_links", False))
        self.recall_cards = _to_bool(admin_config.get("recall_cards", False))
        self.recall_numbers = _to_bool(admin_config.get("recall_numbers", False))

        self.save_json_data()

        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        logger.info(f"敏感词列表: {self.bad_words}")
        logger.info(f"自动回复规则: {self.auto_replies}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s 禁言{self.spam_ban_duration}s")
        logger.info(f"子管理员: {self.sub_admin_list} 黑名单: {self.kick_black_list} 针对名单: {self.target_user_list} 白名单: {self.whitelist}")
        logger.info(f"撤回配置: links={self.recall_links}, cards={self.recall_cards}, numbers={self.recall_numbers}")

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

    async def _auto_delete_after(self, bot, message_id: int, delay: int = 60):
        try:
            await asyncio.sleep(delay)
            await bot.delete_msg(message_id=message_id)
        except Exception as e:
            logger.error(f"定时撤回失败 message_id={message_id}: {e}")

    def _is_pure_text(self, event: AstrMessageEvent, message_str: str) -> bool:
        """
        只要所有分段都是 text / Text / text_plain / Plain 就认为纯文本。
        如果拿不到分段，则用字符串里是否含 CQ 标记作兜底。
        """
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

    def _has_at_or_reply(self, event: AstrMessageEvent, message_str: str) -> bool:
        """检测是否包含 @ 或 回复分段（避免误撤回管理员操作等）"""
        try:
            for seg in getattr(event.message_obj, 'message', []):
                s_type = seg.get("type") if isinstance(seg, dict) else getattr(seg, "type", "")
                s_type = (s_type or "").lower()
                if s_type in ("at", "reply"):
                    return True
        except Exception:
            pass
        return ("[CQ:at" in message_str) or ("[CQ:reply" in message_str)

    def _normalize_for_number_check(self, s: str) -> str:
        """
        数字检测前的标准化：
        1) 全角数字 -> 半角
        2) 去掉空白/常见分隔符（空格、短横线、点、下划线）
        3) 去掉常见不可见字符（零宽/功能性）
        """
        full = "０１２３４５６７８９"
        trans = {ord(full[i]): ord('0') + i for i in range(10)}
        s = s.translate(trans)
        s = re.sub(r"[\s\-\._]", "", s)
        s = s.replace("\u200b", "").replace("\u2060", "").replace("\u2061", "").replace("\u2062", "").replace("\u2063", "")
        return s

    async def _get_member_role(self, event: AstrMessageEvent, group_id: int, user_id: int) -> str:
        try:
            info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(user_id))
            return info.get("role", "member")
        except Exception as e:
            logger.error(f"获取用户 {user_id} 在群 {group_id} 角色失败: {e}")
            return "member"

    async def _is_operator(self, event: AstrMessageEvent, group_id: int, user_id: int) -> bool:
        # 主人永远拥有最高权限
        if str(user_id) == OWNER_QQ:
            return True
        role = await self._get_member_role(event, group_id, user_id)
        if role in ("owner", "admin"):
            return True
        if str(user_id) in self.sub_admin_list:
            return True
        return False

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        if getattr(event.message_obj.raw_message, 'post_type', '') == 'notice':
            return

        group_id = event.get_group_id()
        sender_id = event.get_sender_id()
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id

        # === 新增：普通用户 @机器人 -> 禁言5分钟 + 警告（带详细日志） ===
        # 1) 获取机器人 self_id，优先属性，取不到再调 get_login_info()
        try:
            self_id = str(getattr(event.bot, "self_id", None) or getattr(event, "self_id", None) or "")
        except Exception:
            self_id = ""
        if not self_id:
            try:
                info = await event.bot.get_login_info()
                sid = (info.get("user_id") or info.get("uid") or info.get("uin"))
                if sid:
                    self_id = str(sid)
            except Exception as e:
                logger.error(f"获取机器人 self_id 失败: {e}")

        # 2) 分段扫描 + 文本兜底
        seg_hit = False
        text_hit_cq = False
        text_hit_simple = False

        try:
            segs = getattr(event.message_obj, 'message', []) or []
            # 打印一条调试：消息段类型列表（不含内容，避免隐私/刷屏）
            try:
                seg_types = [(s.get('type') if isinstance(s, dict) else getattr(s, 'type', '')) for s in segs]
                logger.debug(f"@bot debug | seg_types={seg_types}")
            except Exception:
                pass

            for seg in segs:
                s_type = seg.get("type") if isinstance(seg, dict) else getattr(seg, "type", "")
                s_type = (s_type or "").lower()
                if s_type == "at":
                    if isinstance(seg, dict):
                        data = seg.get("data", {}) or {}
                        cand = (
                            data.get("qq") or data.get("target") or data.get("user_id")
                            or seg.get("qq") or seg.get("target")
                        )
                    else:
                        data = getattr(seg, "data", {}) or {}
                        cand = (
                            data.get("qq") or data.get("target") or data.get("user_id")
                            or getattr(seg, "qq", None) or getattr(seg, "target", None)
                        )
                    if cand is not None and self_id and str(cand) == self_id:
                        seg_hit = True
                        break
        except Exception as e:
            logger.error(f"解析消息分段 @ 失败: {e}")

        if self_id:
            # CQ 码兜底
            if f"[CQ:at,qq={self_id}]" in message_str:
                text_hit_cq = True
            # 简式 [At:xxxxx] 兜底
            m = re.search(r"\[At:(\d+)\]", message_str)
            if m and m.group(1) == self_id:
                text_hit_simple = True

        at_bot_matched = bool(seg_hit or text_hit_cq or text_hit_simple)

        # 关键观测日志：看到这条就知道为什么触发/不触发
        logger.info(
            f"@bot check | gid={group_id} uid={sender_id} self_id={self_id} "
            f"seg_hit={seg_hit} text_hit_cq={text_hit_cq} text_hit_simple={text_hit_simple} "
            f"matched={at_bot_matched}"
        )

        if self_id and at_bot_matched:
            # 主人/群主/管理员/子管理员/白名单 不处罚
            is_operator = await self._is_operator(event, int(group_id), int(sender_id))
            in_whitelist = (str(sender_id) in self.whitelist)
            logger.info(
                f"@bot decision | gid={group_id} uid={sender_id} "
                f"is_operator={is_operator} in_whitelist={in_whitelist}"
            )
            if (not is_operator) and (not in_whitelist):
                try:
                    await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=300)
                    await event.bot.send_group_msg(group_id=int(group_id), message="请不要@我，下次惩罚升级！！！")
                    logger.info(f"@bot punished | gid={group_id} uid={sender_id} duration=300")
                except Exception as e:
                    logger.error(f"@机器人 自动禁言失败: {e}")
                return
        # === 新增逻辑结束 ===

        # 自动回复（带冷却）
        now_time = time.time()
        last_reply_time = self.auto_reply_last_time.get(group_id, 0)
        if now_time - last_reply_time >= self.auto_reply_cooldown:
            for key, reply in self.auto_replies.items():
                if key in message_str:
                    try:
                        await event.bot.send_group_msg(group_id=int(group_id), message=reply)
                        self.auto_reply_last_time[group_id] = now_time
                    except Exception as e:
                        logger.error(f"自动回复失败: {e}")
                    break

        # 查询违规（二维码，60秒后撤回）
        if message_str.startswith("查询违规"):
            await self.handle_check_violation(event)
            return

        # 查共群
        if message_str.startswith("查共群"):
            await self.handle_check_common_groups(event)
            return

        # 群管命令
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

        # 群主/管理员跳过撤回
        try:
            member_info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(sender_id))
            if member_info.get("role", "member") in ("owner", "admin"):
                return
        except Exception as e:
            logger.error(f"获取用户 {sender_id} 群身份失败: {e}")

        # 黑名单
        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            await event.bot.send_group_msg(group_id=int(group_id), message=f"检测到黑名单用户 {sender_id}，已踢出！")
            return

        # 白名单
        is_whitelisted = str(sender_id) in self.whitelist

        # 针对名单
        if not is_whitelisted and (str(sender_id) in self.target_user_list):
            await event.bot.delete_msg(message_id=message_id)
            return

        # 违禁词
        if not is_whitelisted:
            for word in self.bad_words:
                if word and word in message_str:
                    logger.error(f"触发违禁词【{word}】已撤回！")
                    await self.try_recall(event, message_id, group_id, sender_id)
                    return

        # 链接
        if (not is_whitelisted) and self.recall_links and ("http://" in message_str or "https://" in message_str):
            logger.error(f"触发【链接】已撤回！")
            await self.try_recall(event, message_id, group_id, sender_id)
            return

        # 卡片
        if (not is_whitelisted) and self.recall_cards:
            for segment in getattr(event.message_obj, 'message', []):
                seg_type = getattr(segment, 'type', '')
                if seg_type in ['Share', 'Card', 'Contact', 'Json', 'Xml', 'share', 'json', 'xml', 'contact']:
                    logger.error(f"触发【卡片】已撤回！")
                    await self.try_recall(event, message_id, group_id, sender_id)
                    return

        # 号码检测（避免 @/引用 消息被误撤回）
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

        # 刷屏
        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)
        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                logger.error(f"触发【刷屏】已禁言并批量撤回！")
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                for msg_id in self.user_message_ids[key]:
                    try:
                        await event.bot.delete_msg(message_id=msg_id)
                    except Exception as e:
                        logger.error(f"刷屏批量撤回失败: {e}")
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

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

    async def handle_check_violation(self, event: AstrMessageEvent):
        """
        发送“查询违规”时返回二维码，内容为固定链接，消息 60 秒后自动撤回。
        与查共群逻辑一致：优先发二维码图片，失败则回退为文本链接。
        """
        group_id = event.get_group_id()
        base_url = "https://m.q.qq.com/a/s/07befc388911b30c2359bfa383f2d693"

        # 生成二维码（与查共群同源 API）
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

    async def handle_commands(self, event: AstrMessageEvent):
        msg = event.message_str.strip()
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        # 二次拦截，防止外部误调用绕过（主人、群主、管理员、子管理员可进入）
        if not await self._is_operator(event, int(group_id), int(sender_id)):
            try:
                resp = await event.bot.send_group_msg(
                    group_id=int(group_id),
                    message="你配指挥我吗？"
                )
                if isinstance(resp, dict) and "message_id" in resp:
                    asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=10))
            except Exception as e:
                logger.error(f"发送无权限提示失败: {e}")
            return

        # ====== 不需要@对象的群级指令（优先处理）======
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

        if msg.startswith("白名单列表"):  # 查看白名单
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 白名单列表")
            items = sorted(self.whitelist, key=lambda x: int(x))
            count = len(items)
            text = "以下为 白名单QQ 总计{}\n{}".format(count, ("\n".join(items) if items else "（空）"))
            await event.bot.send_group_msg(group_id=int(group_id), message=text)
            return

        if msg.startswith("黑名单列表"):  # 查看黑名单
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 黑名单列表")
            items = sorted(self.kick_black_list, key=lambda x: int(x))
            count = len(items)
            text = "以下为 黑名单QQ 总计{}\n{}".format(count, ("\n".join(items) if items else "（空）"))
            await event.bot.send_group_msg(group_id=int(group_id), message=text)
            return

        if msg.startswith("针对列表"):  # 查看针对名单
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 针对列表")
            items = sorted(self.target_user_list, key=lambda x: int(x))
            count = len(items)
            text = "以下为 针对名单QQ 总计{}\n{}".format(count, ("\n".join(items) if items else "（空）"))
            await event.bot.send_group_msg(group_id=int(group_id), message=text)
            return

        if msg.startswith("管理员列表"):  # 查看子管理员（新）
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

        # ====== 需要@对象的指令 ======
        at_list = []
        for segment in getattr(event.message_obj, 'message', []):
            seg_type = getattr(segment, 'type', '')
            if seg_type in ('At', 'at'):
                # 兼容 dict/对象两种取 qq
                qq = getattr(segment, 'qq', None)
                if qq is None and isinstance(segment, dict):
                    qq = segment.get('data', {}).get('qq') or segment.get('qq')
                at_list.append(qq)

        if not at_list:
            logger.error("未检测到 @目标用户，无法执行该命令")
            return

        target_id = str(at_list[0])
        logger.info(f"检测到命令针对@{target_id}")

        # ========== 各指令 ==========
        if msg.startswith("禁言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 禁言")
            duration_match = re.search(r"禁言.*?(\d+)?$", msg)
            duration = int(duration_match.group(1)) * 60 if duration_match and duration_match.group(1) else 600
            await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=duration)
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已禁言 {target_id} {duration//60}分钟")

        elif msg.startswith(("解禁", "解言")):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解禁")
            await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=0)
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已解除 {target_id} 禁言")

        elif msg.startswith("踢黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢黑")
            if target_id in self.kick_black_list:
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已存在黑名单无需踢黑！")
            else:
                self.kick_black_list.add(target_id)
                self.save_json_data()
                await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id), reject_add_request=True)
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已加入踢黑名单并踢出")

        elif msg.startswith("解黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解黑")
            self.kick_black_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移出踢黑名单")

        elif msg.startswith("踢"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢")
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已踢出 {target_id}")

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

        # ===== 仅主人可操作：设置/移除 子管理员 =====
        elif msg.startswith("设置管理员"):
            if str(sender_id) != OWNER_QQ:
                await event.bot.send_group_msg(group_id=int(group_id), message="只有主人才能设置管理员。")
                return
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 设置管理员")
            if target_id in self.sub_admin_list:
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已存在管理员无法新增！")
            else:
                self.sub_admin_list.add(target_id)
                self.save_json_data()
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已设为子管理员")

        elif msg.startswith("移除管理员"):
            if str(sender_id) != OWNER_QQ:
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
            count_match = re.search(r"撤回.*?(\d+)?$", msg)
            recall_count = int(count_match.group(1)) if count_match and count_match.group(1) else 5

            history = await event.bot.get_group_msg_history(group_id=int(group_id), count=100)
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

        # ===== 白名单相关（需要@对象） =====
        elif msg.startswith("加白"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 加白")
            if target_id in self.whitelist:
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已存在白名单无需加白！")
            else:
                self.whitelist.add(target_id)
                self.save_json_data()
                await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已加入白名单（违禁词/广告/卡片/号码/针对将不撤回，刷屏仍生效）")

        elif msg.startswith("移白"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 移白")
            self.whitelist.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移出白名单")

    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
