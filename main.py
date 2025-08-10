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


@register("susceptible", "Qing", "敏感词自动撤回插件(关键词匹配+刷屏检测+群管指令+查共群)", "1.2.0", "https://github.com/QingBaoNie/Cesn")
class AutoRecallKeywordPlugin(Star):
    def __init__(self, context: Context, config):
        super().__init__(context)
        self.config = config
        self.user_message_times = defaultdict(lambda: deque(maxlen=5))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=5))
        self.kick_black_list = set()
        self.target_user_list = set()
        self.sub_admin_list = set()
        self.whitelist = set()  # 白名单

        # ===== 新增：入群欢迎配置（默认关闭）=====
        self.welcome_enabled = False
        self.welcome_groups = set()
        self.welcome_template = "欢迎 {name} 加入 {group} ~"
        self.welcome_autodel = 0  # 秒；0 表示不自动撤回

    async def initialize(self):
        config_data = self.config
        self.bad_words = config_data.get("bad_words", [])
        spam_config = config_data.get("spam_config", {})
        admin_config = config_data.get("admin_config", {})

        self.spam_count = spam_config.get("spam_count", 5)
        self.spam_interval = spam_config.get("spam_interval", 3)
        self.spam_ban_duration = spam_config.get("spam_ban_duration", 60)

        self.sub_admin_list = set(admin_config.get("sub_admin_list", []))
        self.kick_black_list = set(admin_config.get("kick_black_list", []))
        self.target_user_list = set(admin_config.get("target_user_list", []))
        self.whitelist = set(admin_config.get("whitelist", []))  # 从配置加载白名单

        self.recall_links = admin_config.get("recall_links", False)
        self.recall_cards = admin_config.get("recall_cards", False)
        self.recall_numbers = admin_config.get("recall_numbers", False)

        # ===== 新增：读取入群欢迎配置 =====
        welcome_cfg = admin_config.get("welcome", {})
        self.welcome_enabled = bool(welcome_cfg.get("enabled", False))
        # 仅这些群号生效（字符串存储）
        self.welcome_groups = set(str(x) for x in welcome_cfg.get("groups", []))
        self.welcome_template = welcome_cfg.get("template", "欢迎 {name} 加入 {group} ~")
        self.welcome_autodel = int(welcome_cfg.get("auto_delete_seconds", 0))

        self.save_json_data()

        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        logger.info(f"敏感词列表: {self.bad_words}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s 禁言{self.spam_ban_duration}s")
        logger.info(f"子管理员: {self.sub_admin_list} 黑名单: {self.kick_black_list} 针对名单: {self.target_user_list} 白名单: {self.whitelist}")
        logger.info(f"入群欢迎: enabled={self.welcome_enabled} groups={self.welcome_groups or '[]'} autodel={self.welcome_autodel}s")

    def save_json_data(self):
        data = {
            'kick_black_list': list(self.kick_black_list),
            'target_user_list': list(self.target_user_list),
            'sub_admin_list': list(self.sub_admin_list),
            'whitelist': list(self.whitelist),  # 持久化白名单
        }
        with open('cesn_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("已保存数据到 cesn_data.json")

    async def _auto_delete_after(self, bot, message_id: int, delay: int = 60):
        """延时撤回消息"""
        try:
            await asyncio.sleep(delay)
            await bot.delete_msg(message_id=message_id)
            logger.debug(f"已自动撤回 message_id={message_id}")
        except Exception as e:
            logger.error(f"定时撤回失败 message_id={message_id}: {e}")

    # ===== 新增：欢迎模板渲染 =====
    def _render_welcome(self, template: str, payload: dict) -> str:
        """
        可用变量：
          {name}  新人显示名（群名片优先，次选昵称，最后QQ号）
          {qq}    新人QQ号
          {group} 群名称
          {group_id} 群号
          {time}  当前时间（本地）
        """
        try:
            return template.format(**payload)
        except Exception as e:
            logger.error(f"欢迎模板渲染失败，将使用原模板。错误: {e}")
            return template

    # ===== 新增：监听所有事件，捕获入群通知 =====
    @filter.event()
    async def on_any_event(self, event: AstrMessageEvent):
        """
        通过 notice_type == 'group_increase' 判断新人入群。
        仅当：
          1) 开关开启；
          2) 群号在配置的 groups 列表中（列表为空则不在任何群启用）；
          3) 能拿到新人 user_id；
        才会发送欢迎消息。
        """
        try:
            notice_type = getattr(event.message_obj, "notice_type", "")
            if notice_type != "group_increase":
                return

            group_id = str(event.get_group_id())

            if not self.welcome_enabled:
                return
            if self.welcome_groups and (group_id not in self.welcome_groups):
                return

            new_user_id = getattr(event.message_obj, "user_id", None)
            if not new_user_id:
                logger.error("入群欢迎：未获取到 user_id，跳过。")
                return

            # 获取新人名片/昵称
            display_name = str(new_user_id)
            try:
                info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(new_user_id))
                display_name = info.get("card") or info.get("nickname") or str(new_user_id)
            except Exception as e:
                logger.error(f"获取新人资料失败：{e}")

            # 获取群名称
            group_name = group_id
            try:
                ginfo = await event.bot.get_group_info(group_id=int(group_id))
                group_name = ginfo.get("group_name", group_id)
            except Exception as e:
                logger.error(f"获取群资料失败：{e}")

            payload = {
                "name": display_name,
                "qq": str(new_user_id),
                "group": group_name,
                "group_id": group_id,
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            }
            text = self._render_welcome(self.welcome_template, payload)

            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 入群欢迎")

            # @新人 + 欢迎文本
            message_segments = [
                {"type": "At", "data": {"qq": str(new_user_id)}},
                {"type": "text", "data": {"text": f" {text}"}}
            ]
            resp = await event.bot.send_group_msg(group_id=int(group_id), message=message_segments)

            # 自动撤回（如配置了）
            if self.welcome_autodel and isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=self.welcome_autodel))

        except Exception as e:
            logger.error(f"入群欢迎处理异常：{e}")

    # ===== 权限工具 =====
    async def _get_member_role(self, event: AstrMessageEvent, group_id: int, user_id: int) -> str:
        """获取成员在群内的角色：owner/admin/member。失败时按member处理。"""
        try:
            info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(user_id))
            return info.get("role", "member")
        except Exception as e:
            logger.error(f"获取用户 {user_id} 在群 {group_id} 角色失败: {e}")
            return "member"

    async def _is_operator(self, event: AstrMessageEvent, group_id: int, user_id: int) -> bool:
        """
        只有群主/管理员（可选：包含子管理员）可以操作群管命令。
        如不想放开子管理员，把最后那行对子管理员的判断删掉即可。
        """
        role = await self._get_member_role(event, group_id, user_id)
        if role in ("owner", "admin"):
            return True
        # 想禁用子管理员权限，注释/删除下一行
        if str(user_id) in self.sub_admin_list:
            return True
        return False

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        # 跳过系统通知
        if getattr(event.message_obj.raw_message, 'post_type', '') == 'notice':
            return

        group_id = event.get_group_id()
        sender_id = event.get_sender_id()
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id

        # === 查共群（对所有人开放，不需@）===
        if message_str.startswith("查共群"):
            await self.handle_check_common_groups(event)
            return

        # 1. 群管命令识别
        command_keywords = (
            "禁言", "解禁", "解言", "踢黑", "解黑",
            "踢", "针对", "解针对", "设置管理员", "移除管理员", "撤回",
            "全体禁言", "全体解言",
            "加白", "移白", "白名单列表",
        )
        if message_str.startswith(command_keywords):
            # 仅群主/管理员/（可选）子管理员可执行
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

            await self.handle_commands(event)
            return

        # 2. 非命令消息 → 群主/管理员跳过撤回机制
        try:
            member_info = await event.bot.get_group_member_info(
                group_id=int(group_id), user_id=int(sender_id)
            )
            role = member_info.get("role", "member")
            if role in ("owner", "admin"):
                logger.debug(f"检测到 {sender_id} 身份为 {role}，跳过撤回检测")
                return
        except Exception as e:
            logger.error(f"获取用户 {sender_id} 群身份失败: {e}")

        # 3. 黑名单处理（优先生效，不受白名单影响）
        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            await event.bot.send_group_msg(
                group_id=int(group_id),
                message=f"检测到黑名单用户 {sender_id}，已踢出！"
            )
            return

        # 3.5 白名单：跳过关键词/链接/卡片/号码/针对名单撤回，但保留刷屏检测
        is_whitelisted = str(sender_id) in self.whitelist
        if is_whitelisted:
            logger.debug(f"{sender_id} 在白名单中：跳过违禁词/广告/卡片/号码/针对撤回，仅保留刷屏检测")

        # 4. 针对名单处理（白名单覆盖针对）
        if not is_whitelisted and (str(sender_id) in self.target_user_list):
            await event.bot.delete_msg(message_id=message_id)
            logger.info(f"静默撤回 {sender_id} 的消息（针对名单）")
            return

        # 5. 关键词检测
        if not is_whitelisted:
            for word in self.bad_words:
                if word and word in message_str:
                    await self.try_recall(event, message_id, group_id, sender_id)
                    return

        # 6. 链接检测
        if (not is_whitelisted) and self.recall_links and ("http://" in message_str or "https://" in message_str):
            await self.try_recall(event, message_id, group_id, sender_id)
            logger.info(f"检测到链接，已撤回 {sender_id} 的消息")
            return

        # 7. 卡片消息检测
        if (not is_whitelisted) and self.recall_cards:
            for segment in getattr(event.message_obj, 'message', []):
                seg_type = getattr(segment, 'type', '')
                if seg_type in ['Share', 'Card', 'Contact', 'Json', 'Xml', 'share', 'json', 'xml', 'contact']:
                    await self.try_recall(event, message_id, group_id, sender_id)
                    logger.info(f"检测到卡片消息，已撤回 {sender_id} 的消息")
                    return

        # 8. 号码检测
        if (not is_whitelisted) and self.recall_numbers:
            clean_msg = re.sub(r"\[At:\d+\]", "", message_str)
            clean_msg = re.sub(r"@\S+\(\d+\)", "", clean_msg)
            clean_msg = clean_msg.strip()
            match = re.search(r"\d{6,}", clean_msg)
            if match:
                await self.try_recall(event, message_id, group_id, sender_id)
                logger.info(f"检测到连续数字，已撤回 {sender_id} 的消息: {message_str}")
                return

        # 9. 刷屏检测（白名单也生效）
        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)

        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                await event.bot.set_group_ban(
                    group_id=int(group_id),
                    user_id=int(sender_id),
                    duration=self.spam_ban_duration
                )
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
                if role == 'owner':
                    logger.error(f"撤回失败: 对方是群主({sender_id})，无权限撤回。")
                elif role == 'admin':
                    logger.error(f"撤回失败: 对方是管理员({sender_id})，无权限撤回。")
                else:
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

    async def handle_commands(self, event: AstrMessageEvent):
        msg = event.message_str.strip()
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        # 二次拦截，防止外部误调用绕过
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

        # ====== 需要@对象的指令 ======
        at_list = []
        for segment in getattr(event.message_obj, 'message', []):
            if getattr(segment, 'type', '') == 'At':
                at_list.append(getattr(segment, 'qq', None))

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

        elif msg.startswith("设置管理员"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 设置管理员")
            self.sub_admin_list.add(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已设为子管理员")

        elif msg.startswith("移除管理员"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 移除管理员")
            self.sub_admin_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移除子管理员")

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
