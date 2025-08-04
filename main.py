from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.star.filter.event_message_type import EventMessageType
import time
from collections import defaultdict, deque
import json
import re

@register("cesn", "Qing", "敏感词自动撤回插件(关键词匹配+刷屏检测+群管指令)", "1.1.0", "https://github.com/QingBaoNie/Cesn")
class AutoRecallKeywordPlugin(Star):
    def __init__(self, context: Context, config):
        super().__init__(context)
        self.config = config
        self.user_message_times = defaultdict(lambda: deque(maxlen=5))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=5))

        self.kick_black_list = set()
        self.target_user_list = set()
        self.sub_admin_list = set()

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

        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        logger.info(f"敏感词列表: {self.bad_words}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s 禁言{self.spam_ban_duration}s")
        logger.info(f"子管理员: {self.sub_admin_list} 黑名单: {self.kick_black_list} 针对名单: {self.target_user_list}")

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        # 黑名单自动踢
        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            await event.bot.send_group_msg(group_id, f"检测到黑名单用户 {sender_id}，已踢出！")
            return

        # 针对名单静默撤回
        if str(sender_id) in self.target_user_list:
            await event.bot.delete_msg(message_id=int(message_id))
            logger.info(f"静默撤回 {sender_id} 的消息")
            return

        # 敏感词检测
        for word in self.bad_words:
            if word in message_str:
                await self.try_recall(event, message_id, group_id, sender_id)
                return

        # 刷屏检测
        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)

        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                for msg_id in self.user_message_ids[key]:
                    await event.bot.delete_msg(message_id=int(msg_id))
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

        await self.handle_commands(event, message_str)

    async def handle_commands(self, event: AstrMessageEvent, msg: str):
        # 群管命令处理逻辑
        if match := re.match(r"禁言@(\d+)(?: (\d+))?", msg):
            user_id = match.group(1)
            duration = int(match.group(2)) * 60 if match.group(2) else 600
            await event.bot.set_group_ban(group_id=int(event.get_group_id()), user_id=int(user_id), duration=duration)
            await event.bot.send_group_msg(event.get_group_id(), f"已禁言 {user_id} {duration//60}分钟")
        elif match := re.match(r"解禁@(\d+)", msg):
            user_id = match.group(1)
            await event.bot.set_group_ban(group_id=int(event.get_group_id()), user_id=int(user_id), duration=0)
            await event.bot.send_group_msg(event.get_group_id(), f"已解除 {user_id} 禁言")
        elif match := re.match(r"踢@(\d+)", msg):
            user_id = match.group(1)
            await event.bot.set_group_kick(group_id=int(event.get_group_id()), user_id=int(user_id))
            await event.bot.send_group_msg(event.get_group_id(), f"已踢出 {user_id}")
        elif match := re.match(r"踢黑@(\d+)", msg):
            user_id = match.group(1)
            self.kick_black_list.add(user_id)
            await event.bot.set_group_kick(group_id=int(event.get_group_id()), user_id=int(user_id))
            await event.bot.send_group_msg(event.get_group_id(), f"{user_id} 已加入踢黑名单并踢出")
        elif match := re.match(r"解黑@(\d+)", msg):
            user_id = match.group(1)
            self.kick_black_list.discard(user_id)
            await event.bot.send_group_msg(event.get_group_id(), f"{user_id} 已移出踢黑名单")
        elif match := re.match(r"针对@(\d+)", msg):
            user_id = match.group(1)
            self.target_user_list.add(user_id)
            await event.bot.send_group_msg(event.get_group_id(), f"{user_id} 已加入针对名单")
        elif match := re.match(r"解针对@(\d+)", msg):
            user_id = match.group(1)
            self.target_user_list.discard(user_id)
            await event.bot.send_group_msg(event.get_group_id(), f"{user_id} 已移出针对名单")
        elif match := re.match(r"设置管理员@(\d+)", msg):
            user_id = match.group(1)
            self.sub_admin_list.add(user_id)
            await event.bot.send_group_msg(event.get_group_id(), f"{user_id} 已设为子管理员")
        elif match := re.match(r"移除管理员@(\d+)", msg):
            user_id = match.group(1)
            self.sub_admin_list.discard(user_id)
            await event.bot.send_group_msg(event.get_group_id(), f"{user_id} 已移除子管理员")

    async def try_recall(self, event: AstrMessageEvent, message_id: int, group_id: int, sender_id: int):
        try:
            await event.bot.delete_msg(message_id=int(message_id))
        except Exception as e:
            logger.error(f"撤回失败: {e}")

    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
