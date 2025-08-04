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
        self.load_json_data()

    def load_json_data(self):
        try:
            with open('group_mgmt_data.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.kick_black_list = set(data.get('kick_black_list', []))
                self.target_user_list = set(data.get('target_user_list', []))
                self.sub_admin_list = set(data.get('sub_admin_list', []))
        except FileNotFoundError:
            self.save_json_data()

    def save_json_data(self):
        data = {
            'kick_black_list': list(self.kick_black_list),
            'target_user_list': list(self.target_user_list),
            'sub_admin_list': list(self.sub_admin_list)
        }
        with open('group_mgmt_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    async def initialize(self):
        config_data = self.config
        self.bad_words = config_data.get("bad_words", [])
        spam_config = config_data.get("spam_config", {})
        self.spam_count = spam_config.get("spam_count", 5)
        self.spam_interval = spam_config.get("spam_interval", 3)
        self.spam_ban_duration = spam_config.get("spam_ban_duration", 60)
        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            logger.info(f"检测到黑名单用户 {sender_id} ，已踢出！")
            return

        if str(sender_id) in self.target_user_list:
            await event.bot.delete_msg(message_id=int(message_id))
            logger.info(f"针对用户 {sender_id} 静默撤回消息")
            return

        for word in self.bad_words:
            if word in message_str:
                await self.try_recall(event, message_id, group_id, sender_id)
                return

        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)

        if len(self.user_message_times[key]) == self.spam_count:
            time_window = now - self.user_message_times[key][0]
            if time_window <= self.spam_interval:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                for msg_id in self.user_message_ids[key]:
                    await event.bot.delete_msg(message_id=int(msg_id))
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

        await self.handle_commands(event, message_str)

    async def handle_commands(self, event: AstrMessageEvent, msg: str):
        if not event.is_admin() and str(event.get_sender_id()) not in self.sub_admin_list:
            return

        match = re.match(r"禁言@(\d+)(?: (\d+))?", msg)
        if match:
            user_id, duration = match.groups()
            duration = int(duration) * 60 if duration else 600
            await event.bot.set_group_ban(group_id=int(event.get_group_id()), user_id=int(user_id), duration=duration)
            logger.info(f"已禁言 {user_id} {duration}秒")
            return

        match = re.match(r"解禁@(\d+)", msg)
        if match:
            user_id = match.group(1)
            await event.bot.set_group_ban(group_id=int(event.get_group_id()), user_id=int(user_id), duration=0)
            logger.info(f"已解禁 {user_id}")
            return

        match = re.match(r"踢@(\d+)", msg)
        if match:
            user_id = match.group(1)
            await event.bot.set_group_kick(group_id=int(event.get_group_id()), user_id=int(user_id))
            logger.info(f"已踢出 {user_id}")
            return

        match = re.match(r"踢黑@(\d+)", msg)
        if match:
            user_id = match.group(1)
            self.kick_black_list.add(user_id)
            self.save_json_data()
            await event.bot.set_group_kick(group_id=int(event.get_group_id()), user_id=int(user_id))
            logger.info(f"已将 {user_id} 加入踢黑并踢出")
            return

        match = re.match(r"解黑@(\d+)", msg)
        if match:
            user_id = match.group(1)
            self.kick_black_list.discard(user_id)
            self.save_json_data()
            logger.info(f"已将 {user_id} 从踢黑列表移除")
            return

        match = re.match(r"针对@(\d+)", msg)
        if match:
            user_id = match.group(1)
            self.target_user_list.add(user_id)
            self.save_json_data()
            logger.info(f"已将 {user_id} 添加到针对列表")
            return

        match = re.match(r"解针对@(\d+)", msg)
        if match:
            user_id = match.group(1)
            self.target_user_list.discard(user_id)
            self.save_json_data()
            logger.info(f"已将 {user_id} 从针对列表移除")
            return

        match = re.match(r"设置管理员@(\d+)", msg)
        if match:
            user_id = match.group(1)
            self.sub_admin_list.add(user_id)
            self.save_json_data()
            logger.info(f"已将 {user_id} 添加为子管理员")
            return

        match = re.match(r"移除管理员@(\d+)", msg)
        if match:
            user_id = match.group(1)
            self.sub_admin_list.discard(user_id)
            self.save_json_data()
            logger.info(f"已将 {user_id} 移除子管理员")
            return

    async def try_recall(self, event: AstrMessageEvent, message_id: int, group_id: int, sender_id: int):
        try:
            await event.bot.delete_msg(message_id=int(message_id))
        except Exception as e:
            try:
                member_info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(sender_id))
                role = member_info.get('role', 'unknown')
                if role == 'admin':
                    logger.error(f"撤回失败: 对方是管理员({sender_id})")
                elif role == 'owner':
                    logger.error(f"撤回失败: 对方是群主({sender_id})")
                else:
                    logger.error(f"撤回失败: {e} （用户角色: {role}）")
            except Exception as ex:
                logger.error(f"撤回失败且查询用户角色失败: {e} / 查询错误: {ex}")

    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
