import time
import json
import re
from collections import defaultdict, deque

from astrbot import logger
from astrbot.api.star import Context, Star, register
from astrbot.core.star.filter import event_message_type
from astrbot.core.star.filter.event_message_type import EventMessageType
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent as AstrMessageEvent

@register("susceptible", "Qing", "敏感词自动撤回插件(关键词匹配+刷屏检测+群管指令)", "1.1.5", "https://github.com/QingBaoNie/Cesn")
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

        self.recall_links = admin_config.get("recall_links", False)
        self.recall_cards = admin_config.get("recall_cards", False)
        self.recall_numbers = admin_config.get("recall_numbers", False)

        self.save_json_data()

        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        logger.info(f"敏感词列表: {self.bad_words}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s 禁言{self.spam_ban_duration}s")
        logger.info(f"子管理员: {self.sub_admin_list} 黑名单: {self.kick_black_list} 针对名单: {self.target_user_list}")

    def save_json_data(self):
        data = {
            'kick_black_list': list(self.kick_black_list),
            'target_user_list': list(self.target_user_list),
            'sub_admin_list': list(self.sub_admin_list)
        }
        with open('cesn_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("已保存数据到 cesn_data.json")

    @event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        if getattr(event.message_obj.raw_message, 'post_type', '') == 'notice':
            return

        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        if message_str.startswith("撤回"):
            logger.info("检测到撤回命令，跳过刷屏检测")
            await self.handle_commands(event)
            return

        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            await event.bot.send_group_msg(group_id=int(group_id), message=f"检测到黑名单用户 {sender_id}，已踢出！")
            return

        if str(sender_id) in self.target_user_list:
            await event.bot.delete_msg(message_id=message_id)
            logger.info(f"静默撤回 {sender_id} 的消息")
            return

        for word in self.bad_words:
            if word in message_str:
                await self.try_recall(event, message_id, group_id, sender_id)
                return

        if self.recall_links and ("http://" in message_str or "https://" in message_str):
            await self.try_recall(event, message_id, group_id, sender_id)
            logger.info(f"检测到链接，已撤回 {sender_id} 的消息")
            return

        if self.recall_cards:
            for segment in getattr(event.message_obj, 'message', []):
                if segment.type in ['Share', 'Card', 'Contact', 'Json', 'Xml']:
                    await self.try_recall(event, message_id, group_id, sender_id)
                    logger.info(f"检测到卡片消息，已撤回 {sender_id} 的消息")
                    return

        if self.recall_numbers:
            for segment in getattr(event.message_obj, 'message', []):
                if segment.type == 'Text':
                    text_content = segment.data.get('text', '')
                    if re.search(r"\d{6,}", text_content):
                        await self.try_recall(event, message_id, group_id, sender_id)
                        logger.info(f"检测到连续数字，已撤回 {sender_id} 的消息: {text_content}")
                        return

        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)

        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                for msg_id in self.user_message_ids[key]:
                    await event.bot.delete_msg(message_id=msg_id)
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

        await self.handle_commands(event)

    @event_message_type(EventMessageType.ALL)
    async def handle_group_increase(self, event: AstrMessageEvent):
        if getattr(event.message_obj, 'notice_type', None) != 'group_increase':
            return

        group_id = event.get_group_id()
        user_id = event.message_obj.user_id

        if str(user_id) in self.kick_black_list:
            try:
                await event.bot.set_group_kick(group_id=int(group_id), user_id=int(user_id))
                await event.bot.send_group_msg(group_id=int(group_id), message=f"检测到黑名单用户 {user_id}，已踢出并处理！")
            except Exception as e:
                logger.error(f"踢出黑名单用户 {user_id} 失败: {e}")
