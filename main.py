from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.star.filter.event_message_type import EventMessageType
import time
from collections import defaultdict, deque

@register("cesn", "Qing", "敏感词自动撤回插件(关键词匹配+刷屏检测)", "1.0.7", "https://github.com/QingBaoNie/Cesn")
class AutoRecallKeywordPlugin(Star):
    def __init__(self, context: Context, config):
        super().__init__(context)
        self.config = config

        # 初始化缓存（先默认5，initialize时会刷新）
        self.user_message_times = defaultdict(lambda: deque(maxlen=5))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=5))

    async def initialize(self):
        config_data = self.config  # ← 读取 config，不是 context.get_config()

        # 读取敏感词配置
        self.bad_words = config_data.get("bad_words", [])

        # 读取刷屏检测配置 (包裹在 spam_config 里)
        spam_config = config_data.get("spam_config", {})
        self.spam_count = spam_config.get("spam_count", 5)
        self.spam_interval = spam_config.get("spam_interval", 3)
        self.spam_ban_duration = spam_config.get("spam_ban_duration", 60)

        # 刷新缓存容量
        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        logger.info(f"敏感词关键词列表已加载: {self.bad_words}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s，禁言{self.spam_ban_duration}s")

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        logger.info(f"收到消息: [{group_id}] {sender_id}: {message_str}")

        # 敏感词检测
        for word in self.bad_words:
            if word in message_str:
                logger.info(f"检测到敏感词 '{word}'，准备撤回消息 {message_id}")
                await self.try_recall(event, message_id, group_id, sender_id)
                return

        # 刷屏检测
        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)

        if len(self.user_message_times[key]) == self.spam_count:
            time_window = now - self.user_message_times[key][0]
            if time_window <= self.spam_interval:
                logger.info(f"检测到用户 {sender_id} 在群 {group_id} 刷屏，准备禁言并撤回消息")
                try:
                    await event.bot.set_group_ban(
                        group_id=int(group_id),
                        user_id=int(sender_id),
                        duration=self.spam_ban_duration
                    )
                    logger.info(f"已将 {sender_id} 禁言 {self.spam_ban_duration}s")
                except Exception as e:
                    logger.error(f"禁言失败: {e}")

                for msg_id in self.user_message_ids[key]:
                    try:
                        await event.bot.delete_msg(message_id=int(msg_id))
                        logger.info(f"已撤回刷屏消息ID {msg_id}")
                    except Exception as e:
                        logger.error(f"撤回刷屏消息ID {msg_id} 失败: {e}")

                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

    async def try_recall(self, event: AstrMessageEvent, message_id: int, group_id: int, sender_id: int):
        try:
            result = await event.bot.delete_msg(message_id=int(message_id))
            logger.info(f"撤回API返回: {result}")
        except Exception as e:
            try:
                member_info = await event.bot.get_group_member_info(
                    group_id=int(group_id),
                    user_id=int(sender_id)
                )
                role = member_info.get('role', 'unknown')
                if role == 'admin':
                    logger.error(f"撤回失败: 对方是管理员({sender_id})，Bot无权限撤回。")
                elif role == 'owner':
                    logger.error(f"撤回失败: 对方是群主({sender_id})，Bot无权限撤回。")
                else:
                    logger.error(f"撤回失败: {e} （用户角色: {role}）")
            except Exception as ex:
                logger.error(f"撤回失败且查询用户角色失败: {e} / 查询错误: {ex}")

    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
