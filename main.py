from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.star.filter.event_message_type import EventMessageType

@register("autorecall_keyword", "YourName", "敏感词自动撤回插件(关键词匹配)", "1.0.0", "https://github.com/YourRepoLink")
class AutoRecallKeywordPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        config_data = context.get_config()
        self.bad_words = config_data.get("bad_words", [])
        logger.info(f"敏感词关键词列表已加载: {self.bad_words}")

    async def initialize(self):
        logger.info("AutoRecallKeywordPlugin 初始化完成。")

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        message_str = event.message_str.strip()

        # 逐个关键词模糊匹配
        for word in self.bad_words:
            if word in message_str:
                logger.info(f"检测到敏感词 '{word}'，撤回消息 {event.get_sender_id()}")
                try:
                    await event.bot.delete_msg(message_id=int(event.message_obj.message_id))
                except Exception as e:
                    logger.error(f"撤回消息失败: {e}")
                return  # 命中关键词后只撤回一次，退出循环

    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
