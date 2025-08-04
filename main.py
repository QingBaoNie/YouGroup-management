from astrbot.api.event import AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.star.filter.event_message_type import EventMessageType
from astrbot.api.event import filter

@register("autorecall", "YourName", "敏感词自动撤回插件", "1.0.0")
class AutoRecallPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        self.bad_words = context.get_config("bad_words", [])  # 读取敏感词配置
        logger.info(f"敏感词列表已加载: {self.bad_words}")

    async def initialize(self):
        logger.info("AutoRecallPlugin 初始化完成。")

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall_bad_words(self, event: AstrMessageEvent, context: Context, *args, **kwargs):
        """监听消息，检测敏感词并撤回"""
        message_str = event.message_str.strip()
        logger.info(f"接收到消息: {message_str}")

        for word in self.bad_words:
            if word in message_str:
                logger.info(f"检测到敏感词 '{word}'，撤回用户 {event.get_sender_name()} 的消息。")
                yield event.recall()
                yield event.plain_result("⚠️ 请注意文明用语。")
                return  # 撤回后结束

    async def terminate(self):
        logger.info("AutoRecallPlugin 插件已被卸载。")
