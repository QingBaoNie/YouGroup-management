from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

@register("autorecall", "YourName", "敏感词自动撤回插件", "1.0.0")
class AutoRecallPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        self.bad_words = self.context.get_config("bad_words", [])  # 从配置读取敏感词列表
        logger.info(f"敏感词列表已加载: {self.bad_words}")

    async def initialize(self):
        """插件初始化时调用"""
        logger.info("AutoRecallPlugin 初始化完成。")

    @filter.message()
    async def auto_recall_bad_words(self, event: AstrMessageEvent):
        """监听消息，检测敏感词并撤回"""
        message_str = event.message_str.strip()
        message_chain = event.get_messages()
        logger.info(f"接收到消息: {message_chain}")

        for word in self.bad_words:
            if word in message_str:
                logger.info(f"检测到敏感词 '{word}'，撤回用户 {event.get_sender_name()} 的消息。")
                yield event.recall()
                yield event.plain_result("⚠️ 请注意文明用语。")
                return

    async def terminate(self):
        """插件卸载/停用时调用"""
        logger.info("AutoRecallPlugin 插件已被卸载。")
