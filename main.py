from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

@register("autorecall", "author", "敏感词自动撤回插件", "1.0.0", "repo url")
class AutoRecallPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        # 从插件配置读取敏感词列表，默认空列表
        self.bad_words = self.context.get_config("bad_words", [])
        logger.info(f"敏感词列表已加载: {self.bad_words}")

    @filter.message()
    async def auto_recall_bad_words(self, event: AstrMessageEvent):
        '''检测敏感词并自动撤回消息'''
        message_str = event.message_str.strip()

        for word in self.bad_words:
            if word in message_str:
                logger.info(f"检测到敏感词 '{word}'，撤回用户 {event.get_sender_name()} 的消息: {message_str}")
                yield event.recall()
                yield event.plain_result("⚠️ 请注意文明用语。")
                return

    async def terminate(self):
        logger.info("AutoRecallPlugin 插件已被卸载。")
