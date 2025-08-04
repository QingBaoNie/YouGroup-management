from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

@register(
    "Qing",  # 插件唯一识别名，必须与 metadata.yaml 的 name 一致
    "Qing",  # 作者
    "这是 AstrBot 的默认插件，支持关键词回复。",  # 插件描述
    "1.1",   # 插件版本 (与 metadata.yaml 的 version 对应，不带v)
    "https://github.com/QingBaoNie/Cesn"  # 仓库地址
)
class QingPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        self.bad_words = self.context.get_config("bad_words", [])  # 从配置读取敏感词列表
        logger.info(f"敏感词列表已加载: {self.bad_words}")

    async def initialize(self):
        """插件初始化时调用"""
        logger.info("QingPlugin 初始化完成。")

    @filter.message()
    async def auto_recall_bad_words(self, event: AstrMessageEvent):
        """监听消息，检测敏感词并撤回"""
        message_str = event.message_str.strip()
        logger.info(f"接收到消息: {message_str}")

        for word in self.bad_words:
            if word in message_str:
                logger.info(f"检测到敏感词 '{word}'，撤回用户 {event.get_sender_name()} 的消息。")
                yield event.recall()  # 撤回消息
                yield event.plain_result("⚠️ 请注意文明用语。")
                return  # 撤回后结束处理

    async def terminate(self):
        """插件卸载/停用时调用"""
        logger.info("QingPlugin 插件已被卸载。")
