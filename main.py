from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

@register("helloworld", "author", "一个简单的 Hello World 插件", "1.0.0", "repo url")
class MyPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)

    @filter.command("helloworld")
    async def helloworld(self, event: AstrMessageEvent):
        '''这是一个 hello world 指令'''
        user_name = event.get_sender_name()
        message_str = event.message_str
        logger.info("触发 hello world 指令!")
        yield event.plain_result(f"Hello, {user_name}!")

    @filter.message()  # 监听所有消息事件
    async def auto_recall_bad_words(self, event: AstrMessageEvent):
        '''检测敏感词并自动撤回消息'''
        message_str = event.message_str.strip()

        bad_words = ["操你妈"]  # 可扩展更多敏感词
        if any(word in message_str for word in bad_words):
            logger.info(f"检测到敏感词，撤回用户 {event.get_sender_name()} 的消息: {message_str}")
            yield event.recall()  # 调用撤回动作
           
    async def terminate(self):
        '''插件被卸载/停用时调用'''
        logger.info("MyPlugin 插件已被卸载。")
