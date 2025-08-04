from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.star.filter.event_message_type import EventMessageType
from astrbot.core import AstrBotConfig

@register("cesn", "Qing", "敏感词自动撤回插件(关键词匹配)", "1.0.6", "https://github.com/QingBaoNie/Cesn")
class AutoRecallKeywordPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        # ⚠️ 从self.config读取
        self.bad_words = self.config.get("bad_words", [])
        logger.info(f"敏感词关键词列表已加载: {self.bad_words}")

    async def initialize(self):
        logger.info("AutoRecallKeywordPlugin 初始化完成。")

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
async def auto_recall(self, event: AstrMessageEvent):
    message_str = event.message_str.strip()
    message_id = event.message_obj.message_id
    group_id = event.get_group_id()
    sender_id = event.get_sender_id()

    logger.info(f"收到消息: [{group_id}] {sender_id}: {message_str}")
    logger.info(f"消息ID: {message_id}")

    for word in self.bad_words:
        if word in message_str:
            logger.info(f"检测到敏感词 '{word}'，准备撤回消息 {message_id}")
            try:
                result = await event.bot.delete_msg(message_id=int(message_id))
                logger.info(f"撤回API返回: {result}")
            except Exception as e:
                # 查询对方在群内的角色
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
            return  # 命中关键词后立即返回


    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
