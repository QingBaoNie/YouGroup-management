from astrbot.api.star import Context, Star, register
from astrbot.api.event import AstrMessageEvent
from astrbot.core.star import filter
from astrbot.api import logger

@register("autorecall", "YourName", "敏感词自动撤回插件", "1.0.0", "https://github.com/QingBaoNie/Cesn")
class AutoRecallPlugin(Star):
    def __init__(self, context: Context, **kwargs):
        super().__init__(context)
        config_data = context.get_config()

        self.bad_words = config_data.get("bad_words", [])
        self.ban_duration = config_data.get("ban_duration", 60)  # 单位秒
        self.group_whitelist = config_data.get("group_whitelist", [])  # 群聊白名单
        logger.info(f"敏感词列表已加载: {self.bad_words}")
        logger.info(f"白名单群聊: {self.group_whitelist}, 禁言时长: {self.ban_duration}s")

    async def initialize(self):
        logger.info("AutoRecallPlugin 初始化完成。")

    @filter.event_message_type(filter.EventMessageType.GROUP_MESSAGE)
    async def auto_recall_and_ban(self, event: AstrMessageEvent):
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()
        message_str = event.message_str.strip()

        # 群聊白名单过滤
        if self.group_whitelist and group_id not in self.group_whitelist:
            return

        logger.info(f"[{group_id}] {sender_id}: {message_str}")

        for word in self.bad_words:
            if word in message_str:
                logger.info(f"检测到敏感词 '{word}'，撤回并禁言 {sender_id}")

                # 撤回消息
                try:
                    message_id = event.message_obj.message_id
                    await event.bot.delete_msg(message_id=int(message_id))
                except Exception as e:
                    logger.error(f"撤回消息失败: {e}")

                # 禁言用户
                if self.ban_duration > 0:
                    try:
                        await event.bot.set_group_ban(
                            group_id=int(group_id),
                            user_id=int(sender_id),
                            duration=self.ban_duration
                        )
                    except Exception as e:
                        logger.error(f"禁言失败: {e}")

                # 警告提示
                yield event.plain_result(f"⚠️ {event.get_sender_name()} 发送了违禁词，已被撤回并禁言{self.ban_duration}s。")
                return

    async def terminate(self):
        logger.info("AutoRecallPlugin 插件已被卸载。")
