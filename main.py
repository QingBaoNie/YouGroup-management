from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.star.filter.event_message_type import EventMessageType
import time
from collections import defaultdict, deque
import json
import re

@register("cesn", "Qing", "敏感词自动撤回插件(关键词匹配+刷屏检测+群管指令)", "1.1.0", "https://github.com/QingBaoNie/Cesn")
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

        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        logger.info(f"敏感词列表: {self.bad_words}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s 禁言{self.spam_ban_duration}s")
        logger.info(f"子管理员: {self.sub_admin_list} 黑名单: {self.kick_black_list} 针对名单: {self.target_user_list}")

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        # 黑名单自动踢
        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            await event.bot.send_group_msg(group_id, f"检测到黑名单用户 {sender_id}，已踢出！")
            return

        # 针对名单静默撤回
        if str(sender_id) in self.target_user_list:
            await event.bot.delete_msg(message_id=int(message_id))
            logger.info(f"静默撤回 {sender_id} 的消息")
            return

        # 敏感词检测
        for word in self.bad_words:
            if word in message_str:
                await self.try_recall(event, message_id, group_id, sender_id)
                return

        # 刷屏检测
        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)

        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                for msg_id in self.user_message_ids[key]:
                    await event.bot.delete_msg(message_id=int(msg_id))
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

        await self.handle_commands(event, message_str)

    async def handle_commands(self, event: AstrMessageEvent, msg: str):
    match = re.search(r"\[At:(\d+)]", msg)
    if not match:
        return  # 没@人则忽略

    target_id = match.group(1)
    group_id = event.get_group_id()

    # 禁言@用户 [可选时长]
    if msg.startswith("禁言"):
        duration_match = re.search(r"禁言.*?(\d+)?$", msg)
        duration = int(duration_match.group(1)) * 60 if duration_match and duration_match.group(1) else 600
        await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=duration)
        await event.bot.send_group_msg(group_id, f"已禁言 {target_id} {duration//60}分钟")

    elif msg.startswith("解禁"):
        await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=0)
        await event.bot.send_group_msg(group_id, f"已解除 {target_id} 禁言")

    elif msg.startswith("踢黑"):
        self.kick_black_list.add(str(target_id))
        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
        await event.bot.send_group_msg(group_id, f"{target_id} 已加入踢黑名单并踢出")

    elif msg.startswith("解黑"):
        self.kick_black_list.discard(str(target_id))
        await event.bot.send_group_msg(group_id, f"{target_id} 已移出踢黑名单")

    elif msg.startswith("踢"):
        await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
        await event.bot.send_group_msg(group_id, f"已踢出 {target_id}")

    elif msg.startswith("针对"):
        self.target_user_list.add(str(target_id))
        await event.bot.send_group_msg(group_id, f"{target_id} 已加入针对名单")

    elif msg.startswith("解针对"):
        self.target_user_list.discard(str(target_id))
        await event.bot.send_group_msg(group_id, f"{target_id} 已移出针对名单")

    elif msg.startswith("设置管理员"):
        self.sub_admin_list.add(str(target_id))
        await event.bot.send_group_msg(group_id, f"{target_id} 已设为子管理员")

    elif msg.startswith("移除管理员"):
        self.sub_admin_list.discard(str(target_id))
        await event.bot.send_group_msg(group_id, f"{target_id} 已移除子管理员")


    async def try_recall(self, event: AstrMessageEvent, message_id: int, group_id: int, sender_id: int):
    try:
        await event.bot.delete_msg(message_id=int(message_id))
    except Exception as e:
        # 无论什么异常都去查用户角色
        try:
            member_info = await event.bot.get_group_member_info(
                group_id=int(group_id),
                user_id=int(sender_id)
            )
            role = member_info.get('role', 'member')
            if role == 'owner':
                logger.error(f"撤回失败: 对方是群主({sender_id})，无权限撤回。")
            elif role == 'admin':
                logger.error(f"撤回失败: 对方是管理员({sender_id})，无权限撤回。")
            else:
                logger.error(f"撤回失败: {e}（用户角色: {role}）")
        except Exception as ex:
            logger.error(f"撤回失败且查询用户角色失败: {e} / 查询错误: {ex}")


    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
