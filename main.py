import time
import json
import re
import urllib.parse
import asyncio
from collections import defaultdict, deque

from astrbot import logger
from astrbot.api.star import Context, Star, register
from astrbot.api.event import filter
from astrbot.core.star.filter.event_message_type import EventMessageType
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent as AstrMessageEvent


@register("susceptible", "Qing", "敏感词自动撤回插件(关键词匹配+刷屏检测+群管指令+查共群+二维码识别)", "1.2.0", "https://github.com/QingBaoNie/Cesn")
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

        self.recall_links = admin_config.get("recall_links", False)
        self.recall_cards = admin_config.get("recall_cards", False)
        self.recall_numbers = admin_config.get("recall_numbers", False)
        self.recall_qrcode = admin_config.get("recall_qrcode", False)

        self.save_json_data()

        self.user_message_times = defaultdict(lambda: deque(maxlen=self.spam_count))
        self.user_message_ids = defaultdict(lambda: deque(maxlen=self.spam_count))

        logger.info(f"敏感词列表: {self.bad_words}")
        logger.info(f"刷屏检测配置: {self.spam_count}条/{self.spam_interval}s 禁言{self.spam_ban_duration}s")
        logger.info(f"子管理员: {self.sub_admin_list} 黑名单: {self.kick_black_list} 针对名单: {self.target_user_list}")
        logger.info(f"功能开关：链接={self.recall_links} 卡片={self.recall_cards} 号码={self.recall_numbers} 二维码={self.recall_qrcode}")

    def save_json_data(self):
        data = {
            'kick_black_list': list(self.kick_black_list),
            'target_user_list': list(self.target_user_list),
            'sub_admin_list': list(self.sub_admin_list)
        }
        with open('cesn_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("已保存数据到 cesn_data.json")

    async def _auto_delete_after(self, bot, message_id: int, delay: int = 60):
        try:
            await asyncio.sleep(delay)
            await bot.delete_msg(message_id=message_id)
            logger.debug(f"已自动撤回 message_id={message_id}")
        except Exception as e:
            logger.error(f"定时撤回失败 message_id={message_id}: {e}")

    # ===== 权限工具 =====
    async def _get_member_role(self, event: AstrMessageEvent, group_id: int, user_id: int) -> str:
        try:
            info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(user_id))
            return info.get("role", "member")
        except Exception as e:
            logger.error(f"获取用户 {user_id} 在群 {group_id} 角色失败: {e}")
            return "member"

    async def _is_operator(self, event: AstrMessageEvent, group_id: int, user_id: int) -> bool:
        role = await self._get_member_role(event, group_id, user_id)
        if role in ("owner", "admin"):
            return True
        if str(user_id) in self.sub_admin_list:
            return True
        return False

    # ===== 二维码检测工具 =====
    def _detect_qr_in_image(self, file_path: str) -> bool:
        # 方案1：OpenCV
        try:
            import cv2  # type: ignore
            img = cv2.imread(file_path)
            if img is not None:
                detector = cv2.QRCodeDetector()
                data, points, _ = detector.detectAndDecode(img)
                if (isinstance(data, str) and data) or (points is not None and len(points) > 0):
                    return True
        except Exception:
            pass

        # 方案2：pyzbar + Pillow
        try:
            from PIL import Image  # type: ignore
            from pyzbar.pyzbar import decode  # type: ignore
            im = Image.open(file_path)
            codes = decode(im)
            if codes:
                return True
        except Exception:
            pass

        return False

    async def _segment_has_qr(self, event: AstrMessageEvent, segment) -> bool:
        """
        兼容多种消息段结构，取到 file/url 后用 get_image 获取本地缓存路径再检测
        """
        file_id = None
        seg_type = ""

        if isinstance(segment, dict):
            seg_type = str(segment.get('type', '')).lower()
            data_obj = segment.get('data', {}) if isinstance(segment.get('data'), dict) else {}
            file_id = segment.get('file') or data_obj.get('file') or segment.get('url') or data_obj.get('url')
        else:
            seg_type = str(getattr(segment, 'type', '')).lower()
            file_id = getattr(segment, 'file', None)
            if not file_id and hasattr(segment, 'data'):
                try:
                    d = segment.data
                    if isinstance(d, dict):
                        file_id = d.get('file') or d.get('url')
                    elif hasattr(d, 'get'):
                        file_id = d.get('file') or d.get('url')
                except Exception:
                    pass

        if not file_id:
            logger.debug("[二维码] 未获取到图片file/url，段类型=%s，内容(截断)=%s", seg_type, str(segment)[:160])
            return False

        try:
            info = await event.bot.get_image(file=file_id)  # {"file": "/path/to/cache.jpg"}
            local_path = (info or {}).get("file")
            if not local_path:
                logger.debug("[二维码] get_image 返回空路径 file=%s info=%s", file_id, info)
                return False
        except Exception as e:
            logger.error(f"[二维码] get_image 失败 file={file_id}: {e}")
            return False

        try:
            return await asyncio.to_thread(self._detect_qr_in_image, local_path)
        except Exception as e:
            logger.error(f"[二维码] 检测线程异常: {e}")
            return False

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def auto_recall(self, event: AstrMessageEvent):
        # 跳过系统通知
        if getattr(event.message_obj.raw_message, 'post_type', '') == 'notice':
            return

        group_id = event.get_group_id()
        sender_id = event.get_sender_id()
        message_str = event.message_str.strip()
        message_id = event.message_obj.message_id

        # === 查共群（对所有人开放，不需@）===
        if message_str.startswith("查共群"):
            await self.handle_check_common_groups(event)
            return

        # 1. 群管命令识别
        command_keywords = (
            "禁言", "解禁", "解言", "踢黑", "解黑",
            "踢", "针对", "解针对", "设置管理员", "移除管理员", "撤回",
            "全体禁言", "全体解言"
        )
        if message_str.startswith(command_keywords):
            if not await self._is_operator(event, int(group_id), int(sender_id)):
                try:
                    resp = await event.bot.send_group_msg(group_id=int(group_id), message="你配指挥我吗？")
                    if isinstance(resp, dict) and "message_id" in resp:
                        asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=10))
                except Exception as e:
                    logger.error(f"发送无权限提示失败: {e}")
                return
            await self.handle_commands(event)
            return

        # 2. 非命令消息 → 群主/管理员跳过撤回机制
        try:
            member_info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(sender_id))
            role = member_info.get("role", "member")
            if role in ("owner", "admin"):
                logger.debug(f"检测到 {sender_id} 身份为 {role}，跳过撤回检测")
                return
        except Exception as e:
            logger.error(f"获取用户 {sender_id} 群身份失败: {e}")

        # 3. 黑名单处理
        if str(sender_id) in self.kick_black_list:
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(sender_id))
            await event.bot.send_group_msg(group_id=int(group_id), message=f"检测到黑名单用户 {sender_id}，已踢出！")
            return

        # 4. 针对名单处理
        if str(sender_id) in self.target_user_list:
            await event.bot.delete_msg(message_id=message_id)
            logger.info(f"静默撤回 {sender_id} 的消息")
            return

        # 5. 关键词检测
        for word in self.bad_words:
            if word and word in message_str:
                await self.try_recall(event, message_id, group_id, sender_id)
                return

        # 6. 链接检测
        if self.recall_links and ("http://" in message_str or "https://" in message_str):
            await self.try_recall(event, message_id, group_id, sender_id)
            logger.info(f"检测到链接，已撤回 {sender_id} 的消息")
            return

        # 7. 卡片消息检测
        if self.recall_cards:
            for segment in getattr(event.message_obj, 'message', []):
                seg_type = getattr(segment, 'type', '')
                if seg_type in ['Share', 'Card', 'Contact', 'Json', 'Xml', 'share', 'json', 'xml', 'contact']:
                    await self.try_recall(event, message_id, group_id, sender_id)
                    logger.info(f"检测到卡片消息，已撤回 {sender_id} 的消息")
                    return

        # 7.5 二维码图片检测（仅当开启）
        if self.recall_qrcode:
            for seg in getattr(event.message_obj, 'message', []):
                seg_type = str(getattr(seg, 'type', seg.get('type') if isinstance(seg, dict) else '')).lower()
                if seg_type in ('image', 'imageurl', 'imagefile'):
                    try:
                        has_qr = await self._segment_has_qr(event, seg)
                    except Exception as e:
                        logger.error(f"[二维码] 检测失败（忽略此图片）：{e}")
                        has_qr = False

                    if has_qr:
                        if hasattr(event, "mark_action"):
                            event.mark_action("敏感词插件 - 二维码撤回")
                        await self.try_recall(event, message_id, group_id, sender_id)
                        logger.info(f"[二维码] 检测到二维码图片，已撤回 user={sender_id}")
                        return

        # 8. 号码检测
        if self.recall_numbers:
            clean_msg = re.sub(r"\[At:\d+\]", "", message_str)
            clean_msg = re.sub(r"@\S+\(\d+\)", "", clean_msg)
            clean_msg = clean_msg.strip()
            match = re.search(r"\d{6,}", clean_msg)
            if match:
                await self.try_recall(event, message_id, group_id, sender_id)
                logger.info(f"检测到连续数字，已撤回 {sender_id} 的消息: {message_str}")
                return

        # 9. 刷屏检测
        now = time.time()
        key = (group_id, sender_id)
        self.user_message_times[key].append(now)
        self.user_message_ids[key].append(message_id)

        if len(self.user_message_times[key]) == self.spam_count:
            if now - self.user_message_times[key][0] <= self.spam_interval:
                await event.bot.set_group_ban(group_id=int(group_id), user_id=int(sender_id), duration=self.spam_ban_duration)
                for msg_id in self.user_message_ids[key]:
                    try:
                        await event.bot.delete_msg(message_id=msg_id)
                    except Exception as e:
                        logger.error(f"刷屏批量撤回失败: {e}")
                self.user_message_times[key].clear()
                self.user_message_ids[key].clear()

    async def try_recall(self, event: AstrMessageEvent, message_id: str, group_id: int, sender_id: int):
        try:
            await event.bot.delete_msg(message_id=message_id)
        except Exception as e:
            try:
                member_info = await event.bot.get_group_member_info(group_id=int(group_id), user_id=int(sender_id))
                role = member_info.get('role', 'member')
                if role == 'owner':
                    logger.error(f"撤回失败: 对方是群主({sender_id})，无权限撤回。")
                elif role == 'admin':
                    logger.error(f"撤回失败: 对方是管理员({sender_id})，无权限撤回。")
                else:
                    logger.error(f"撤回失败: {e}（用户角色: {role}）")
            except Exception as ex:
                logger.error(f"撤回失败且查询用户角色失败: {e} / 查询错误: {ex}")

    async def handle_check_common_groups(self, event: AstrMessageEvent):
        group_id = event.get_group_id()
        msg = event.message_str.strip()

        m = re.search(r"^查共群\s+(\d{5,12})$", msg)
        if not m:
            resp = await event.bot.send_group_msg(group_id=int(group_id), message="用法：查共群 <QQ号>（例如：查共群 123123）")
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"]))
            return

        uin = m.group(1)
        base_url = f"https://ti.qq.com/friends/recall?uin={uin}"
        qr_api = "https://api.qrserver.com/v1/create-qr-code/"
        params = f"size=360x360&margin=0&data={urllib.parse.quote_plus(base_url)}"
        qr_url = f"{qr_api}?{params}"

        message_segments = [
            {"type": "text", "data": {"text": f"扫描以下二维码查询『{uin}』与你的共同群（60秒后自动撤回）\n"}},
            {"type": "image", "data": {"file": qr_url}},
        ]

        try:
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 查共群")

            resp = await event.bot.send_group_msg(group_id=int(group_id), message=message_segments)
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"]))
        except Exception as e:
            logger.error(f"发送二维码失败，退回文本方式: {e}")
            resp = await event.bot.send_group_msg(
                group_id=int(group_id),
                message=f"扫描以下二维码查询『{uin}』与你的共同群（120秒后自动撤回）：\n{base_url}"
            )
            if isinstance(resp, dict) and "message_id" in resp:
                asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"]))

    async def handle_commands(self, event: AstrMessageEvent):
        msg = event.message_str.strip()
        group_id = event.get_group_id()
        sender_id = event.get_sender_id()

        if not await self._is_operator(event, int(group_id), int(sender_id)):
            try:
                resp = await event.bot.send_group_msg(group_id=int(group_id), message="你配指挥我吗？")
                if isinstance(resp, dict) and "message_id" in resp:
                    asyncio.create_task(self._auto_delete_after(event.bot, resp["message_id"], delay=10))
            except Exception as e:
                logger.error(f"发送无权限提示失败: {e}")
            return

        # ====== 不需要@对象的群级指令 ======
        if msg.startswith("全体禁言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 全体禁言")
            try:
                await event.bot.set_group_whole_ban(group_id=int(group_id), enable=True)
                await event.bot.send_group_msg(group_id=int(group_id), message="已开启全体禁言")
            except Exception as e:
                logger.error(f"开启全体禁言失败: {e}")
            return

        if msg.startswith("全体解言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 全体解言")
            try:
                await event.bot.set_group_whole_ban(group_id=int(group_id), enable=False)
                await event.bot.send_group_msg(group_id=int(group_id), message="已关闭全体禁言")
            except Exception as e:
                logger.error(f"关闭全体禁言失败: {e}")
            return

        # ====== 需要@对象的指令 ======
        at_list = []
        for segment in getattr(event.message_obj, 'message', []):
            if getattr(segment, 'type', '') == 'At':
                at_list.append(getattr(segment, 'qq', None))

        if not at_list:
            logger.error("未检测到 @目标用户，无法执行该命令")
            return

        target_id = str(at_list[0])
        logger.info(f"检测到命令针对@{target_id}")

        if msg.startswith("禁言"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 禁言")
            duration_match = re.search(r"禁言.*?(\d+)?$", msg)
            duration = int(duration_match.group(1)) * 60 if duration_match and duration_match.group(1) else 600
            await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=duration)
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已禁言 {target_id} {duration//60}分钟")

        elif msg.startswith(("解禁", "解言")):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解禁")
            await event.bot.set_group_ban(group_id=int(group_id), user_id=int(target_id), duration=0)
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已解除 {target_id} 禁言")

        elif msg.startswith("踢黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢黑")
            self.kick_black_list.add(target_id)
            self.save_json_data()
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id), reject_add_request=True)
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已加入踢黑名单并踢出")

        elif msg.startswith("解黑"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解黑")
            self.kick_black_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移出踢黑名单")

        elif msg.startswith("踢"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 踢")
            await event.bot.set_group_kick(group_id=int(group_id), user_id=int(target_id))
            await event.bot.send_group_msg(group_id=int(group_id), message=f"已踢出 {target_id}")

        elif msg.startswith("针对"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 针对")
            self.target_user_list.add(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已加入针对名单")

        elif msg.startswith("解针对"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 解针对")
            self.target_user_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移出针对名单")

        elif msg.startswith("设置管理员"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 设置管理员")
            self.sub_admin_list.add(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已设为子管理员")

        elif msg.startswith("移除管理员"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 移除管理员")
            self.sub_admin_list.discard(target_id)
            self.save_json_data()
            await event.bot.send_group_msg(group_id=int(group_id), message=f"{target_id} 已移除子管理员")

        elif msg.startswith("撤回"):
            if hasattr(event, "mark_action"):
                event.mark_action("敏感词插件 - 撤回")
            count_match = re.search(r"撤回.*?(\d+)?$", msg)
            recall_count = int(count_match.group(1)) if count_match and count_match.group(1) else 5

            history = await event.bot.get_group_msg_history(group_id=int(group_id), count=100)
            deleted = 0
            for msg_data in reversed(history.get('messages', [])):
                if deleted >= recall_count:
                    break
                if str(msg_data.get('sender', {}).get('user_id')) == target_id:
                    try:
                        await event.bot.delete_msg(message_id=msg_data['message_id'])
                        deleted += 1
                    except Exception as e:
                        logger.error(f"撤回 {target_id} 消息 {msg_data.get('message_id')} 失败: {e}")

            await event.bot.send_group_msg(group_id=int(group_id), message=f"已撤回 {target_id} 的 {deleted} 条消息")

    async def terminate(self):
        logger.info("AutoRecallKeywordPlugin 插件已被卸载。")
