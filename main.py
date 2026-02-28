"""
PrincessDainaBot — ready-to-use Telegram group management bot
Works with python-telegram-bot v21+ (async)

Features
- /start /help /about /privacy
- Admin-only: /ban /unban /kick /mute /unmute /warn /warns /resetwarns
- Protection: /antilink /antispam /lock /unlock
- Welcome/Goodbye: /setwelcome /setgoodbye
- Filters: /filter /stop /filters
- Rules: /setrules /rules
- Utilities: /admins /pin /unpin

Storage: SQLite (bot.db)

ENV required:
- BOT_TOKEN="123:ABC..."
Optional:
- OWNER_ID="123456789"   (your Telegram user id; gets bypass permissions)
"""

import os
import re
import time
import sqlite3
from collections import defaultdict, deque
from typing import Optional

import httpx
from urllib.parse import quote_plus

from telegram import Update, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode, ChatMemberStatus
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ChatMemberHandler,
    ContextTypes,
    filters,
)



from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import CallbackQueryHandler


# ---------------------------
# Config
# ---------------------------
DB_PATH = os.getenv("DB_PATH", "bot.db")

# Anti-spam defaults (can be toggled per chat with /antispam)
SPAM_WINDOW_SECONDS = 6
SPAM_MAX_MSGS = 6

LINK_RE = re.compile(
    r"(?i)\b("
    r"(?:https?://|www\.)\S+"
    r"|t\.me/\S+"
    r"|telegram\.me/\S+"
    r"|(?:\S+\.)+(?:com|in|net|org|io|me|app|xyz|co)\b\S*"
    r")"
)

MENTION_RE = re.compile(r"@\w{4,}")
CODEBLOCK_SAFE = re.compile(r"```.*?```", re.DOTALL)

# In-memory anti-spam tracker: chat_id -> user_id -> deque[timestamps]
spam_tracker = defaultdict(lambda: defaultdict(lambda: deque(maxlen=SPAM_MAX_MSGS + 3)))


# ---------------------------
# DB helpers
# ---------------------------
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id INTEGER PRIMARY KEY,
                antilink INTEGER DEFAULT 0,
                antispam INTEGER DEFAULT 0,
                welcome TEXT,
                goodbye TEXT,
                rules TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS warns (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                count INTEGER DEFAULT 0,
                PRIMARY KEY (chat_id, user_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS filters (
                chat_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                reply TEXT NOT NULL,
                PRIMARY KEY (chat_id, key)
            )
            """
        )


def get_setting(chat_id: int, key: str, default=None):
    with db() as conn:
        row = conn.execute(
            f"SELECT {key} FROM chat_settings WHERE chat_id=?",
            (chat_id,),
        ).fetchone()
        if row is None:
            # ensure row exists
            conn.execute("INSERT OR IGNORE INTO chat_settings(chat_id) VALUES (?)", (chat_id,))
            return default
        return row[0] if row[0] is not None else default


def set_setting(chat_id: int, key: str, value) -> None:
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO chat_settings(chat_id) VALUES (?)", (chat_id,))
        conn.execute(f"UPDATE chat_settings SET {key}=? WHERE chat_id=?", (value, chat_id))


def get_warns(chat_id: int, user_id: int) -> int:
    with db() as conn:
        row = conn.execute(
            "SELECT count FROM warns WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        ).fetchone()
        return int(row[0]) if row else 0


def set_warns(chat_id: int, user_id: int, count: int) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO warns(chat_id, user_id, count) VALUES (?,?,?) "
            "ON CONFLICT(chat_id, user_id) DO UPDATE SET count=excluded.count",
            (chat_id, user_id, count),
        )


def reset_warns(chat_id: int, user_id: int) -> None:
    with db() as conn:
        conn.execute("DELETE FROM warns WHERE chat_id=? AND user_id=?", (chat_id, user_id))


def add_filter(chat_id: int, key: str, reply: str) -> None:
    key = key.strip().lower()
    with db() as conn:
        conn.execute(
            "INSERT INTO filters(chat_id, key, reply) VALUES (?,?,?) "
            "ON CONFLICT(chat_id, key) DO UPDATE SET reply=excluded.reply",
            (chat_id, key, reply),
        )


def remove_filter(chat_id: int, key: str) -> bool:
    key = key.strip().lower()
    with db() as conn:
        cur = conn.execute("DELETE FROM filters WHERE chat_id=? AND key=?", (chat_id, key))
        return cur.rowcount > 0


def list_filters(chat_id: int):
    with db() as conn:
        rows = conn.execute("SELECT key FROM filters WHERE chat_id=? ORDER BY key ASC", (chat_id,)).fetchall()
        return [r[0] for r in rows]


def match_filter(chat_id: int, text: str) -> Optional[str]:
    # Match filter keys as whole words or exact lower substring (simple + reliable)
    if not text:
        return None
    t = text.lower()
    with db() as conn:
        rows = conn.execute("SELECT key, reply FROM filters WHERE chat_id=?", (chat_id,)).fetchall()
    for k, reply in rows:
        k = k.lower()
        # whole word match OR exact trigger (for short keys)
        if re.search(rf"(?i)\b{re.escape(k)}\b", t) or t.strip() == k:
            return reply
    return None


# ---------------------------
# Permission helpers
# ---------------------------
def owner_id() -> Optional[int]:
    v = os.getenv("OWNER_ID", "").strip()
    return int(v) if v.isdigit() else None


async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    oid = owner_id()
    chat = update.effective_chat
    msg = update.effective_message
    user = update.effective_user

    # Must be group/supergroup
    if not chat or chat.type not in ("group", "supergroup"):
        return False

    # ✅ 1) Anonymous admin (or "send as group") — sender_chat is the group itself
    if msg and msg.sender_chat and msg.sender_chat.id == chat.id:
        return True

    # ✅ 2) Sent as a linked channel (sender_chat exists)
    if msg and msg.sender_chat:
        try:
            member = await context.bot.get_chat_member(chat.id, msg.sender_chat.id)
            if member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER):
                return True
        except Exception:
            pass

    # ✅ 3) Owner bypass (only if user exists)
    if oid and user and user.id == oid:
        return True

    # ✅ 4) Normal admin check
    if user:
        try:
            member = await context.bot.get_chat_member(chat.id, user.id)
            return member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)
        except Exception:
            return False

    return False




async def require_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if await is_admin(update, context):
        return True
    if update.effective_message:
        await update.effective_message.reply_text("⛔ Access Denied\nOnly group admins can use this command.")
    return False


def parse_target_from_reply(update: Update) -> Optional[int]:
    msg = update.effective_message
    if msg and msg.reply_to_message and msg.reply_to_message.from_user:
        return msg.reply_to_message.from_user.id
    return None


def parse_target_from_args(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Optional[int]:
    # Accept @username OR numeric id
    if not context.args:
        return None
    arg = context.args[0].strip()
    if arg.isdigit():
        return int(arg)
    # If @username provided, Telegram API needs user_id; we cannot resolve reliably without extra steps.
    return None


async def get_target_user_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Optional[int]:
    uid = parse_target_from_reply(update)
    if uid:
        return uid
    uid = parse_target_from_args(update, context)
    if uid:
        return uid
    return None


# ---------------------------
# Basic commands
# ---------------------------
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "👑 *Princess Daina Bot*\n"
        "Your smart & elegant Telegram group assistant.\n\n"
        "Use /help to see commands.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "👑 *Princess Daina Bot — Commands*\n\n"
        "*Basic*\n"
        "/start - Start the bot\n"
        "/help - Show help\n"
        "/about - About the bot\n"
        "/privacy - Privacy policy\n\n"
        "*Admin & Moderation*\n"
        "/ban, /unban, /kick\n"
        "/mute, /unmute\n"
        "/warn, /warns, /resetwarns\n\n"
        "*Protection*\n"
        "/antilink - Toggle link blocking\n"
        "/antispam - Toggle spam protection\n"
        "/lock, /unlock - Lock/unlock chat\n\n"
        "*Messages & Filters*\n"
        "/setwelcome, /setgoodbye\n"
        "/filter <key> <reply>\n"
        "/stop <key>\n"
        "/filters\n\n"
        "*Rules & Utilities*\n"
        "/setrules, /rules\n"
        "/admins\n"
        "/pin, /unpin (reply to a message)\n"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


async def about_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "👑 *Princess Daina Bot*\n"
        "Smart • Secure • Simple\n"
        "Built to keep Telegram communities clean & friendly.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def privacy_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "🔐 *Privacy Policy*\n\n"
        "• Uses minimal data needed for moderation (user/chat IDs, moderation context).\n"
        "• Does not read private chats.\n"
        "• Does not sell or share data.\n"
        "• Data is stored only to provide features (warnings, settings, filters).\n\n"
        "By using the bot, you agree to this policy.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def ping_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text("🏓 Pong! Bot is alive ✅")


async def id_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    chat = update.effective_chat

    await update.effective_message.reply_text(
        f"👤 User ID: `{user.id}`\n"
        f"💬 Chat ID: `{chat.id}`",
        parse_mode=ParseMode.MARKDOWN,
    )


async def debug_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    user = update.effective_user
    msg = update.effective_message

    await update.effective_message.reply_text(
        f"chat_id = {chat.id}\n"
        f"user_id = {user.id if user else 'None'}\n"
        f"sender_chat_id = {msg.sender_chat.id if msg and msg.sender_chat else 'None'}"
    )


async def movie_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.effective_message.reply_text("🎬 Usage: /movie <movie name>\nExample: /movie interstellar")
        return

    api_key = os.getenv("TMDB_API_KEY", "").strip()
    if not api_key:
        await update.effective_message.reply_text("❌ TMDB_API_KEY is missing in Railway Variables.")
        return

    query = " ".join(context.args).strip()
    url = f"https://api.themoviedb.org/3/search/movie?api_key={api_key}&query={quote_plus(query)}&include_adult=false&language=en-US&page=1"

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        await update.effective_message.reply_text(f"❌ TMDb error: {e}")
        return

    results = data.get("results") or []
    if not results:
        await update.effective_message.reply_text("😕 No results found. Try a different name.")
        return

    m = results[0]
    title = m.get("title") or "Unknown"
    year = (m.get("release_date") or "")[:4] or "—"
    rating = m.get("vote_average")
    rating_txt = f"{rating:.1f}/10" if isinstance(rating, (int, float)) else "—"
    overview = (m.get("overview") or "No description available.").strip()
    if len(overview) > 900:
        overview = overview[:900] + "…"

    movie_id = m.get("id")
    tmdb_link = f"https://www.themoviedb.org/movie/{movie_id}" if movie_id else "https://www.themoviedb.org/"
    trailer_search = f"https://www.youtube.com/results?search_query={quote_plus(title + ' trailer')}"

    caption = (
        f"🎬 *{title}* ({year})\n"
        f"⭐ Rating: *{rating_txt}*\n\n"
        f"{overview}\n\n"
        f"_Data from TMDb_"
    )

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("TMDb", url=tmdb_link),
         InlineKeyboardButton("Trailer", url=trailer_search)]
    ])

    poster_path = m.get("poster_path")
    if poster_path:
        poster_url = f"https://image.tmdb.org/t/p/w500{poster_path}"
        try:
            await context.bot.send_photo(
                chat_id=update.effective_chat.id,
                photo=poster_url,
                caption=caption,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=keyboard,
            )
            return
        except Exception:
            pass

    await update.effective_message.reply_text(caption, parse_mode=ParseMode.MARKDOWN, reply_markup=keyboard)


# ---------------------------
# Rules button (inline)
# ---------------------------

RULES_CB = "pd_rules"

async def rulesbutton_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("📌 View Rules", callback_data=RULES_CB)]
    ])
    await update.effective_message.reply_text(
        "Tap the button below to view group rules 👇",
        reply_markup=keyboard
    )

async def rules_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    chat_id = query.message.chat.id
    rules = get_setting(chat_id, "rules", None)

    if not rules:
        await query.message.reply_text("📜 No rules set yet. Admins can set them using /setrules")
        return

    await query.message.reply_text(
        f"📜 *Group Rules*\n\n{rules}",
        parse_mode=ParseMode.MARKDOWN
    )


# ---------------------------
# Moderation commands
# ---------------------------
async def ban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    target = await get_target_user_id(update, context)
    if not target:
        await update.effective_message.reply_text("⚠️ Reply to a user (or pass numeric user_id) to ban.")
        return
    try:
        await context.bot.ban_chat_member(update.effective_chat.id, target)
        await update.effective_message.reply_text("🔨 User banned successfully.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to ban: {e}")


async def unban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    target = await get_target_user_id(update, context)
    if not target:
        await update.effective_message.reply_text("⚠️ Reply to a user (or pass numeric user_id) to unban.")
        return
    try:
        await context.bot.unban_chat_member(update.effective_chat.id, target)
        await update.effective_message.reply_text("✅ User unbanned successfully.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to unban: {e}")


async def kick_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    target = await get_target_user_id(update, context)
    if not target:
        await update.effective_message.reply_text("⚠️ Reply to a user (or pass numeric user_id) to kick.")
        return
    try:
        await context.bot.ban_chat_member(update.effective_chat.id, target)
        await context.bot.unban_chat_member(update.effective_chat.id, target)
        await update.effective_message.reply_text("🧹 User removed from the group.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to kick: {e}")


async def mute_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    target = await get_target_user_id(update, context)
    if not target:
        await update.effective_message.reply_text("⚠️ Reply to a user (or pass numeric user_id) to mute.")
        return

    # Optional: /mute 10m or /mute 1h  (we'll parse but default to forever)
    until_date = None
    try:
        if len(context.args) >= 1:
            # If first arg is numeric user_id, duration could be second arg.
            # If reply-based, duration can be first arg.
            dur = context.args[1] if (context.args and context.args[0].isdigit() and len(context.args) >= 2) else (
                context.args[0] if context.args else None
            )
            if dur:
                m = re.fullmatch(r"(\d+)([smhd])", dur.lower())
                if m:
                    n = int(m.group(1))
                    unit = m.group(2)
                    seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
                    until_date = int(time.time()) + seconds
    except Exception:
        until_date = None

    try:
        perms = ChatPermissions(can_send_messages=False)
        await context.bot.restrict_chat_member(
            update.effective_chat.id,
            target,
            permissions=perms,
            until_date=until_date,
        )
        await update.effective_message.reply_text("🔇 User muted.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to mute: {e}")


async def unmute_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    target = await get_target_user_id(update, context)
    if not target:
        await update.effective_message.reply_text("⚠️ Reply to a user (or pass numeric user_id) to unmute.")
        return
    try:
        perms = ChatPermissions(
            can_send_messages=True,
            can_send_polls=True,
            can_send_other_messages=True,
            can_add_web_page_previews=True,
            can_change_info=False,
            can_invite_users=True,
            can_pin_messages=False,
        )
        await context.bot.restrict_chat_member(update.effective_chat.id, target, permissions=perms)
        await update.effective_message.reply_text("🔊 User unmuted.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to unmute: {e}")


async def warn_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    target = await get_target_user_id(update, context)
    if not target:
        await update.effective_message.reply_text("⚠️ Reply to a user (or pass numeric user_id) to warn.")
        return

    chat_id = update.effective_chat.id
    count = get_warns(chat_id, target) + 1
    set_warns(chat_id, target, count)

    # Auto action at 3 warns: mute for 1 day
    if count >= 3:
        try:
            perms = ChatPermissions(can_send_messages=False)
            await context.bot.restrict_chat_member(chat_id, target, permissions=perms, until_date=int(time.time()) + 86400)
            await update.effective_message.reply_text(
                f"⚠️ Warning issued: *{count}/3*\n"
                f"🔇 Reached 3 warnings — user muted for 24h.",
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as e:
            await update.effective_message.reply_text(
                f"⚠️ Warning issued: {count}/3\n❌ Auto-mute failed: {e}"
            )
    else:
        await update.effective_message.reply_text(
            f"⚠️ Warning issued.\nCurrent warnings: *{count}/3*",
            parse_mode=ParseMode.MARKDOWN,
        )


async def warns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    target = await get_target_user_id(update, context)
    if not target:
        # If used as reply, good; otherwise show sender's warns
        target = update.effective_user.id

    count = get_warns(chat_id, target)
    await update.effective_message.reply_text(f"⚠️ Warnings: *{count}/3*", parse_mode=ParseMode.MARKDOWN)


async def resetwarns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    target = await get_target_user_id(update, context)
    if not target:
        await update.effective_message.reply_text("⚠️ Reply to a user (or pass numeric user_id) to reset warnings.")
        return
    reset_warns(update.effective_chat.id, target)
    await update.effective_message.reply_text("✅ Warnings reset.")


# ---------------------------
# Protection commands
# ---------------------------
async def antilink_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    chat_id = update.effective_chat.id
    cur = int(get_setting(chat_id, "antilink", 0) or 0)
    new = 0 if cur else 1
    set_setting(chat_id, "antilink", new)
    await update.effective_message.reply_text(f"🛑 Anti-link {'enabled' if new else 'disabled'}.")


async def antispam_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    chat_id = update.effective_chat.id
    cur = int(get_setting(chat_id, "antispam", 0) or 0)
    new = 0 if cur else 1
    set_setting(chat_id, "antispam", new)
    await update.effective_message.reply_text(f"🛡️ Anti-spam {'enabled' if new else 'disabled'}.")


async def lock_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    try:
        perms = ChatPermissions(
            can_send_messages=False,
            can_send_polls=False,
            can_send_other_messages=False,
            can_add_web_page_previews=False,
            can_invite_users=False,
        )
        await context.bot.set_chat_permissions(update.effective_chat.id, perms)
        await update.effective_message.reply_text("🔒 Chat locked. Only admins can talk.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to lock: {e}")


async def unlock_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    try:
        perms = ChatPermissions(
            can_send_messages=True,
            can_send_polls=True,
            can_send_other_messages=True,
            can_add_web_page_previews=True,
            can_invite_users=True,
        )
        await context.bot.set_chat_permissions(update.effective_chat.id, perms)
        await update.effective_message.reply_text("🔓 Chat unlocked.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to unlock: {e}")


# ---------------------------
# Welcome/Goodbye + Rules
# ---------------------------
async def setwelcome_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    chat_id = update.effective_chat.id
    text = update.effective_message.text or ""
    parts = text.split(None, 1)
    if len(parts) < 2:
        await update.effective_message.reply_text(
            "Usage:\n/setwelcome Welcome {name}! 🎉\n\n"
            "Placeholders: {name} {mention} {id} {chat}"
        )
        return
    set_setting(chat_id, "welcome", parts[1].strip())
    await update.effective_message.reply_text("🎉 Welcome message updated successfully.")


async def setgoodbye_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    chat_id = update.effective_chat.id
    text = update.effective_message.text or ""
    parts = text.split(None, 1)
    if len(parts) < 2:
        await update.effective_message.reply_text(
            "Usage:\n/setgoodbye Goodbye {name}! 👋\n\n"
            "Placeholders: {name} {mention} {id} {chat}"
        )
        return
    set_setting(chat_id, "goodbye", parts[1].strip())
    await update.effective_message.reply_text("👋 Goodbye message updated successfully.")


async def setrules_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    chat_id = update.effective_chat.id
    text = update.effective_message.text or ""
    parts = text.split(None, 1)
    if len(parts) < 2:
        await update.effective_message.reply_text("Usage:\n/setrules 1) Be respectful\n2) No spam\n3) No links")
        return
    set_setting(chat_id, "rules", parts[1].strip())
    await update.effective_message.reply_text("📜 Group rules updated.")


async def rules_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    rules = get_setting(update.effective_chat.id, "rules", None)
    if not rules:
        await update.effective_message.reply_text("📜 No rules set yet. Admins can set with /setrules")
        return
    await update.effective_message.reply_text(f"📜 *Group Rules*\n\n{rules}", parse_mode=ParseMode.MARKDOWN)


# ---------------------------
# Filters
# ---------------------------
async def filter_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    text = update.effective_message.text or ""
    parts = text.split(None, 2)
    if len(parts) < 3:
        await update.effective_message.reply_text("Usage:\n/filter hello Hi! 😊\n/filter price Contact admin for pricing.")
        return
    key = parts[1].strip()
    reply = parts[2].strip()
    add_filter(update.effective_chat.id, key, reply)
    await update.effective_message.reply_text(f"✅ Filter saved for: *{key}*", parse_mode=ParseMode.MARKDOWN)


async def stop_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    if not context.args:
        await update.effective_message.reply_text("Usage:\n/stop <key>")
        return
    key = context.args[0].strip()
    ok = remove_filter(update.effective_chat.id, key)
    await update.effective_message.reply_text("✅ Filter removed." if ok else "ℹ️ No such filter found.")


async def filters_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keys = list_filters(update.effective_chat.id)
    if not keys:
        await update.effective_message.reply_text("ℹ️ No filters set.")
        return
    await update.effective_message.reply_text("🧠 *Active Filters*\n" + "\n".join(f"• `{k}`" for k in keys),
                                             parse_mode=ParseMode.MARKDOWN)


# ---------------------------
# Utilities
# ---------------------------
async def admins_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        admins = await context.bot.get_chat_administrators(update.effective_chat.id)
        names = []
        for a in admins:
            u = a.user
            if u.username:
                names.append(f"• @{u.username}")
            else:
                names.append(f"• {u.first_name}")
        await update.effective_message.reply_text("👮 *Admins*\n" + "\n".join(names), parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed: {e}")


async def pin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    if not update.effective_message.reply_to_message:
        await update.effective_message.reply_text("⚠️ Reply to a message to pin it.")
        return
    try:
        await context.bot.pin_chat_message(
            update.effective_chat.id,
            update.effective_message.reply_to_message.message_id,
            disable_notification=True,
        )
        await update.effective_message.reply_text("📌 Pinned.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to pin: {e}")


async def unpin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await require_admin(update, context):
        return
    try:
        await context.bot.unpin_chat_message(update.effective_chat.id)
        await update.effective_message.reply_text("📍 Unpinned.")
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Failed to unpin: {e}")


# ---------------------------
# Moderation engines (antilink + antispam + filter replies)
# ---------------------------
async def moderate_messages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.effective_chat or update.effective_chat.type not in ("group", "supergroup"):
        return
    msg = update.effective_message
    if not msg or not msg.text:
        return

    chat_id = update.effective_chat.id
    user = update.effective_user
    user_id = user.id if user else 0

    # Skip admin moderation (optional)
    if user and await is_admin(update, context):
        # Still allow filters for admins? Usually yes; but we can skip moderation only.
        pass

    text = msg.text

    # 1) Filters auto reply (doesn't delete)
    reply = match_filter(chat_id, text)
    if reply:
        await msg.reply_text(reply)
        # continue; allow other moderation too if desired

    # 2) Anti-link
    antilink = int(get_setting(chat_id, "antilink", 0) or 0)
    if antilink:
        # ignore code blocks for false positives
        scrub = CODEBLOCK_SAFE.sub("", text)
        if LINK_RE.search(scrub):
            # if sender is admin, skip deletion
            if user and await is_admin(update, context):
                return
            try:
                await msg.delete()
            except Exception:
                pass
            try:
                await msg.chat.send_message(
                    f"🛑 Links are not allowed here.\n"
                    f"User: {user.mention_html() if user else 'Unknown'}",
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
            return

    # 3) Anti-spam (simple)
    antispam = int(get_setting(chat_id, "antispam", 0) or 0)
    if antispam:
        if user and await is_admin(update, context):
            return

        now = time.time()
        dq = spam_tracker[chat_id][user_id]
        dq.append(now)

        # Count messages within window
        recent = [t for t in dq if now - t <= SPAM_WINDOW_SECONDS]
        if len(recent) >= SPAM_MAX_MSGS:
            # Delete spammy message
            try:
                await msg.delete()
            except Exception:
                pass
            # Warn user (soft)
            try:
                await msg.chat.send_message(
                    f"🛡️ Please slow down, {user.mention_html() if user else 'user'}.\n"
                    "Spamming is not allowed.",
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass


# ---------------------------
# Welcome / Goodbye handler
# ---------------------------
def render_template(template: str, user, chat) -> str:
    name = (user.full_name if user else "there")
    mention = (user.mention_html() if user else "there")
    uid = (str(user.id) if user else "0")
    chatname = (chat.title if chat else "this chat")
    out = template.replace("{name}", name)
    out = out.replace("{mention}", mention)
    out = out.replace("{id}", uid)
    out = out.replace("{chat}", chatname)
    return out


async def chat_member_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Fires on join/leave when using ChatMemberHandler
    if not update.chat_member:
        return
    chat = update.chat_member.chat
    new = update.chat_member.new_chat_member
    old = update.chat_member.old_chat_member

    user = new.user if new else None

    # Joined
    if old and new and old.status in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED) and new.status in (
        ChatMemberStatus.MEMBER,
        ChatMemberStatus.RESTRICTED,
    ):
        tpl = get_setting(chat.id, "welcome", None)
        if tpl:
            try:
                await context.bot.send_message(
                    chat.id,
                    render_template(tpl, user, chat),
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass

    # Left / kicked
    if old and new and old.status in (ChatMemberStatus.MEMBER, ChatMemberStatus.RESTRICTED) and new.status in (
        ChatMemberStatus.LEFT,
        ChatMemberStatus.KICKED,
    ):
        tpl = get_setting(chat.id, "goodbye", None)
        if tpl:
            try:
                await context.bot.send_message(
                    chat.id,
                    render_template(tpl, user, chat),
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass


# ---------------------------
# Main
# ---------------------------
def main():
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("BOT_TOKEN env var is missing.")

    print("BOT_TOKEN length:", len(token))
    print("BOT_TOKEN prefix:", token.split(":")[0])

    init_db()
    app = Application.builder().token(token).build()

    # Basic
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("about", about_cmd))
    app.add_handler(CommandHandler("privacy", privacy_cmd))
    app.add_handler(CommandHandler("ping", ping_cmd))
    app.add_handler(CommandHandler("id", id_cmd))
    app.add_handler(CommandHandler("debug", debug_cmd))
    app.add_handler(CommandHandler("rulesbutton", rulesbutton_cmd))
    app.add_handler(CallbackQueryHandler(rules_callback, pattern=f"^{RULES_CB}$"))
    app.add_handler(CommandHandler("movie", movie_cmd))

    




    # Moderation
    app.add_handler(CommandHandler("ban", ban_cmd))
    app.add_handler(CommandHandler("unban", unban_cmd))
    app.add_handler(CommandHandler("kick", kick_cmd))
    app.add_handler(CommandHandler("mute", mute_cmd))
    app.add_handler(CommandHandler("unmute", unmute_cmd))
    app.add_handler(CommandHandler("warn", warn_cmd))
    app.add_handler(CommandHandler("warns", warns_cmd))
    app.add_handler(CommandHandler("resetwarns", resetwarns_cmd))

    # Protection
    app.add_handler(CommandHandler("antilink", antilink_cmd))
    app.add_handler(CommandHandler("antispam", antispam_cmd))
    app.add_handler(CommandHandler("lock", lock_cmd))
    app.add_handler(CommandHandler("unlock", unlock_cmd))

    # Welcome/Goodbye + Rules
    app.add_handler(CommandHandler("setwelcome", setwelcome_cmd))
    app.add_handler(CommandHandler("setgoodbye", setgoodbye_cmd))
    app.add_handler(CommandHandler("setrules", setrules_cmd))
    app.add_handler(CommandHandler("rules", rules_cmd))

    # Filters
    app.add_handler(CommandHandler("filter", filter_cmd))
    app.add_handler(CommandHandler("stop", stop_cmd))
    app.add_handler(CommandHandler("filters", filters_cmd))

    # Utilities
    app.add_handler(CommandHandler("admins", admins_cmd))
    app.add_handler(CommandHandler("pin", pin_cmd))
    app.add_handler(CommandHandler("unpin", unpin_cmd))

    # Message moderation (antilink/antispam + filter replies)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, moderate_messages))

    # Join/Leave
    app.add_handler(ChatMemberHandler(chat_member_update, ChatMemberHandler.CHAT_MEMBER))

    print("PrincessDainaBot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()













