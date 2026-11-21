"""Radar de tokens promocionados en DexScreener. Requiere Python 3.11+."""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from http.client import HTTPException
from io import BytesIO
import json
import logging
import math
import os
from pathlib import Path
import re
import subprocess
import statistics
import time
import requests
from PIL import Image, ImageChops, ImageDraw, ImageFont, ImageOps, ImageFilter
from urllib.parse import urlsplit, parse_qsl, urlencode
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

DEX = "https://api.dexscreener.com"
STATE = Path(__file__).resolve().with_name("sent_tokens.json")
CHAINS = {"solana": "Solana", "base": "Base"}
MAX_ALERTS = 3
MAX_AUDITS = 12
MIN_SCORE = 60
BASE_FLAGS = (
    "is_honeypot", "is_blacklisted", "transfer_pausable",
    "owner_change_balance", "can_take_back_ownership", "is_mintable",
)
BASE_OPTIONAL_FLAGS = ("cannot_sell_all", "cannot_buy", "is_proxy", "hidden_owner")
CRITICAL_NAMES = ("mint authority", "mintable", "freeze authority", "honeypot")
LOG = logging.getLogger("radar")


class RadarError(RuntimeError):
    pass


class ApiError(RadarError):
    def __init__(self, service, reason, *, retryable=False):
        super().__init__(f"{service}: {reason}")
        self.retryable = retryable


class TelegramRejected(RadarError):
    """Telegram confirmó que rechazó la publicación."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Bloquea redirecciones de API, en especial las de la URL con el token del bot.
HTTP = build_opener(NoRedirect())


def obj(value):
    return value if isinstance(value, dict) else {}


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        result = float(value)
    except (ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def address(chain, value):
    if not isinstance(value, str):
        return None
    if chain == "solana" and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", value):
        return value
    if chain == "base" and re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        return value.lower()
    return None


def request_json(service, url, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=body, headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "memecoin-radar/1.0",
    })
    attempts = 2 if payload is None else 1
    for attempt in range(attempts):
        try:
            with HTTP.open(request, timeout=7) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ApiError(service, "respuesta demasiado grande")
            return json.loads(raw)
        except HTTPError as error:
            with error:
                status = error.code
            if payload is not None and status in {400, 401, 403, 404, 429}:
                raise TelegramRejected(f"Telegram rechazó el envío (HTTP {status})") from None
            failure = ApiError(service, f"HTTP {status}", retryable=status == 429 or status >= 500)
        except (URLError, OSError, ValueError, HTTPException) as error:
            # La excepción original puede contener la URL y el secreto de Telegram.
            failure = ApiError(service, f"fallo de respuesta ({type(error).__name__})",
                               retryable=not isinstance(error, ValueError))
        if not failure.retryable or attempt + 1 == attempts:
            raise failure
        time.sleep(1)


@dataclass(frozen=True)
class Candidate:
    chain: str
    mint: str
    pair: str
    name: str
    symbol: str
    liquidity: float
    volume_1h: float
    volume_5m: float | None
    buys: float
    sells: float
    fdv: float | None
    market_cap: float | None
    change_5m: float | None
    change_1h: float | None
    created_at: float
    logo_url: str = ''
    website_url: str = ''
    telegram_url: str = ''
    x_url: str = ''
    price_usd: float | None = None

    @property
    def key(self):
        return f"{self.chain}:{self.mint}"

    @property
    def age_minutes(self):
        return max(0, (time.time() * 1000 - self.created_at) / 60_000)

    @property
    def signal(self):
        recent = self.volume_5m or 0
        # Solo compara periodos completos. Una piscina recién creada sesgaría la base.
        if self.age_minutes >= 60 and 5000 < recent < self.volume_1h:
            multiple = 11 * recent / (self.volume_1h - recent)
            if multiple >= 3:
                return f"5m volume ×{min(multiple, 999):.1f} vs previous pace"
        if recent > 5000 and (self.change_5m or 0) >= 8:
            return f"Price +{self.change_5m:.1f}% in 5 minutes"
        return ""

    @property
    def score(self):
        """Puntuación explicable de 0 a 100 para ordenar el momentum."""
        liquidity_points = min(24, 8 * math.log10(max(1, self.liquidity / 10_000)) + 8)
        volume_points = min(28, 10 * math.log10(max(1, self.volume_1h / 30_000)) + 12)
        buy_ratio = self.buys / max(1, self.buys + self.sells)
        buy_points = min(22, max(0, (buy_ratio - 0.50) * 110))
        velocity = (self.volume_5m or 0) / max(1, self.volume_1h)
        velocity_points = min(16, velocity * 96)
        price = self.change_1h or 0
        price_points = 10 if 5 <= price <= 80 else 6 if 0 < price < 150 else 0
        return round(min(100, liquidity_points + volume_points + buy_points + velocity_points + price_points))


def token_label(value, default, limit):
    if not isinstance(value, str):
        return default
    # Quita saltos, controles y marcas de dirección antes de escapar el HTML.
    cleaned = "".join(char for char in value[:256] if char.isprintable()).strip()
    return cleaned[:limit] or default


def safe_public_url(value, allowed_hosts=None):
    """Accept only short HTTPS links suitable for Telegram inline buttons."""
    if not isinstance(value, str) or len(value) > 500:
        return ""
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return ""
    if allowed_hosts and host not in allowed_hosts:
        return ""
    return value.strip()


def official_links(info):
    """Extract the first official website, Telegram and X links from DexScreener."""
    info = obj(info)
    website = ""
    for item in info.get("websites") if isinstance(info.get("websites"), list) else []:
        website = safe_public_url(obj(item).get("url"))
        if website:
            break
    telegram = x_url = ""
    for item in info.get("socials") if isinstance(info.get("socials"), list) else []:
        item = obj(item)
        social_type = str(item.get("type") or "").lower()
        if social_type == "telegram" and not telegram:
            telegram = safe_public_url(item.get("url"), {"t.me", "telegram.me"})
        elif social_type in {"twitter", "x"} and not x_url:
            x_url = safe_public_url(item.get("url"), {"x.com", "twitter.com"})
    return website, telegram, x_url


def qualify(chain, pair, wanted, now_ms):
    pair = obj(pair)
    base = obj(pair.get("baseToken"))
    mint = address(chain, base.get("address"))
    pool = address(chain, pair.get("pairAddress"))
    created = number(pair.get("pairCreatedAt"))
    if pair.get("chainId") != chain or mint not in wanted or not pool or created is None:
        return None
    if not 300_000 <= now_ms - created <= 86_400_000:
        return None

    liquidity = number(obj(pair.get("liquidity")).get("usd"))
    volume = obj(pair.get("volume"))
    h1, m5 = number(volume.get("h1")), number(volume.get("m5"))
    tx = obj(obj(pair.get("txns")).get("h1"))
    buys, sells = number(tx.get("buys")), number(tx.get("sells"))
    if liquidity is None or liquidity <= 10_000 or h1 is None or h1 < 0:
        return None
    if buys is None or sells is None or not (buys.is_integer() and sells.is_integer()):
        return None
    if not buys > sells >= 0:
        return None

    # h1 incluye los últimos 5 min. Los 55 min anteriores equivalen a 11 ventanas.
    burst = m5 is not None and 5_000 < m5 <= h1 and m5 >= 2 * ((h1 - m5) / 11)
    if h1 <= 30_000 and not burst:
        return None
    change = obj(pair.get("priceChange"))
    info = obj(pair.get("info"))
    website, telegram, x_url = official_links(info)
    return Candidate(
        chain, mint, pool, token_label(base.get("name"), "Token", 80),
        token_label(base.get("symbol"), "?", 24), liquidity, h1, m5, buys, sells,
        number(pair.get("fdv")), number(pair.get("marketCap")),
        number(change.get("m5")), number(change.get("h1")), created,
        info.get("imageUrl") or "", website, telegram, x_url, number(pair.get("priceUsd")),
    )


def discover(chains, history):
    selected = {chain: {} for chain in chains}
    sources = (
        ("boosts recientes", f"{DEX}/token-boosts/latest/v1"),
        ("boosts destacados", f"{DEX}/token-boosts/top/v1"),
        ("perfiles recientes", f"{DEX}/token-profiles/latest/v1"),
    )
    source_failures = 0
    for label, url in sources:
        try:
            rows = request_json("DexScreener", url)
            if not isinstance(rows, list):
                raise RadarError(f"DexScreener: formato inesperado en {label}")
        except RadarError as error:
            LOG.warning("%s", error)
            source_failures += 1
            continue
        for item in map(obj, rows):
            chain = item.get("chainId")
            if not isinstance(chain, str) or chain not in selected:
                continue
            mint = address(chain, item.get("tokenAddress"))
            if mint and f"{chain}:{mint}" not in history:
                selected[chain][mint] = None
    if source_failures == len(sources):
        raise RadarError("DexScreener: fallaron todas las fuentes de descubrimiento")

    best = {}
    failures = source_failures
    for chain, tokens in selected.items():
        addresses = list(tokens)[:60]
        for offset in range(0, len(addresses), 30):
            batch = addresses[offset:offset + 30]
            url = f"{DEX}/tokens/v1/{chain}/{','.join(batch)}"
            try:
                pairs = request_json("DexScreener", url)
                if not isinstance(pairs, list):
                    raise RadarError("DexScreener: formato inesperado en pares")
            except RadarError as error:
                LOG.warning("%s", error)
                failures += 1
                continue
            wanted = set(batch)
            now_ms = time.time() * 1000
            for row in pairs:
                candidate = qualify(chain, row, wanted, now_ms)
                if candidate is not None:
                    current = best.get(candidate.key)
                    if current is None or (candidate.liquidity, candidate.volume_1h, candidate.pair) > (
                        current.liquidity, current.volume_1h, current.pair
                    ):
                        best[candidate.key] = candidate
    qualified = [candidate for candidate in best.values() if candidate.score >= MIN_SCORE and candidate.signal]
    return sorted(qualified, key=lambda c: (c.chain != "solana", -c.score, -c.volume_1h, c.key)), failures


def passes_audit(candidate):
    mint = candidate.mint
    if candidate.chain == "solana":
        report = obj(request_json("RugCheck", f"https://api.rugcheck.xyz/v1/tokens/{mint}/report/summary"))
        risks = report.get("risks")
        program = report.get("tokenProgram")
        if report.get("error") or not isinstance(program, str) or not program or not isinstance(risks, list):
            raise RadarError("RugCheck: informe incompleto")
        for risk in map(obj, risks):
            level, name = risk.get("level"), risk.get("name")
            if not isinstance(level, str) or not level.strip() or not isinstance(name, str) or not name.strip():
                raise RadarError("RugCheck: riesgo sin clasificar")
            if level.strip().lower() in {"danger", "critical", "high"} or any(
                term in name.lower() for term in CRITICAL_NAMES
            ):
                return False
        return True

    query = f"https://api.gopluslabs.io/api/v1/token_security/8453?contract_addresses={mint}"
    report = obj(request_json("GoPlus", query))
    token = obj(obj(report.get("result")).get(mint))
    if report.get("code") != 1 or not token:
        raise RadarError("GoPlus: informe incompleto")
    if token.get("is_open_source") != "1":
        return False
    if any(token.get(flag) not in ("0", "1") for flag in BASE_FLAGS):
        raise RadarError("GoPlus: faltan indicadores básicos")
    return all(token.get(flag) != "1" for flag in BASE_FLAGS + BASE_OPTIONAL_FLAGS)


def format_alert(candidate, chat, channel):
    def usd(value):
        return f"${value:,.0f} USD" if value is not None and value >= 0 else "N/A"

    def percent(value):
        return f"{value:+.2f}%" if value is not None else "N/A"

    cap = f"FDV {usd(candidate.fdv)}"
    if candidate.market_cap is not None and candidate.market_cap > 0:
        cap = f"Market Cap {usd(candidate.market_cap)} · {cap}"
    footer = "🔁 Forward this signal and help the intelligence network grow."
    if channel:
        footer = f'🔁 Share <a href="https://t.me/{channel}">IS IT COOKED?</a> with your community.'
    official = []
    if candidate.telegram_url:
        official.append(f'<a href="{escape(candidate.telegram_url, quote=True)}">Telegram</a>')
    if candidate.website_url:
        official.append(f'<a href="{escape(candidate.website_url, quote=True)}">Website</a>')
    if candidate.x_url:
        official.append(f'<a href="{escape(candidate.x_url, quote=True)}">X</a>')
    official_line = f"🌐 <b>Official:</b> {' · '.join(official)}" if official else ""
    headline = "⚡ " + (candidate.signal or "BREAKOUT ACTIVITY DETECTED")
    lines = [
        f"<b>{headline}</b>",
        f"<b>{escape(candidate.name)}</b> · <b>${escape(candidate.symbol)}</b> · {CHAINS[candidate.chain]}",
        "", "📋 <b>CONTRACT ADDRESS</b>", f"<pre>{candidate.mint}</pre>",
        "",
        f"🎯 Radar Score  <b>{candidate.score}/100</b> · Age <b>{candidate.age_minutes:.0f} min</b>",
        f"🏷 {cap}",
        f"💧 Liquidity  <b>{usd(candidate.liquidity)}</b>",
        f"📈 Volume 1h  <b>{usd(candidate.volume_1h)}</b> · 5m {usd(candidate.volume_5m)}",
        f"⚡ Price Change  5m <b>{percent(candidate.change_5m)}</b> · 1h <b>{percent(candidate.change_1h)}</b>",
        f"🔄 Buys/Sells 1h  <b>{candidate.buys:,.0f} / {candidate.sells:,.0f}</b>",
    ]
    if official_line:
        lines.extend(("", official_line))
    lines.extend((
        "", "<i>Signal before noise · Always do your own research.</i>",
        f"<i>{footer}</i>",
    ))
    message = "\n".join(lines)
    chart = f"https://dexscreener.com/{candidate.chain}/{candidate.pair}"
    if candidate.chain == "solana":
        trade = ("⚡ Quick Buy · Photon", f"https://photon-sol.tinyastro.io/en/lp/{candidate.pair}")
        audit = ("🔍 Security Check · RugCheck", f"https://rugcheck.xyz/tokens/{candidate.mint}")
    else:
        trade = ("⚡ Quick Buy · Uniswap",
                 f"https://app.uniswap.org/swap?chain=base&outputCurrency={candidate.mint}")
        audit = ("🔍 Security Check · GoPlus", f"https://console.gopluslabs.io/token-security/8453/{candidate.mint}")
    buttons = [("📊 View Chart", chart), trade, audit]
    keyboard = [[{"text": title, "url": url}] for title, url in buttons]
    social_buttons = []
    if candidate.telegram_url:
        social_buttons.append({"text": "💬 Telegram", "url": candidate.telegram_url})
    if candidate.website_url:
        social_buttons.append({"text": "🌐 Website", "url": candidate.website_url})
    if candidate.x_url:
        social_buttons.append({"text": "𝕏 X", "url": candidate.x_url})
    if social_buttons:
        keyboard.append(social_buttons)
    keyboard.append([{"text": "📋 Copy Contract", "copy_text": {"text": candidate.mint}}])
    return {
        "chat_id": chat, "text": message, "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": True},
        "reply_markup": {"inline_keyboard": keyboard},
    }


def load_font(size, bold=False):
    names = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def compact_usd(value):
    if value is None or value < 0:
        return "N/A"
    for divisor, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if value >= divisor:
            return f"${value / divisor:.1f}{suffix}"
    return f"${value:,.0f}"


def load_logo(url):
    if not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.netloc.lower() == "cdn.dexscreener.com" and parsed.path.startswith("/cms/images/"):
        params = dict(parse_qsl(parsed.query))
        params.update(width=512, height=512, fit="contain", quality=95)
        hd = parsed._replace(query=urlencode(params)).geturl()
        image = read_logo(hd)
        if image is not None:
            return image
    return read_logo(url)


def read_logo(url):
    try:
        if not isinstance(url, str) or urlsplit(url).netloc.lower() not in {
            "cdn.dexscreener.com", "dd.dexscreener.com"
        } or not url.startswith("https://"):
            return None
        with HTTP.open(Request(url, headers={"User-Agent": "MemecoinRadar/2"}), timeout=3) as response:
            data = response.read(2_000_001)
        if len(data) > 2_000_000:
            return None
        with Image.open(BytesIO(data), formats=("PNG", "JPEG", "WEBP", "GIF")) as source:
            if source.width * source.height <= 8_000_000:
                logo = ImageOps.contain(source.convert("RGBA"), (236, 218), method=Image.Resampling.LANCZOS)
                sharp = logo.convert("RGB").filter(ImageFilter.UnsharpMask(radius=0.8, percent=70, threshold=4))
                sharp.putalpha(logo.getchannel("A"))
                return sharp
    except (OSError, ValueError, HTTPException, Image.DecompressionBombError):
        pass
    return None


def logo_accent(logo):
    import colorsys
    bins = [0.0] * 36
    if logo is not None:
        for r, g, b, alpha in logo.resize((48, 48)).getdata():
            hue, saturation, light = colorsys.rgb_to_hsv(r/255, g/255, b/255)
            if alpha > 150 and saturation > 0.22 and light > 0.17:
                bins[int(hue * 36) % 36] += saturation * light
    if not max(bins):
        return (133, 211, 255)
    hue = (bins.index(max(bins)) + 0.5) / 36
    return tuple(round(v*255) for v in colorsys.hsv_to_rgb(hue, 0.48, 1))


def render_card(candidate):
    import random
    logo = load_logo(candidate.logo_url)
    accent = logo_accent(logo)
    # Galaxia espiral inclinada. Las estrellas son estables entre publicaciones.
    sky = Image.new("RGB", (300, 169))
    for y in range(169):
        for x in range(300):
            dx, dy = x-237, y-51
            u, v = (dx*.94-dy*.34)/54, (dx*.34+dy*.94)/18
            radius = math.hypot(u, v)
            angle = math.atan2(v, u)
            arm = (.5 + .5*math.cos(2*angle-5*math.log1p(radius)))**4
            grain = .8 + .2*math.sin(x*.71+y*.35)*math.sin(y*.53-x*.23)
            haze = math.exp(-radius*1.18)*(.24+arm)*grain
            core = math.exp(-radius*6)
            halo = .29 * math.exp(-((x-34)/35)**2 - ((y-52)/17)**2)
            sky.putpixel((x,y),tuple(min(255,round(base+(haze*.85+halo)*c+core*195))
                                    for base,c in zip((8,11,32),accent)))
    image = sky.resize((1200,675), Image.Resampling.BICUBIC)
    draw = ImageDraw.Draw(image)
    rng = random.Random(813)
    for i in range(1350):
        x,y = rng.randrange(1200),rng.randrange(675)
        brightness = rng.randrange(45,185)
        star = (brightness,brightness,min(255,brightness+30))
        draw.point((x,y),fill=star)
        if i % 59 == 0:
            draw.line((x-2,y,x+2,y),fill=star)
            draw.line((x,y-2,x,y+2),fill=star)
    draw.rounded_rectangle((30,445,1170,592),radius=20,fill="#101629",outline="#30394e")
    paper, muted = "#ffffff","#d6dff1"
    def label(x, y, text, size, color, width, bold=False):
        font = load_font(size, bold)
        while text and draw.textlength(text, font=font) > width:
            text = text[:-2].rstrip("…") + "…" if len(text) > 2 else ""
        draw.text((x, y), text, font=font, fill=color)

    draw.ellipse((53,39,75,61),outline=accent,width=2)
    draw.ellipse((60,46,68,54),fill=accent)
    label(92, 30, "IS IT COOKED?  /  RADAR", 28, accent, 650, True)
    stamp = datetime.now(timezone.utc).strftime("%d.%m.%Y   %H:%M UTC")
    label(838, 33, stamp, 22, muted, 315)
    draw.line((52,87,1148,87), fill="#334451", width=2)
    if logo is not None:
        alpha = logo.getchannel("A")
        if alpha.getextrema()[0] > 240:
            # Disuelve el perímetro de imágenes opacas y conserva el centro nítido.
            fade = Image.radial_gradient("L").resize(logo.size).point(
                lambda v: max(0, min(255, (169-v)*5)))
            alpha = ImageChops.multiply(alpha, fade)
        image.paste(logo, (143-logo.width//2, 210-logo.height//2), alpha)
    else:
        draw.text((143,210), candidate.symbol[:2].upper(), font=load_font(48, True),
                  fill=accent, anchor="mm")
    network = {"ethereum": "Ethereum", **CHAINS}.get(candidate.chain, candidate.chain)
    if candidate.chain in ("solana", "base", "ethereum"):
        icon_path = Path(__file__).with_name("redes") / (candidate.chain + ".png")
        with Image.open(icon_path) as icon:
            badge = icon.convert("RGBA")
            if candidate.chain == "solana":
                # El archivo incluye un fondo negro. Aísla las tres barras de color.
                rgb = badge.convert("RGB")
                mask = rgb.convert("L").point(lambda v: min(255,v*12))
                badge.putalpha(ImageChops.multiply(mask, badge.getchannel("A")))
                badge = badge.crop(badge.getbbox())
            badge.thumbnail((24,24), Image.Resampling.LANCZOS)
    row_font = load_font(25, True)
    row_text = network.upper() + "   /   $" + candidate.symbol
    left, top, right, bottom = draw.textbbox((0,0),row_text,font=row_font)
    row_center = 154
    if candidate.chain in ("solana", "base", "ethereum"):
        image.paste(badge,(265+(24-badge.width)//2,row_center-badge.height//2),badge)
    draw.text((301-left,row_center-(top+bottom)//2),row_text,font=row_font,fill=accent)
    label(265,179,candidate.name,76,paper,645,True)
    draw.polygon([(52,331),(1125,331),(1148,354),(1148,429),(75,429),(52,406)],
                 fill=accent)
    draw.line((83,339,216,339),fill="#385022",width=3)
    label(78,354,candidate.signal or "BREAKOUT ACTIVITY DETECTED",38,"#132312",1040,True)
    for x, title, value in ((52,"VOLUME · 5 MIN",compact_usd(candidate.volume_5m)),
                            (424,"LIQUIDITY",compact_usd(candidate.liquidity)),
                            (796,"BUY PRESSURE · 1 H",f"{100*candidate.buys/max(1,candidate.buys+candidate.sells):.0f}%")):
        tint = accent
        draw.line((x,457,x+51,457),fill=tint,width=4)
        label(x,473,title,22,muted,330,True)
        label(x,505,value,61,paper,330,True)
    draw.line((52,602,1148,602),fill="#334451",width=2)
    label(52,622,"SIGNAL BEFORE NOISE   /   "+network,22,muted,700)
    label(875,622,f"Momentum   {candidate.score}/100",22,accent,280,True)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def parse_telegram_response(response):
    try:
        data = obj(response.json())
    except ValueError:
        raise RadarError("Telegram devolvió una respuesta ilegible") from None
    message_id = obj(data.get("result")).get("message_id")
    if data.get("ok") is True and type(message_id) is int and message_id > 0:
        return message_id
    if data.get("ok") is False and data.get("error_code") in (400, 401, 403, 404, 429):
        raise TelegramRejected(f"Telegram rechazó el envío (código {data['error_code']})")
    raise RadarError("Telegram devolvió un resultado incierto")


def send(token, payload, card=None):
    if card is not None:
        url = f"https://api.telegram.org/bot{token}/sendPhoto"
        fields = {
            "chat_id": payload["chat_id"], "caption": payload["text"],
            "parse_mode": payload["parse_mode"],
            "reply_markup": json.dumps(payload["reply_markup"]),
            "show_caption_above_media": "false",
        }
        try:
            response = requests.post(
                url, data=fields, files={"photo": ("radar.png", card, "image/png")},
                timeout=(5, 15), allow_redirects=False,
            )
        except requests.RequestException as error:
            raise RadarError(f"Telegram: envío incierto ({type(error).__name__})") from None
        return parse_telegram_response(response)

    response = obj(request_json("Telegram", f"https://api.telegram.org/bot{token}/sendMessage", payload))
    message_id = obj(response.get("result")).get("message_id")
    if response.get("ok") is True and type(message_id) is int and message_id > 0:
        return message_id
    if response.get("ok") is False and response.get("error_code") in (400, 401, 403, 404, 429):
        raise TelegramRejected(f"Telegram rechazó el envío (código {response['error_code']})")
    raise RadarError("Telegram devolvió un resultado incierto")


def read_history():
    try:
        history = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RadarError("No se pudo leer sent_tokens.json. Restaura el historial antes de publicar.") from None
    if not isinstance(history, dict):
        raise RadarError("sent_tokens.json debe ser un objeto JSON")
    return history


def git(*args):
    try:
        subprocess.run(
            ["git", *args], cwd=STATE.parent, check=True, timeout=15,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        raise RadarError(f"Falló git {args[0]}. Comprueba permisos, rama y ejecuciones concurrentes.") from None


def save_history(history, ref, message):
    temp = STATE.with_suffix(".tmp")
    try:
        temp.write_text(json.dumps(history, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        temp.replace(STATE)
    except OSError:
        raise RadarError("No se pudo escribir sent_tokens.json") from None
    git("add", "--", STATE.name)
    git("commit", "-m", f"Radar: {message}", "--", STATE.name)
    # Un push sin fuerza falla si la rama avanzó. Conserva el historial remoto.
    git("push", "origin", f"HEAD:{ref}")


def maintain_heartbeat(history, ref):
    """Registra actividad cada 14 días para conservar el cron en repos públicos."""
    now = datetime.now(timezone.utc)
    heartbeat = obj(history.get("_meta")).get("heartbeat")
    try:
        previous = datetime.fromisoformat(heartbeat) if isinstance(heartbeat, str) else None
    except ValueError:
        previous = None
    if previous is not None and previous.tzinfo is not None and (now - previous).days < 14:
        return
    meta = obj(history.get("_meta"))
    meta["heartbeat"] = now.isoformat()
    history["_meta"] = meta
    save_history(history, ref, "mantenimiento quincenal")


def publish(candidate, payload, card, token, history, ref):
    entry = {
        "status": "reserved", "reserved_at": datetime.now(timezone.utc).isoformat(),
        "chain": candidate.chain, "mint": candidate.mint, "pair": candidate.pair,
        "symbol": candidate.symbol, "score": candidate.score,
        "initial_price": candidate.price_usd, "initial_liquidity": candidate.liquidity,
    }
    history[candidate.key] = entry
    # Persiste antes del POST. Un fallo posterior deja esta clave reservada.
    save_history(history, ref, f"reservar {candidate.key}")
    try:
        message_id = send(token, payload, card)
    except TelegramRejected:
        del history[candidate.key]
        save_history(history, ref, f"liberar {candidate.key}")
        raise
    except RadarError as error:
        raise RadarError(f"{candidate.key} sigue reservado. {error}") from None
    entry.update(status="sent", message_id=message_id, sent_at=datetime.now(timezone.utc).isoformat(), tracking={})
    save_history(history, ref, f"confirmar {candidate.key}")


def current_market(entry):
    chain, mint = entry.get("chain"), entry.get("mint")
    if chain not in CHAINS or not isinstance(mint, str):
        return None
    rows = request_json("DexScreener", f"{DEX}/latest/dex/tokens/{mint}")
    pairs = rows.get("pairs") if isinstance(rows, dict) else None
    if not isinstance(pairs, list):
        raise RadarError("DexScreener: invalid tracking response")
    same_chain = [obj(pair) for pair in pairs if obj(pair).get("chainId") == chain]
    preferred = next((pair for pair in same_chain if pair.get("pairAddress") == entry.get("pair")), None)
    if preferred is None and same_chain:
        preferred = max(same_chain, key=lambda pair: number(obj(pair.get("liquidity")).get("usd")) or 0)
    if preferred is None:
        return {"price": None, "liquidity": 0}
    return {"price": number(preferred.get("priceUsd")),
            "liquidity": number(obj(preferred.get("liquidity")).get("usd")) or 0}


def receipt_payload(entry, checkpoint, chat, channel):
    initial, current = number(entry.get("initial_price")), number(checkpoint.get("price"))
    change = checkpoint.get("change_pct")
    symbol = escape(str(entry.get("symbol") or "TOKEN")[:24])
    network = CHAINS.get(entry.get("chain"), str(entry.get("chain") or ""))
    if initial and current and isinstance(change, (int, float)):
        result = (f"Signal price  <b>${initial:.8g}</b> → <b>${current:.8g}</b>\n"
                  f"24h change  <b>{change:+.1f}%</b>")
    else:
        result = "Current market data is unavailable. Liquidity may have disappeared."
    footer = "Every signal stays in the record — wins and losses."
    if channel:
        footer = f'Every signal stays in <a href="https://t.me/{channel}">the public record</a>.'
    text = "\n".join((
        "🧾 <b>THE RECEIPT · 24H UPDATE</b>",
        f"<b>${symbol}</b> · {network}", "", result,
        f"Liquidity now  <b>{compact_usd(checkpoint.get('liquidity'))}</b>",
        f"Original Radar Score  <b>{entry.get('score', 'N/A')}/100</b>", "",
        f"<i>{footer}</i>", "<i>Tracked outcome · Not financial advice.</i>",
    ))
    chart = f"https://dexscreener.com/{entry.get('chain')}/{entry.get('pair')}"
    return {"chat_id": chat, "text": text, "parse_mode": "HTML",
            "link_preview_options": {"is_disabled": True},
            "reply_markup": {"inline_keyboard": [[{"text": "📊 View Current Chart", "url": chart}]]}}


def update_receipts(history, token, chat, channel, ref):
    """Track ~1h/~6h/~24h outcomes and publish one transparent 24h receipt."""
    now, failures = datetime.now(timezone.utc), 0
    for key, entry in list(history.items()):
        if key == "_meta" or not isinstance(entry, dict) or entry.get("status") != "sent":
            continue
        initial = number(entry.get("initial_price"))
        sent_at = entry.get("sent_at")
        if not initial or not isinstance(sent_at, str):
            continue
        try:
            sent = datetime.fromisoformat(sent_at)
        except ValueError:
            continue
        elapsed = (now - sent).total_seconds() / 3600
        tracking = obj(entry.get("tracking"))
        due = [("1h", 1), ("6h", 6), ("24h", 24)]
        missing = [(label, hours) for label, hours in due if elapsed >= hours and label not in tracking]
        if not missing:
            continue
        try:
            market = current_market(entry)
        except RadarError as error:
            LOG.warning("Receipt tracking skipped for %s: %s", key, error)
            failures += 1
            continue
        price = market["price"] if market else None
        change = round((price / initial - 1) * 100, 2) if price else None
        for label, _ in missing:
            tracking[label] = {"price": price, "liquidity": market.get("liquidity", 0),
                               "change_pct": change, "observed_after_h": round(elapsed, 1)}
        entry["tracking"] = tracking
        publish_24h = any(label == "24h" for label, _ in missing) and not entry.get("receipt_message_id")
        save_history(history, ref, f"track {key} at {','.join(label for label, _ in missing)}")
        if publish_24h:
            try:
                entry["receipt_message_id"] = send(token, receipt_payload(entry, tracking["24h"], chat, channel))
                save_history(history, ref, f"confirm receipt {key}")
            except RadarError as error:
                LOG.warning("24h receipt for %s was not confirmed: %s", key, error)
                failures += 1
    return failures


def maybe_weekly_receipt(history, token, chat, channel, ref):
    now = datetime.now(timezone.utc)
    if now.weekday() != 6 or now.hour < 18:
        return 0
    meta = obj(history.get("_meta")); week = now.strftime("%G-W%V")
    if meta.get("weekly_receipt") == week:
        return 0
    rows = []
    for entry in history.values():
        if not isinstance(entry, dict):
            continue
        try:
            sent = datetime.fromisoformat(entry.get("sent_at", ""))
        except (TypeError, ValueError):
            continue
        if (now - sent).total_seconds() > 7 * 86400:
            continue
        point = obj(obj(entry.get("tracking")).get("24h"))
        change = point.get("change_pct")
        if isinstance(change, (int, float)):
            rows.append((str(entry.get("symbol") or "TOKEN"), float(change)))
    rows = rows[-20:]
    if len(rows) < 3:
        return 0
    changes = [change for _, change in rows]; positives = sum(change > 0 for change in changes)
    best = max(rows, key=lambda row: row[1]); worst = min(rows, key=lambda row: row[1])
    text = "\n".join((
        "🧾 <b>THE RECEIPT · WEEKLY SCORECARD</b>", "",
        f"Signals tracked  <b>{len(rows)}</b>",
        f"Positive at ~24h  <b>{positives}/{len(rows)}</b>",
        f"Median result  <b>{statistics.median(changes):+.1f}%</b>",
        f"Best  <b>${escape(best[0])} {best[1]:+.1f}%</b>",
        f"Worst  <b>${escape(worst[0])} {worst[1]:+.1f}%</b>", "",
        "<i>No deleted losses. No cherry-picking. Past performance is not a guarantee.</i>",
    ))
    payload = {"chat_id": chat, "text": text, "parse_mode": "HTML",
               "link_preview_options": {"is_disabled": True}}
    try:
        send(token, payload)
    except RadarError as error:
        LOG.warning("Weekly receipt failed: %s", error)
        return 1
    meta["weekly_receipt"] = week; history["_meta"] = meta
    save_history(history, ref, f"weekly receipt {week}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("dry-run", "test", "live"), default="dry-run")
    args = parser.parse_args()

    chat = os.getenv("CHAT_ID", "").strip()
    token = os.getenv("TELEGRAM_TOKEN", "").strip()
    channel = os.getenv("CHANNEL_USERNAME", "").strip().removeprefix("@")
    if not channel and chat.startswith("@"):
        channel = chat[1:]
    if channel and not re.fullmatch(r"[A-Za-z0-9_]{5,32}", channel):
        raise RadarError("CHANNEL_USERNAME debe ser el alias público del canal")
    if args.mode != "dry-run" and (
        not re.fullmatch(r"\d+:[A-Za-z0-9_-]+", token)
        or not re.fullmatch(r"@[A-Za-z0-9_]{5,32}|-100\d+", chat)
    ):
        raise RadarError("Configura TELEGRAM_TOKEN y CHAT_ID con el alias @canal o ID -100…")
    if args.mode == "test":
        send(token, {"chat_id": chat, "text": "✅ Memecoin Radar test successful. Telegram is connected."})
        LOG.info("Telegram confirmó la publicación de prueba.")
        return 0

    # En modo real solo se publica si existe una rama remota para la reserva.
    ref = os.getenv("RADAR_BRANCH_REF", "")
    if args.mode == "live":
        if not ref.startswith("refs/heads/"):
            raise RadarError("Configura RADAR_BRANCH_REF o ejecuta el workflow en la rama predeterminada.")
        git("check-ref-format", ref)

    history = read_history()
    background_failures = 0
    if args.mode == "live":
        background_failures += update_receipts(history, token, chat, channel, ref)
        background_failures += maybe_weekly_receipt(history, token, chat, channel, ref)
    chains = ["solana", "base"] if os.getenv("ENABLE_BASE", "").lower() == "true" else ["solana"]
    candidates, failures = discover(chains, history)
    failures += background_failures
    posted = audited = 0
    for candidate in candidates[:MAX_AUDITS]:
        if posted >= MAX_ALERTS:
            break
        audited += 1
        try:
            if not passes_audit(candidate):
                LOG.info("Riesgo bloqueante para %s", candidate.key)
                continue
        except RadarError as error:
            LOG.warning("Se omite %s. %s", candidate.key, error)
            failures += 1
            continue

        payload = format_alert(candidate, chat, channel)
        card = render_card(candidate)
        if args.mode == "dry-run":
            LOG.info("Simulación %s\n%s", candidate.key, payload["text"])
        else:
            publish(candidate, payload, card, token, history, ref)
            LOG.info("Publicada %s", candidate.key)
        posted += 1

    LOG.info("%s pares candidatos, %s auditados, %s alertas (%s), %s fallos de consulta",
             len(candidates), audited, posted, args.mode, failures)
    if args.mode == "live":
        maintain_heartbeat(history, ref)
    return 1 if failures else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        raise SystemExit(main())
    except RadarError as exc:
        LOG.error("%s", exc)
        raise SystemExit(1) from None
