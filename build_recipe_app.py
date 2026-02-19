"""
Extract all recipes from Broodje Dunner PDF e-books and generate a searchable PWA.
Run: python build_recipe_app.py
Output: recepten_app.html (open in Chrome on Android, then "Add to Home Screen")
"""

import re
import os
import json
import base64
import io
import hashlib
import secrets
from pypdf import PdfReader
from PIL import Image

FOLDER = os.path.dirname(os.path.abspath(__file__))

# --- Encryption helpers (AES-256-GCM) ---
def get_password():
    """Get the app password from .env file or environment variable."""
    env_path = os.path.join(FOLDER, '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('APP_PASSWORD='):
                    return line.split('=', 1)[1].strip().strip('"').strip("'")
    # Fallback to environment variable
    return os.environ.get('APP_PASSWORD', '')


def encrypt_data(plaintext: str, password: str) -> dict:
    """Encrypt plaintext with AES-256-GCM using PBKDF2-derived key.
    Returns dict with salt, iv, and ciphertext (all base64).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)  # 96-bit IV for AES-GCM

    # Derive 256-bit key with PBKDF2 (same params used in JS Web Crypto API)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode('utf-8'))

    # Encrypt
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)

    return {
        'salt': base64.b64encode(salt).decode('ascii'),
        'iv': base64.b64encode(iv).decode('ascii'),
        'data': base64.b64encode(ciphertext).decode('ascii'),
    }

# Image settings for recipe photos
IMG_MAX_WIDTH = 500
IMG_JPEG_QUALITY = 70


def extract_page_image(page):
    """Extract the first image from a PDF page and return as resized JPEG base64."""
    try:
        imgs = page.images
        if not imgs:
            return None
        img_data = imgs[0].data
        img = Image.open(io.BytesIO(img_data))
        # Convert CMYK/RGBA to RGB
        if img.mode in ('CMYK', 'RGBA', 'P'):
            img = img.convert('RGB')
        # Resize if wider than max
        if img.width > IMG_MAX_WIDTH:
            ratio = IMG_MAX_WIDTH / img.width
            new_h = int(img.height * ratio)
            img = img.resize((IMG_MAX_WIDTH, new_h), Image.LANCZOS)
        # Save as JPEG to buffer
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=IMG_JPEG_QUALITY, optimize=True)
        b64 = base64.b64encode(buf.getvalue()).decode('ascii')
        return f"data:image/jpeg;base64,{b64}"
    except Exception as e:
        print(f"    [WARN] Image extraction failed: {e}")
        return None


def extract_pages(pdf_path):
    """Extract text and page objects per page from PDF."""
    reader = PdfReader(pdf_path)
    pages = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            pages.append((text, page))
    return pages


def parse_recipe_page(text, ebook_num, pdf_page=None):
    """Parse a single page that may contain a recipe.

    Two layouts exist:
      Layout A (ingredients first):  Name / Recept voor Tijd / Ingrediënten Aantal / ... / Steps
      Layout B (steps first):        Name / Recept voor Tijd / Steps / Ingrediënten Aantal / ...
    """
    lines = [l.strip() for l in text.split('\n') if l.strip()]

    # Find "Ingrediënten Aantal" line
    ing_line_idx = None
    for i, line in enumerate(lines):
        if 'Ingrediënten' in line and 'Aantal' in line:
            ing_line_idx = i
            break
    if ing_line_idx is None:
        for i, line in enumerate(lines):
            if line.strip() == 'Ingrediënten' and i + 1 < len(lines) and lines[i+1].strip() == 'Aantal':
                ing_line_idx = i
                break
    if ing_line_idx is None:
        return None

    # --- Determine layout: check if numbered steps appear before ingredients ---
    first_step_idx = None
    for i, line in enumerate(lines):
        if re.match(r'^\d+\.', line):
            first_step_idx = i
            break
    steps_before_ingredients = (first_step_idx is not None and first_step_idx < ing_line_idx)

    # --- Extract recipe name ---
    # The recipe name is always at the TOP of the page (before both steps and ingredients).
    # It may span multiple lines and may have "Recept voor Tijd" appended.
    recipe_name = ""
    recipe_time = ""

    # Find the boundary: either the first step or the ingredient header, whichever comes first
    name_boundary = min(first_step_idx if first_step_idx is not None else ing_line_idx, ing_line_idx)

    # Collect name parts from lines 0 up to name_boundary
    # Recipe names are at most 2 lines. After "Recept voor Tijd" or time, stop.
    name_parts = []
    found_recept_voor = False
    found_time = False
    for i in range(min(name_boundary, len(lines))):
        line = lines[i]
        # Extract time
        if re.match(r'^\d+\s*minuut', line) or re.match(r'^\d+\s*uur', line) or line.startswith('Minimaal'):
            recipe_time = line
            found_time = True
            continue
        # After we've seen "Recept voor Tijd" or a time, stop collecting name parts
        if found_recept_voor or found_time:
            break
        # Skip portion lines
        if re.match(r'^\d+\s*(pizza|plak|boll|stuk|persoon|persone)?$', line) and len(line) < 20:
            continue
        # "Recept voor Tijd" marks end of name
        if line == 'Recept voor Tijd':
            found_recept_voor = True
            continue
        # Skip numbered steps
        if re.match(r'^\d+\.', line):
            break
        # Skip tip/notes/vega
        if line.startswith('Tip:') or line.startswith('Tip ') or line.startswith('ENJOY') or line.startswith('Je mag'):
            continue
        if line.startswith('Liever vega') or line.startswith('V ega') or line.startswith('Vega:'):
            continue
        # Skip boodschappenlijst lines
        if re.match(r'^Boodschappenlijst', line, re.IGNORECASE):
            continue
        # Skip long descriptive text (not a recipe name)
        if len(line) > 60 and not 'Recept' in line:
            continue

        # Clean "Recept voor Tijd" suffix
        cleaned = re.sub(r'\s*Recept\s+voor\s+Tijd\s*$', '', line).strip()
        cleaned = re.sub(r'\s*\d+\s*minuutjes?\s*$', '', cleaned).strip()
        cleaned = re.sub(r'\s*\d+\s*uur\s*$', '', cleaned).strip()
        cleaned = re.sub(r'^Boodschappenlijst(je)?\s+', '', cleaned, flags=re.IGNORECASE).strip()
        if cleaned and len(cleaned) > 1:
            name_parts.append(cleaned)

    # Join multi-line names (e.g. "Gevulde courgette met" + "rivierkreeftjes")
    if name_parts:
        recipe_name = ' '.join(name_parts)

    if not recipe_name:
        return None

    # Clean up
    recipe_name = recipe_name.replace('  ', ' ').strip()
    recipe_name = re.sub(r'\s*Recept.*', '', recipe_name).strip()
    if re.match(r'^\d+\.', recipe_name):
        return None
    if recipe_name.startswith('Vega:') or recipe_name.startswith('V ega:'):
        return None

    # --- Extract ingredients ---
    raw_ingredients = []
    j = ing_line_idx + 1
    if j < len(lines) and lines[j].strip() == 'Aantal':
        j += 1

    while j < len(lines):
        line = lines[j]
        if re.match(r'^\d+\.', line):
            break
        if line.startswith('Tip:') or line.startswith('Liever vega') or line.startswith('V ega') or line.startswith('Vega:'):
            break
        if line.startswith('INGREDIËNTEN') or line.startswith('Boodschappen'):
            break
        # Stop at long prose text (ingredient descriptions/tips embedded after ingredients)
        if len(line) > 70 and not re.search(r'\d+\s*(gram|stuk|ml|el|tl|stuks)', line.lower()):
            break
        # Stop at instruction-like lines that aren't ingredients
        if line.startswith('Let op:') or line.startswith('let op:'):
            break
        if line and line != 'ENJOY!':
            raw_ingredients.append(line)
        j += 1

    # Merge broken ingredient lines
    ingredients = []
    for line in raw_ingredients:
        is_continuation = False
        if ingredients:
            if line.startswith('('):
                is_continuation = True
            elif line[0].islower() and len(line) < 30:
                is_continuation = True
            elif ingredients[-1].count('(') > ingredients[-1].count(')'):
                is_continuation = True
        if is_continuation:
            ingredients[-1] = ingredients[-1].rstrip() + ' ' + line
        else:
            ingredients.append(line)

    # --- Extract steps ---
    steps = []
    for k, line in enumerate(lines):
        if re.match(r'^\d+\.', line):
            step_text = line
            m = k + 1
            while m < len(lines):
                next_l = lines[m]
                if re.match(r'^\d+\.', next_l):
                    break
                if 'Ingrediënten' in next_l or next_l.startswith('Tip:') or next_l.startswith('Boodschappen'):
                    break
                if next_l.startswith('Liever vega') or next_l.startswith('V ega') or next_l.startswith('Vega:'):
                    break
                if next_l.startswith('Je mag') or next_l.startswith('Dit gerecht'):
                    break
                if next_l.startswith('- Tip:') or next_l.startswith('- Liever'):
                    break
                # If we're in Layout B (steps before ingredients), don't merge ingredient lines
                if steps_before_ingredients and re.search(r'\d+\s*(gram|stuk|ml|el|tl|stuks|halve|snufje|handje|bladeren|vellen|sprieten|teentje)', next_l.lower()):
                    break
                step_text += ' ' + next_l
                m += 1
            steps.append(step_text)

    # Filter out ENJOY step and deduplicate
    clean_steps = []
    seen = set()
    for s in steps:
        clean = re.sub(r'^\d+[\.\)]\s*', '', s).strip()
        if 'ENJOY' in clean.upper():
            continue
        key = clean.lower()
        if key not in seen and len(clean) > 3:
            seen.add(key)
            clean_steps.append(clean)

    # --- Extract vega option ---
    vega = ""
    for line in lines:
        if 'Liever vega' in line or line.startswith('V ega:') or line.startswith('Vega:'):
            vega = line.replace('V ega:', 'Vega:').strip()
            break

    if not ingredients and not clean_steps:
        return None

    # Final name cleanup: capitalize first letter
    if recipe_name and recipe_name[0].islower():
        recipe_name = recipe_name[0].upper() + recipe_name[1:]

    # Parse time: "220 minuutjes" = 2 personen, 20 min (first digit = portions when 3+ digits)
    parsed_time = ""
    portions = ""
    if recipe_time:
        m = re.match(r'^(\d+)\s*minuut', recipe_time)
        if m:
            num_str = m.group(1)
            if len(num_str) >= 3:
                portions = num_str[0]
                mins = int(num_str[1:])
                parsed_time = f"{mins} min"
            else:
                mins = int(num_str)
                parsed_time = f"{mins} min"

    # Extract image from PDF page
    image_b64 = None
    if pdf_page is not None:
        image_b64 = extract_page_image(pdf_page)

    return {
        'name': recipe_name,
        'ebook': ebook_num,
        'time': parsed_time,
        'portions': portions,
        'ingredients': ingredients,
        'steps': clean_steps,
        'vega': vega,
        'image': image_b64
    }


# Manual name corrections for recipes where PDF parsing gives bad names
# Keys are LOWERCASE - matching is case-insensitive
NAME_FIXES = {
    # E-book 2
    'green ﬂuff': 'Green fluff',
    'broodje knoﬂook champignons': 'Broodje knoflook champignons',
    'pannenkoek choco- aardbei': 'Pannenkoek choco-aardbei',
    'pizza tonno 1 pizza': 'Pizza tonno',
    # E-book 3 - multi-line name picked up too much text
    'bananenbrood (tussendoortje) 8 plakken': 'Bananenbrood',
    'bananenbrood (tussendoortje)': 'Bananenbrood',
    # E-book 5
    "avg\u2019 t j e": "AVG'tje",
    "avg' t j e": "AVG'tje",
    'overnight pudding 1minimaal': 'Overnight pudding',
    # E-book 6
    'baked chocolate-chip': 'Baked chocolate-chip cookies',
    'portobelloburger': 'Portobello sandwich',
    # E-book 7
    'overnight oats 1minimaal 1 nacht': 'Overnight oats met banaan',
    'tortilla pulled chicken': 'Quesadilla',
    # Cleanup PDF ligature artifacts
    'broodje a vo': 'Broodje avo',
    'zoete aardappel stamppot': 'Zoete aardappelstamppot',
}

# For names that contain garbage after the real name, use prefix matching
# These are checked if exact match fails: if name starts with prefix, use the fix
NAME_PREFIX_FIXES = {
    'kwarkbollen appel': 'Kwarkbollen appel-kaneel',
    'scrambled eggs broodje': 'Scrambled eggs',
    'broodje komijnekaas broodje': 'Broodje komijnekaas',
}


def extract_recipes_from_ebook(pdf_path, ebook_num):
    """Extract all recipes from a single e-book PDF."""
    pages = extract_pages(pdf_path)
    recipes = []

    # Build case-insensitive lookups
    name_fixes_lower = {k.lower(): v for k, v in NAME_FIXES.items()}
    prefix_fixes_lower = {k.lower(): v for k, v in NAME_PREFIX_FIXES.items()}

    for page_text, pdf_page in pages:
        recipe = parse_recipe_page(page_text, ebook_num, pdf_page)
        if recipe:
            name_lower = recipe['name'].lower()
            # Try exact match first
            if name_lower in name_fixes_lower:
                recipe['name'] = name_fixes_lower[name_lower]
            else:
                # Try prefix matching for names with garbage suffixes
                for prefix, fixed_name in prefix_fixes_lower.items():
                    if name_lower.startswith(prefix):
                        recipe['name'] = fixed_name
                        break
            recipes.append(recipe)

    return recipes


def deduplicate_recipes(recipes):
    """Remove duplicate recipes, keeping the most complete version."""
    seen = {}
    for r in recipes:
        # Normalize name for dedup
        key = r['name'].lower().strip()
        key = re.sub(r'[^a-z0-9àáâãäåèéêëìíîïòóôõöùúûüýÿ]', '', key)

        if key in seen:
            existing = seen[key]
            score = len(r['ingredients']) + len(r['steps'])
            existing_score = len(existing['ingredients']) + len(existing['steps'])
            if score > existing_score:
                seen[key] = r
        else:
            seen[key] = r

    return list(seen.values())


def categorize_recipe(r):
    """Assign a category based on recipe name and context."""
    n = r['name'].lower()
    ings = ' '.join(r['ingredients']).lower()

    # Ontbijt patterns
    ontbijt_keywords = [
        'bowl', 'fruity', 'fluffy', 'choco', 'chocoatmeal', 'oatmeal', 'havermout',
        'pannenkoek', 'poffert', 'wentelteef', 'appeltaart', 'ontbijt', 'yoghurt',
        'kwarkbol', 'bananensplit', 'fluff', 'green goedje', 'groen goedje',
        'breakf', 'meloentje', 'meloen maan', 'fram-bo', 'overnight', 'pudding',
        'appel-pinda', 'snelste ontbijt', 'havermoutpap', 'summer bowl'
    ]

    # Lunch patterns
    lunch_keywords = [
        'broodje', 'tosti', 'wrap', 'sandwich', 'club', 'scrambled',
        'soep', 'salade gerookte', 'salade zalm', 'salade gerookte zalm',
        'mozzarella salade', 'hummus', 'tortilla rosbief', 'tortilla kip',
        'salade gerookte kip', 'salade beef'
    ]

    # Tussendoortje
    snack_keywords = ['bananenbrood', 'tussendoortje', 'tussendoor']

    for kw in ontbijt_keywords:
        if kw in n:
            return 'Ontbijt'

    for kw in lunch_keywords:
        if kw in n:
            return 'Lunch'

    for kw in snack_keywords:
        if kw in n:
            return 'Tussendoortje'

    return 'Diner'


def build_html(recipes, password=''):
    """Build the complete PWA HTML file. If password is given, encrypt recipe data."""

    # Add category to each recipe
    for r in recipes:
        r['category'] = categorize_recipe(r)

    # Separate images from recipe data to keep JSON compact
    images = []
    for r in recipes:
        images.append(r.get('image') or '')
        # Don't include base64 in the main JSON
        r_copy = dict(r)
        r.pop('image', None)

    recipes_json = json.dumps(recipes, ensure_ascii=False)
    images_json = json.dumps(images, ensure_ascii=False)

    # Encrypt if password provided
    use_encryption = bool(password)
    encrypted_payload = None
    if use_encryption:
        # Bundle recipes + images into one payload for encryption
        payload = json.dumps({'recipes': json.loads(recipes_json), 'images': json.loads(images_json)}, ensure_ascii=False)
        encrypted_payload = encrypt_data(payload, password)
        print(f"  Data versleuteld ({len(payload)//1024}KB -> {len(encrypted_payload['data'])//1024}KB ciphertext)")

    # Load app icon if available
    icon_path = os.path.join(FOLDER, 'icon.png')
    icon_192_b64 = ''
    icon_512_b64 = ''
    if os.path.exists(icon_path):
        icon_img = Image.open(icon_path)
        if icon_img.mode in ('CMYK', 'P'):
            icon_img = icon_img.convert('RGBA')
        for size in [192, 512]:
            resized = icon_img.resize((size, size), Image.LANCZOS)
            buf = io.BytesIO()
            resized.save(buf, format='PNG', optimize=True)
            b64 = base64.b64encode(buf.getvalue()).decode('ascii')
            if size == 192:
                icon_192_b64 = b64
            else:
                icon_512_b64 = b64
        print(f"  App-icoon geladen: {os.path.basename(icon_path)}")

    icon_192_uri = f"data:image/png;base64,{icon_192_b64}" if icon_192_b64 else ''
    icon_512_uri = f"data:image/png;base64,{icon_512_b64}" if icon_512_b64 else ''

    manifest_icons = []
    if icon_192_b64:
        manifest_icons.append({"src": icon_192_uri, "sizes": "192x192", "type": "image/png"})
    if icon_512_b64:
        manifest_icons.append({"src": icon_512_uri, "sizes": "512x512", "type": "image/png"})

    manifest = {
        "name": "Broodje Dunner Recepten",
        "short_name": "Recepten",
        "start_url": ".",
        "display": "standalone",
        "background_color": "#f0f4f0",
        "theme_color": "#2d6a4f",
        "icons": manifest_icons
    }
    manifest_b64 = base64.b64encode(json.dumps(manifest).encode()).decode()

    # Build the data script section based on whether encryption is used
    if use_encryption:
        data_script = f'''
const ENCRYPTED = {{
  salt: "{encrypted_payload['salt']}",
  iv: "{encrypted_payload['iv']}",
  data: "{encrypted_payload['data']}"
}};
let R = [];
let IMGS = [];
'''
    else:
        data_script = f'''
const R = {recipes_json};
const IMGS = {images_json};
'''

    # Login screen HTML (only shown when encrypted)
    login_screen_html = ''
    login_screen_css = ''
    decrypt_js = ''
    init_call = 'initApp();' if use_encryption else 'renderFilters();renderCats();render();updateFab();'

    if use_encryption:
        login_screen_css = '''
.login-screen {
  position: fixed;
  inset: 0;
  z-index: 9999;
  background: linear-gradient(135deg, #2d6a4f 0%, #40916c 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.login-screen.hidden { display: none; }
.login-box {
  background: white;
  border-radius: 24px;
  padding: 40px 28px;
  max-width: 360px;
  width: 100%;
  box-shadow: 0 20px 60px rgba(0,0,0,0.3);
  text-align: center;
}
.login-box h1 {
  font-size: 24px;
  color: var(--text);
  margin-bottom: 4px;
}
.login-box .sub {
  font-size: 14px;
  color: var(--text-light);
  margin-bottom: 28px;
}
.login-box .icon {
  font-size: 48px;
  margin-bottom: 16px;
}
.login-pass-wrap {
  position: relative;
  margin-bottom: 16px;
}
.login-pass-wrap input {
  width: 100%;
  padding: 14px 48px 14px 18px;
  border: 2px solid #e0e0e0;
  border-radius: 14px;
  font-size: 16px;
  text-align: center;
  outline: none;
  transition: border-color 0.2s;
}
.login-pass-wrap input:focus {
  border-color: var(--green);
}
.pass-toggle {
  position: absolute;
  right: 14px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  font-size: 20px;
  cursor: pointer;
  opacity: 0.4;
  padding: 4px;
  line-height: 1;
}
.pass-toggle:active { opacity: 0.7; }
.login-box button.login-submit {
  width: 100%;
  padding: 14px;
  border: none;
  border-radius: 14px;
  background: linear-gradient(135deg, var(--green) 0%, var(--green-light) 100%);
  color: white;
  font-size: 16px;
  font-weight: 700;
  cursor: pointer;
  transition: transform 0.1s;
}
.login-box button.login-submit:active { transform: scale(0.97); }
.login-box button.login-submit:disabled {
  opacity: 0.5;
  cursor: default;
}
.login-error {
  color: #c62828;
  font-size: 13px;
  font-weight: 600;
  margin-top: 12px;
  min-height: 20px;
}
'''
        login_screen_html = '''
<div class="login-screen" id="loginScreen">
  <div class="login-box">
    <div class="icon">&#128274;</div>
    <h1>Broodje Dunner</h1>
    <div class="sub">Voer het wachtwoord in om de recepten te openen</div>
    <div class="login-pass-wrap">
      <input type="password" id="loginPass" placeholder="Wachtwoord" autocomplete="off">
      <button class="pass-toggle" type="button" onclick="togglePassVis()" id="passToggle">&#128065;</button>
    </div>
    <button class="login-submit" id="loginBtn" onclick="doLogin()">Ontgrendelen</button>
    <div class="login-error" id="loginError"></div>
  </div>
</div>
'''
        decrypt_js = '''
function togglePassVis() {
  const inp = $('loginPass');
  const btn = $('passToggle');
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.innerHTML = '&#128064;';
    btn.style.opacity = '0.7';
  } else {
    inp.type = 'password';
    btn.innerHTML = '&#128065;';
    btn.style.opacity = '0.4';
  }
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

function b64toBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function decryptData(password) {
  try {
    const salt = b64toBytes(ENCRYPTED.salt);
    const iv = b64toBytes(ENCRYPTED.iv);
    const ciphertext = b64toBytes(ENCRYPTED.data);
    const key = await deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ciphertext
    );
    const text = new TextDecoder().decode(decrypted);
    return JSON.parse(text);
  } catch(e) {
    return null;
  }
}

async function doLogin() {
  const pass = $('loginPass').value;
  if (!pass) return;
  $('loginBtn').disabled = true;
  $('loginBtn').textContent = 'Ontsleutelen...';
  $('loginError').textContent = '';

  // Small delay for UI update
  await new Promise(r => setTimeout(r, 50));

  const data = await decryptData(pass);
  if (data && data.recipes) {
    R = data.recipes;
    IMGS = data.images || [];
    sessionStorage.setItem('bd_pass', pass);
    $('loginScreen').classList.add('hidden');
    renderFilters(); renderCats(); render(); updateFab();
  } else {
    $('loginError').textContent = 'Verkeerd wachtwoord. Probeer opnieuw.';
    $('loginBtn').disabled = false;
    $('loginBtn').textContent = 'Ontgrendelen';
    $('loginPass').value = '';
    $('loginPass').focus();
  }
}

async function initApp() {
  // Check sessionStorage for cached password
  const cached = sessionStorage.getItem('bd_pass');
  if (cached) {
    const data = await decryptData(cached);
    if (data && data.recipes) {
      R = data.recipes;
      IMGS = data.images || [];
      $('loginScreen').classList.add('hidden');
      renderFilters(); renderCats(); render(); updateFab();
      return;
    }
  }
  // Show login screen, set up enter key
  $('loginPass').addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });
  $('loginPass').focus();
}
'''

    html = f'''<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#2d6a4f">
<meta name="mobile-web-app-capable" content="yes">
<title>Broodje Dunner Recepten</title>
<link rel="manifest" href="data:application/json;base64,{manifest_b64}">
{f'<link rel="apple-touch-icon" href="{icon_192_uri}">' if icon_192_b64 else ''}
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }}
:root {{
  --green: #2d6a4f;
  --green-light: #40916c;
  --green-pale: #b7e4c7;
  --green-bg: #d8f3dc;
  --bg: #f0f4f0;
  --card: #ffffff;
  --text: #1b4332;
  --text-light: #52796f;
  --shadow: 0 2px 12px rgba(45,106,79,0.10);
  --radius: 16px;
}}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  padding-bottom: 80px;
  -webkit-font-smoothing: antialiased;
}}
.header {{
  background: linear-gradient(135deg, var(--green) 0%, var(--green-light) 100%);
  color: white;
  padding: 20px 16px 18px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 4px 20px rgba(0,0,0,0.15);
}}
.header h1 {{
  font-size: 22px;
  font-weight: 800;
  margin-bottom: 2px;
  letter-spacing: -0.5px;
}}
.header .subtitle {{
  font-size: 13px;
  opacity: 0.8;
  margin-bottom: 12px;
}}
.search-box {{
  position: relative;
}}
.search-box input {{
  width: 100%;
  padding: 12px 16px 12px 44px;
  border: none;
  border-radius: 12px;
  font-size: 16px;
  background: rgba(255,255,255,0.95);
  color: var(--text);
  outline: none;
  transition: box-shadow 0.2s;
}}
.search-box input:focus {{
  box-shadow: 0 0 0 3px rgba(255,255,255,0.4);
}}
.search-box input::placeholder {{ color: #95a5a6; }}
.search-icon {{
  position: absolute;
  left: 14px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 18px;
  opacity: 0.4;
}}
.filters {{
  display: flex;
  gap: 8px;
  padding: 12px 16px 0;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  scrollbar-width: none;
}}
.filters::-webkit-scrollbar {{ display: none; }}
.filter-btn {{
  flex-shrink: 0;
  padding: 7px 14px;
  border-radius: 20px;
  border: 1.5px solid var(--green-pale);
  background: white;
  color: var(--green);
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}}
.filter-btn.active {{
  background: var(--green);
  color: white;
  border-color: var(--green);
}}
.cat-tabs {{
  display: flex;
  gap: 6px;
  padding: 12px 16px 4px;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  scrollbar-width: none;
}}
.cat-tabs::-webkit-scrollbar {{ display: none; }}
.cat-tab {{
  flex-shrink: 0;
  padding: 6px 14px;
  border-radius: 16px;
  background: var(--green-bg);
  color: var(--green);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}}
.cat-tab.active {{
  background: var(--green);
  color: white;
}}
.results-count {{
  padding: 10px 16px 4px;
  font-size: 13px;
  color: var(--text-light);
  font-weight: 500;
}}
.recipe-list {{
  padding: 6px 16px;
  max-width: 600px;
  margin: 0 auto;
}}
.recipe-card {{
  background: var(--card);
  border-radius: var(--radius);
  margin-bottom: 10px;
  box-shadow: var(--shadow);
  overflow: hidden;
  transition: transform 0.1s;
}}
.recipe-card:active {{ transform: scale(0.988); }}
.card-img {{
  width: 100%;
  height: 180px;
  object-fit: cover;
  display: block;
  cursor: pointer;
  background: #e8e8e8;
}}
.card-top {{
  padding: 14px 16px 10px;
  cursor: pointer;
}}
.card-top h3 {{
  font-size: 16px;
  font-weight: 700;
  color: var(--text);
  line-height: 1.3;
  margin-bottom: 6px;
}}
.card-meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}}
.badge {{
  display: inline-block;
  padding: 2px 10px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 700;
}}
.badge-ebook {{ background: var(--green-bg); color: var(--green); }}
.badge-cat {{ background: #fff3e0; color: #e65100; }}
.badge-time {{ background: #e3f2fd; color: #1565c0; }}
.badge-portions {{ background: #f3e5f5; color: #7b1fa2; }}
.badge-vega {{ background: #e8f5e9; color: #2e7d32; }}
.detail {{
  display: none;
  padding: 0 16px 16px;
  border-top: 1px solid #eef2ee;
}}
.detail.open {{ display: block; }}
.detail-sec {{
  margin-top: 14px;
}}
.detail-sec h4 {{
  font-size: 14px;
  font-weight: 700;
  color: var(--green);
  margin-bottom: 8px;
}}
.ing-list {{
  list-style: none;
}}
.ing-list li {{
  padding: 5px 0;
  border-bottom: 1px solid #f4f7f4;
  font-size: 14px;
  display: flex;
  align-items: flex-start;
  gap: 8px;
  line-height: 1.4;
}}
.ing-list li::before {{
  content: '';
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--green-pale);
  flex-shrink: 0;
  margin-top: 7px;
}}
.step-list {{
  list-style: none;
  counter-reset: step;
}}
.step-list li {{
  padding: 6px 0;
  font-size: 14px;
  line-height: 1.5;
  display: flex;
  gap: 10px;
}}
.step-num {{
  flex-shrink: 0;
  width: 24px; height: 24px;
  border-radius: 50%;
  background: var(--green);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  margin-top: 2px;
}}
.vega-info {{
  display: inline-block;
  margin-top: 10px;
  padding: 8px 12px;
  border-radius: 10px;
  background: #e8f5e9;
  color: #2e7d32;
  font-size: 13px;
  line-height: 1.4;
}}
.add-btn {{
  width: 100%;
  padding: 10px;
  margin-top: 12px;
  border-radius: 10px;
  border: 2px dashed var(--green-pale);
  background: transparent;
  color: var(--green);
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.2s;
}}
.add-btn:active {{ background: var(--green-bg); }}
.empty {{
  text-align: center;
  padding: 60px 20px;
  color: var(--text-light);
}}
.empty .big {{ font-size: 48px; margin-bottom: 12px; }}
.empty p {{ font-size: 15px; }}
/* Shopping FAB */
.fab {{
  position: fixed;
  bottom: 20px;
  right: 16px;
  width: 56px; height: 56px;
  border-radius: 50%;
  background: var(--green);
  color: white;
  border: none;
  font-size: 24px;
  box-shadow: 0 4px 16px rgba(45,106,79,0.4);
  cursor: pointer;
  z-index: 90;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: transform 0.2s;
}}
.fab:active {{ transform: scale(0.9); }}
.fab .count {{
  position: absolute;
  top: -2px; right: -2px;
  min-width: 20px; height: 20px;
  border-radius: 10px;
  background: #e53935;
  color: white;
  font-size: 11px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 5px;
}}
/* Modal */
.overlay {{
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.45);
  z-index: 200;
  align-items: flex-end;
  justify-content: center;
}}
.overlay.open {{ display: flex; }}
.modal {{
  background: white;
  border-radius: 20px 20px 0 0;
  width: 100%;
  max-width: 500px;
  max-height: 85vh;
  overflow-y: auto;
  padding: 20px 16px;
  animation: slideUp 0.25s ease;
}}
@keyframes slideUp {{
  from {{ transform: translateY(100%); }}
  to {{ transform: translateY(0); }}
}}
.modal-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}}
.modal-header h2 {{ font-size: 18px; }}
.modal-close {{
  background: none;
  border: none;
  font-size: 28px;
  cursor: pointer;
  color: var(--text-light);
  line-height: 1;
}}
.modal-back {{
  background: none;
  border: none;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  color: var(--green);
  padding: 4px 8px;
  border-radius: 8px;
  transition: background 0.15s;
}}
.modal-back:active {{
  background: var(--green-bg);
}}
.shop-item {{
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 0;
  border-bottom: 1px solid #f4f7f4;
  font-size: 14px;
}}
.shop-item input[type=checkbox] {{
  width: 20px; height: 20px;
  accent-color: var(--green);
  flex-shrink: 0;
}}
.shop-item.done {{ opacity: 0.35; text-decoration: line-through; }}
.clear-btn {{
  width: 100%;
  padding: 12px;
  margin-top: 12px;
  border-radius: 12px;
  border: none;
  background: #ffebee;
  color: #c62828;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
}}
/* Toast notification */
.toast {{
  position: fixed;
  bottom: 86px;
  left: 50%;
  transform: translateX(-50%) translateY(20px);
  background: var(--green);
  color: white;
  padding: 12px 24px;
  border-radius: 12px;
  font-size: 14px;
  font-weight: 600;
  box-shadow: 0 4px 20px rgba(0,0,0,0.25);
  z-index: 300;
  opacity: 0;
  transition: opacity 0.3s, transform 0.3s;
  pointer-events: none;
  max-width: 90%;
  text-align: center;
}}
.toast.show {{
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}}
/* Confirm dialog */
.confirm-overlay {{
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.45);
  z-index: 400;
  align-items: center;
  justify-content: center;
}}
.confirm-overlay.open {{ display: flex; }}
.confirm-box {{
  background: white;
  border-radius: 16px;
  padding: 24px;
  max-width: 300px;
  width: 85%;
  text-align: center;
  box-shadow: 0 8px 32px rgba(0,0,0,0.2);
  animation: slideUp 0.2s ease;
}}
.confirm-box p {{
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 20px;
}}
.confirm-btns {{
  display: flex;
  gap: 10px;
}}
.confirm-btns button {{
  flex: 1;
  padding: 12px;
  border-radius: 10px;
  border: none;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
}}
.confirm-btns .cancel {{
  background: #f0f4f0;
  color: var(--text-light);
}}
.confirm-btns .danger {{
  background: #ffebee;
  color: #c62828;
}}
/* Picnic integration */
.picnic-btn {{
  width: 100%;
  padding: 12px;
  margin-top: 8px;
  border-radius: 12px;
  border: none;
  background: linear-gradient(135deg, #e8453c 0%, #ff6b5b 100%);
  color: white;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}}
.picnic-btn:disabled {{
  opacity: 0.5;
  cursor: default;
}}
.picnic-login-form {{
  padding: 16px 0;
}}
.picnic-login-form label {{
  display: block;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-light);
  margin-bottom: 4px;
  margin-top: 12px;
}}
.picnic-login-form input {{
  width: 100%;
  padding: 10px 14px;
  border: 1.5px solid #ddd;
  border-radius: 10px;
  font-size: 15px;
  outline: none;
  transition: border-color 0.2s;
}}
.picnic-login-form input:focus {{
  border-color: var(--green);
}}
.picnic-status {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  margin-top: 10px;
  border-radius: 10px;
  font-size: 13px;
  font-weight: 600;
}}
.picnic-status.ok {{ background: #e8f5e9; color: #2e7d32; }}
.picnic-status.err {{ background: #ffebee; color: #c62828; }}
.picnic-status.busy {{ background: #fff3e0; color: #e65100; }}
#picnicOverlay .modal {{
  max-height: 100vh;
  height: 100vh;
  border-radius: 0;
  max-width: 100%;
}}
.picnic-progress {{
  margin-top: 12px;
  padding: 12px;
  background: #fafafa;
  border-radius: 10px;
  font-size: 13px;
  max-height: calc(100vh - 320px);
  overflow-y: auto;
}}
.picnic-progress .item {{
  padding: 8px 0;
  border-bottom: 1px solid #eee;
}}
.picnic-progress .item:last-child {{ border-bottom: none; }}
.picnic-progress .item .row {{
  display: flex;
  align-items: center;
  gap: 8px;
}}
.picnic-progress .item.ok .row {{ color: #2e7d32; }}
.picnic-progress .item.fail .row {{ color: #c62828; }}
.picnic-progress .item.wait .row {{ color: #999; }}
.picnic-progress .item.busy .row {{ color: #e65100; }}
.picnic-progress .item.choose .row {{ color: #1565c0; }}
.picnic-choices {{
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-top: 6px;
  padding-left: 22px;
}}
.picnic-choice {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-radius: 8px;
  background: #f5f5f5;
  cursor: pointer;
  font-size: 12px;
  transition: background 0.15s;
  border: 1.5px solid transparent;
}}
.picnic-choice:active {{ background: #e8f5e9; }}
.picnic-choice .pname {{ flex: 1; font-weight: 500; }}
.picnic-choice .pprice {{ color: var(--text-light); white-space: nowrap; }}
.picnic-retry {{
  display: flex;
  gap: 6px;
  margin-top: 6px;
  padding-left: 22px;
}}
.picnic-retry input {{
  flex: 1;
  padding: 6px 10px;
  border: 1.5px solid #ddd;
  border-radius: 8px;
  font-size: 13px;
  outline: none;
}}
.picnic-retry button {{
  padding: 6px 12px;
  border-radius: 8px;
  border: none;
  background: var(--green);
  color: white;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
}}
.picnic-skip {{
  padding: 6px 12px;
  border-radius: 8px;
  border: 1.5px solid #ddd;
  background: white;
  color: var(--text-light);
  font-size: 12px;
  cursor: pointer;
  white-space: nowrap;
}}
.picnic-server-input {{
  display: flex;
  gap: 8px;
  margin-top: 8px;
}}
.picnic-server-input input {{
  flex: 1;
  padding: 8px 12px;
  border: 1.5px solid #ddd;
  border-radius: 8px;
  font-size: 13px;
}}
.picnic-server-input button {{
  padding: 8px 14px;
  border-radius: 8px;
  border: none;
  background: var(--green);
  color: white;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
}}
/* Weekmenu */
.menu-fab {{
  position: fixed;
  bottom: 20px;
  left: 16px;
  width: 56px; height: 56px;
  border-radius: 50%;
  background: #e65100;
  color: white;
  border: none;
  font-size: 22px;
  box-shadow: 0 4px 16px rgba(230,81,0,0.4);
  cursor: pointer;
  z-index: 90;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: transform 0.2s;
}}
.menu-fab:active {{ transform: scale(0.9); }}
.weekmenu-day {{
  background: white;
  border-radius: 14px;
  margin-bottom: 10px;
  box-shadow: var(--shadow);
  overflow: hidden;
}}
.weekmenu-day-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 16px;
  cursor: pointer;
}}
.weekmenu-day-header h3 {{
  font-size: 15px;
  font-weight: 700;
  color: var(--text);
}}
.weekmenu-day-header .day-badge {{
  font-size: 11px;
  font-weight: 700;
  padding: 3px 10px;
  border-radius: 10px;
  background: var(--green-bg);
  color: var(--green);
}}
.weekmenu-day-header .day-badge.today {{
  background: var(--green);
  color: white;
}}
.weekmenu-recipe {{
  padding: 0 16px 14px;
  display: flex;
  align-items: center;
  gap: 12px;
}}
.weekmenu-recipe img {{
  width: 60px; height: 60px;
  border-radius: 10px;
  object-fit: cover;
  flex-shrink: 0;
  background: #e8e8e8;
}}
.weekmenu-recipe .wm-info {{
  flex: 1;
  min-width: 0;
}}
.weekmenu-recipe .wm-name {{
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.weekmenu-recipe .wm-meta {{
  font-size: 12px;
  color: var(--text-light);
  margin-top: 2px;
}}
.weekmenu-remove {{
  background: none;
  border: none;
  font-size: 18px;
  color: #c62828;
  cursor: pointer;
  padding: 4px 8px;
  flex-shrink: 0;
}}
.weekmenu-empty {{
  padding: 0 16px 14px;
  font-size: 13px;
  color: var(--text-light);
  font-style: italic;
}}
.weekmenu-add {{
  padding: 0 16px 14px;
}}
.weekmenu-add select {{
  width: 100%;
  padding: 8px 12px;
  border: 1.5px solid var(--green-pale);
  border-radius: 10px;
  font-size: 13px;
  color: var(--text);
  background: white;
  outline: none;
}}
.weekmenu-sync {{
  margin-top: 12px;
  padding: 14px 16px;
  background: #f8f9f8;
  border-radius: 14px;
}}
.weekmenu-sync p {{
  font-size: 13px;
  color: var(--text-light);
  margin-bottom: 8px;
}}
.weekmenu-sync .sync-code {{
  display: flex;
  gap: 8px;
  align-items: center;
}}
.weekmenu-sync .sync-code input {{
  flex: 1;
  padding: 8px 12px;
  border: 1.5px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  font-family: monospace;
  text-align: center;
  outline: none;
}}
.weekmenu-sync .sync-code button {{
  padding: 8px 14px;
  border-radius: 8px;
  border: none;
  background: var(--green);
  color: white;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
}}
@media (min-width: 600px) {{
  .header {{ text-align: center; }}
  .filters, .cat-tabs {{ justify-content: center; }}
}}
{login_screen_css}
</style>
</head>
<body>
{login_screen_html}
<div class="header">
  <h1>Broodje Dunner Recepten</h1>
  <div class="subtitle" id="recipeCount"></div>
  <div class="search-box">
    <span class="search-icon">&#128269;</span>
    <input type="text" id="search" placeholder="Zoek recept of ingredi&#235;nt..." autocomplete="off">
  </div>
</div>

<div class="filters" id="filters"></div>
<div class="cat-tabs" id="cats"></div>
<div class="results-count" id="countLabel"></div>
<div class="recipe-list" id="list"></div>

<button class="fab" id="fabBtn">&#128722;<span class="count" id="fabCount" style="display:none">0</span></button>
<button class="menu-fab" id="menuFab" onclick="openWeekMenu()">&#128197;</button>

<div class="toast" id="toast"></div>

<div class="confirm-overlay" id="confirmOverlay">
  <div class="confirm-box">
    <p id="confirmMsg">Weet je het zeker?</p>
    <div class="confirm-btns">
      <button class="cancel" id="confirmNo">Annuleer</button>
      <button class="danger" id="confirmYes">Legen</button>
    </div>
  </div>
</div>

<div class="overlay" id="overlay">
  <div class="modal">
    <div class="modal-header">
      <h2>&#128722; Boodschappenlijst</h2>
      <button class="modal-close" id="modalClose">&times;</button>
    </div>
    <div id="shopList"></div>
    <button class="picnic-btn" id="picnicBtn" onclick="openPicnic()">&#128722; Naar Picnic winkelwagen</button>
    <button class="clear-btn" id="clearBtn">Lijst legen</button>
  </div>
</div>

<div class="overlay" id="picnicOverlay" style="align-items:stretch">
  <div class="modal">
    <div class="modal-header">
      <button class="modal-back" onclick="$('picnicOverlay').classList.remove('open');renderShop();$('overlay').classList.add('open')">&#8592; Terug</button>
      <h2>&#128722; Picnic</h2>
      <button class="modal-close" onclick="$('picnicOverlay').classList.remove('open')">&times;</button>
    </div>
    <div id="picnicContent">
      <div id="picnicSetup">
        <p style="font-size:14px;color:var(--text-light);margin-bottom:8px">Server URL:</p>
        <div class="picnic-server-input">
          <input type="url" id="picnicUrl" placeholder="https://jouw-server.onrender.com" value="">
          <button onclick="savePicnicUrl()">Opslaan</button>
        </div>
        <div class="picnic-login-form" id="picnicLoginForm">
          <label>Picnic e-mail</label>
          <input type="email" id="pEmail" placeholder="je@email.nl" autocomplete="email">
          <label>Wachtwoord</label>
          <input type="password" id="pPass" placeholder="Je Picnic wachtwoord" autocomplete="current-password">
          <button class="picnic-btn" style="margin-top:16px" onclick="picnicLogin()">Inloggen bij Picnic</button>
        </div>
        <div id="picnicStatus"></div>
      </div>
      <div id="picnicSend" style="display:none">
        <div class="picnic-status ok" id="picnicUser"></div>
        <p style="font-size:14px;margin:14px 0 8px;font-weight:600">Ingredi&#235;nten toevoegen aan Picnic:</p>
        <div id="picnicProgress" class="picnic-progress"></div>
        <button class="picnic-btn" style="margin-top:12px" id="picnicStartBtn" onclick="picnicAddAll()">Alles zoeken en toevoegen</button>
        <button class="picnic-btn" style="margin-top:8px;background:#f0f4f0;color:var(--text)" onclick="picnicLogout()">Uitloggen</button>
      </div>
    </div>
  </div>
</div>

<div class="overlay" id="weekMenuOverlay" style="align-items:stretch">
  <div class="modal" style="max-height:100vh;height:100vh;border-radius:0;max-width:100%">
    <div class="modal-header">
      <h2>&#128197; Weekmenu</h2>
      <button class="modal-close" onclick="$('weekMenuOverlay').classList.remove('open')">&times;</button>
    </div>
    <div id="weekMenuContent"></div>
    <div class="weekmenu-sync" id="weekMenuSync">
      <p>&#128260; Sync met partner — deel deze code:</p>
      <div class="sync-code">
        <input type="text" id="syncCode" readonly>
        <button onclick="copySyncCode()">Kopieer</button>
      </div>
      <div style="margin-top:8px">
        <p>Of voer de code van je partner in:</p>
        <div class="sync-code" style="margin-top:6px">
          <input type="text" id="syncCodeInput" placeholder="Plak code hier">
          <button onclick="applySyncCode()">Laden</button>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="overlay" id="recipeViewOverlay">
  <div class="modal" style="max-height:90vh;overflow-y:auto">
    <div class="modal-header">
      <h2>Recept</h2>
      <button class="modal-close" onclick="$('recipeViewOverlay').classList.remove('open')">&times;</button>
    </div>
    <div id="recipeViewContent" style="padding:16px"></div>
  </div>
</div>

<script>
{data_script}
let ebook = 'all';
let cat = 'all';
let q = '';
let shop = JSON.parse(localStorage.getItem('bd_shop') || '[]');
let shopRecipes = JSON.parse(localStorage.getItem('bd_shop_recipes') || '[]');

const $ = id => document.getElementById(id);

function esc(s) {{ const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }}

function saveShop() {{ localStorage.setItem('bd_shop', JSON.stringify(shop)); localStorage.setItem('bd_shop_recipes', JSON.stringify(shopRecipes)); updateFab(); }}

function updateFab() {{
  const c = $('fabCount');
  if (shop.length > 0) {{ c.style.display = 'flex'; c.textContent = shop.length; }}
  else {{ c.style.display = 'none'; }}
}}

function filtered() {{
  let f = R.map((r, idx) => ({{...r, _idx: idx}}));
  if (ebook !== 'all') f = f.filter(r => r.ebook == ebook);
  if (cat !== 'all') f = f.filter(r => r.category === cat);
  if (q) {{
    const s = q.toLowerCase();
    f = f.filter(r =>
      r.name.toLowerCase().includes(s) ||
      r.ingredients.some(i => i.toLowerCase().includes(s)) ||
      r.steps.some(st => st.toLowerCase().includes(s)) ||
      (r.vega && r.vega.toLowerCase().includes(s))
    );
  }}
  return f;
}}

function renderFilters() {{
  const ebs = [...new Set(R.map(r => r.ebook))].sort((a,b) => a-b);
  $('filters').innerHTML = [
    `<button class="filter-btn ${{ebook==='all'?'active':''}}" data-e="all">Alle</button>`,
    ...ebs.map(e => `<button class="filter-btn ${{ebook==e?'active':''}}" data-e="${{e}}">E-book ${{e}}</button>`)
  ].join('');
  $('filters').querySelectorAll('.filter-btn').forEach(b => b.onclick = () => {{
    ebook = b.dataset.e === 'all' ? 'all' : parseInt(b.dataset.e);
    renderFilters(); render();
  }});
}}

function renderCats() {{
  const cs = ['all','Ontbijt','Lunch','Diner','Tussendoortje'];
  $('cats').innerHTML = cs.map(c =>
    `<button class="cat-tab ${{cat===c?'active':''}}" data-c="${{c}}">${{c==='all'?'Alles':c}}</button>`
  ).join('');
  $('cats').querySelectorAll('.cat-tab').forEach(b => b.onclick = () => {{
    cat = b.dataset.c; renderCats(); render();
  }});
}}

function render() {{
  const recipes = filtered();
  $('countLabel').textContent = `${{recipes.length}} recept${{recipes.length!==1?'en':''}} gevonden`;
  $('recipeCount').textContent = `${{R.length}} recepten uit 7 e-books`;

  if (!recipes.length) {{
    $('list').innerHTML = '<div class="empty"><div class="big">&#129371;</div><p>Geen recepten gevonden.<br>Probeer een andere zoekterm!</p></div>';
    return;
  }}

  $('list').innerHTML = recipes.map((r, i) => `
    <div class="recipe-card">
      ${{IMGS[r._idx] ? `<img class="card-img" src="${{IMGS[r._idx]}}" alt="${{esc(r.name)}}" onclick="toggle(${{i}})" loading="lazy">` : ''}}
      <div class="card-top" onclick="toggle(${{i}})">
        <h3>${{esc(r.name)}}</h3>
        <div class="card-meta">
          <span class="badge badge-ebook">E-book ${{r.ebook}}</span>
          <span class="badge badge-cat">${{r.category}}</span>
          ${{r.time ? `<span class="badge badge-time">&#9201; ${{esc(r.time)}}</span>` : ''}}
          ${{r.portions ? `<span class="badge badge-portions">&#127860; ${{r.portions}}p</span>` : ''}}
          ${{r.vega ? '<span class="badge badge-vega">&#127793; Vega</span>' : ''}}
        </div>
      </div>
      <div class="detail" id="d${{i}}">
        ${{r.ingredients.length ? `
        <div class="detail-sec">
          <h4>&#129367; Ingredi&euml;nten</h4>
          <ul class="ing-list">
            ${{r.ingredients.map(ing => `<li>${{esc(ing)}}</li>`).join('')}}
          </ul>
          <button class="add-btn" onclick="addShop(${{i}});event.stopPropagation()">+ Toevoegen aan boodschappenlijst</button>
        </div>` : ''}}
        ${{r.steps.length ? `
        <div class="detail-sec">
          <h4>&#128293; Bereiding</h4>
          <div class="step-list">
            ${{r.steps.map((s, si) => `<div style="display:flex;gap:10px;padding:6px 0"><span class="step-num">${{si+1}}</span><span style="line-height:1.5">${{esc(s)}}</span></div>`).join('')}}
          </div>
        </div>` : ''}}
        ${{r.vega ? `<div class="vega-info">&#127793; ${{esc(r.vega)}}</div>` : ''}}
      </div>
    </div>`).join('');
}}

function toggle(i) {{
  const el = $('d'+i);
  el.classList.toggle('open');
}}

function showToast(msg) {{
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 2200);
}}

function addShop(i) {{
  const r = filtered()[i];
  const origIdx = r._idx;
  let added = 0;
  r.ingredients.forEach(ing => {{
    if (!shop.includes(ing)) {{ shop.push(ing); added++; }}
  }});
  // Track which recipe was added to shopping list (for weekmenu)
  if (!shopRecipes.includes(origIdx)) shopRecipes.push(origIdx);
  saveShop();
  if (added > 0) showToast(added + ' ingredi\\u00ebnt' + (added>1?'en':'') + ' toegevoegd!');
  else showToast('Alle ingredi\\u00ebnten staan al op je lijst');
}}

function renderShop() {{
  if (!shop.length) {{
    $('shopList').innerHTML = '<p style="text-align:center;padding:30px 0;color:var(--text-light)">Je boodschappenlijst is leeg.<br>Open een recept en voeg ingredi\\u00ebnten toe!</p>';
    return;
  }}
  $('shopList').innerHTML = shop.map((item, i) =>
    `<div class="shop-item" id="si${{i}}"><input type="checkbox" onchange="this.parentElement.classList.toggle('done')"><span>${{esc(item)}}</span></div>`
  ).join('');
}}

$('search').addEventListener('input', e => {{ q = e.target.value; render(); }});

$('fabBtn').onclick = () => {{ renderShop(); $('overlay').classList.add('open'); }};
$('modalClose').onclick = () => $('overlay').classList.remove('open');
$('overlay').onclick = e => {{ if (e.target === e.currentTarget) $('overlay').classList.remove('open'); }};
$('clearBtn').onclick = () => {{
  if (!shop.length) return;
  $('confirmOverlay').classList.add('open');
}};
$('confirmNo').onclick = () => $('confirmOverlay').classList.remove('open');
$('confirmYes').onclick = () => {{
  shop = []; shopRecipes = []; saveShop(); renderShop();
  $('confirmOverlay').classList.remove('open');
  showToast('Boodschappenlijst geleegd');
}};

// Picnic integration
let picnicUrl = localStorage.getItem('bd_picnic_url') || '';
let picnicSession = localStorage.getItem('bd_picnic_session') || '';

function savePicnicUrl() {{
  picnicUrl = $('picnicUrl').value.replace(/\\/+$/, '');
  localStorage.setItem('bd_picnic_url', picnicUrl);
  showToast('Server URL opgeslagen');
}}

function getUncheckedItems() {{
  // Get items from shopping list that are NOT checked off
  const unchecked = [];
  const items = document.querySelectorAll('.shop-item');
  items.forEach((el, i) => {{
    if (!el.classList.contains('done') && shop[i]) {{
      unchecked.push(shop[i]);
    }}
  }});
  // Fallback: if modal wasn't rendered yet, return all
  return unchecked.length > 0 || items.length > 0 ? unchecked : shop;
}}

function openPicnic() {{
  if (!shop.length) {{ showToast('Je boodschappenlijst is leeg'); return; }}
  const unchecked = getUncheckedItems();
  if (!unchecked.length) {{ showToast('Alle items zijn al afgevinkt'); return; }}
  window._picnicShopItems = unchecked;
  $('overlay').classList.remove('open');
  $('picnicUrl').value = picnicUrl;
  if (picnicSession) {{
    $('picnicSetup').style.display = 'none';
    $('picnicSend').style.display = 'block';
    $('picnicUser').textContent = '\\u2713 Ingelogd bij Picnic';
    renderPicnicItems();
  }} else {{
    $('picnicSetup').style.display = 'block';
    $('picnicSend').style.display = 'none';
  }}
  $('picnicOverlay').classList.add('open');
}}

async function picnicLogin() {{
  const email = $('pEmail').value.trim();
  const pass = $('pPass').value;
  if (!email || !pass) {{ showStatus('Vul e-mail en wachtwoord in', 'err'); return; }}
  if (!picnicUrl) {{ showStatus('Stel eerst de server URL in', 'err'); return; }}
  showStatus('Inloggen...', 'busy');
  try {{
    const res = await fetch(picnicUrl + '/api/login', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: email, password: pass}})
    }});
    const data = await res.json();
    if (data.success) {{
      picnicSession = data.sessionKey;
      localStorage.setItem('bd_picnic_session', picnicSession);
      $('picnicSetup').style.display = 'none';
      $('picnicSend').style.display = 'block';
      $('picnicUser').textContent = '\\u2713 Ingelogd als ' + email;
      renderPicnicItems();
    }} else {{
      showStatus(data.error || 'Login mislukt', 'err');
    }}
  }} catch(e) {{
    showStatus('Kan server niet bereiken. Check de URL.', 'err');
  }}
}}

function picnicLogout() {{
  picnicSession = '';
  localStorage.removeItem('bd_picnic_session');
  $('picnicOverlay').classList.remove('open');
  showToast('Uitgelogd bij Picnic');
}}

function showStatus(msg, type) {{
  $('picnicStatus').innerHTML = `<div class="picnic-status ${{type}}">${{msg}}</div>`;
}}

function cleanIngredient(ing) {{
  let s = ing;
  // Remove bracketed text like (Santa Maria), (1 blik), (ongekookt)
  s = s.replace(/\\(.*?\\)/g, '');
  // Remove quantities at END: "200 gram", "4 stuks", "1 el", "1/2 tl", "halve", "1 stuk"
  s = s.replace(/\\s+\\d+[\\.,\\/]?\\d*\\s*(gram|gr|g|ml|liter|l|el|tl|stuks?|blik(je)?|plak(ken)?|teen(tje)?|snufje|handje?|hele|zakje|potje|stengel|bundel|bos|bol|blaad(jes)?|blad(eren)?|vellen?|sprieten?|streng(en)?|trosje|koekje|druppels?|beker|bakje|eetlepel|theelepel|schijfjes?|cm|grote?|stengels?)\\s*$/i, '');
  // Remove trailing amounts like "100 gram", "2 stuks" without unit word
  s = s.replace(/\\s+\\d+[\\.,\\/]?\\d*\\s*$/i, '');
  // Remove trailing words: Halve, Handje, Naar wens, Naar smaak, Een halve, Grote hand
  s = s.replace(/\\s+(Halve|halve|Een halve|Handje|handje|Grote hand|Naar wens!?|Naar smaak!?)\\s*$/i, '');
  // Remove leading "- " (tips/notes that slipped through)
  s = s.replace(/^-\\s+/, '');
  // Remove quantities at START: "1 tl", "100 gram", "15 ml"
  s = s.replace(/^\\d+[\\.,\\/]?\\d*\\s*(gram|gr|g|ml|liter|l|el|tl|stuks?|blik(je)?|plak(ken)?|teen(tje)?|snufje|handje|halve|hele|zakje|potje)\\b\\s*/i, '');
  // Remove leading count words
  s = s.replace(/^(een|twee|drie|vier|vijf|zes|half|halve|kwart)\\s+/i, '');
  // Remove "half zakje" type prefixes
  s = s.replace(/^half\\s+(zakje|blikje|stuk)\\s*/i, '');
  // Remove trailing "half zakje" / "halve" etc.
  s = s.replace(/\\s+(half|halve)\\s+(zakje|blikje|stuk)\\s*$/i, '');
  // Clean up double spaces
  s = s.replace(/\\s{{2,}}/g, ' ');
  s = s.trim();
  // If nothing useful left, return original
  if (s.length < 2) return ing;
  return s;
}}

function renderPicnicItems() {{
  const shopItems = window._picnicShopItems || shop;
  const existing = window._picnicItems || [];

  // Build map of existing items to preserve their state
  const existingMap = {{}};
  existing.forEach(it => {{ existingMap[it.original] = it; }});

  // Build new list: reuse existing state where available
  const items = shopItems.map(ing => {{
    if (existingMap[ing]) return existingMap[ing];
    return {{
      original: ing,
      search: cleanIngredient(ing),
      status: 'wait',
      products: [],
      result: ''
    }};
  }});

  window._picnicItems = items;
  // Recalculate counters from actual item statuses
  window._picnicAdded = items.filter(it => it.status === 'ok').length;
  window._picnicFailed = items.filter(it => it.status === 'skip' || it.status === 'fail').length;
  updatePicnicProgress();
}}

function formatPrice(p) {{
  if (!p) return '';
  const euros = typeof p === 'number' ? (p / 100).toFixed(2) : p;
  return '\\u20AC' + euros;
}}

function updatePicnicProgress() {{
  const items = window._picnicItems || [];
  $('picnicProgress').innerHTML = items.map((it, i) => {{
    const icon = it.status === 'ok' ? '\\u2713' : it.status === 'fail' ? '\\u2717' : it.status === 'busy' ? '\\u23F3' : it.status === 'choose' ? '\\u2B07' : it.status === 'skip' ? '\\u2015' : '\\u25CB';
    let extra = '';

    if (it.status === 'choose' && it.products.length > 0) {{
      extra = `<div class="picnic-choices">
        ${{it.products.slice(0, 5).map((p, pi) =>
          `<div class="picnic-choice" onclick="picnicChoose(${{i}},${{pi}})">
            <span class="pname">${{esc(p.name)}}</span>
            ${{p.unit ? `<span style="opacity:0.5;font-size:11px">${{esc(p.unit)}}</span>` : ''}}
            <span class="pprice">${{formatPrice(p.price)}}</span>
          </div>`
        ).join('')}}
      </div>`;
    }}

    if (it.status === 'fail') {{
      extra = `<div class="picnic-retry">
        <input type="text" value="${{esc(it.search)}}" id="retry${{i}}" placeholder="Andere zoekterm...">
        <button onclick="picnicRetry(${{i}})">Zoek</button>
        <button class="picnic-skip" onclick="picnicSkipItem(${{i}})">Sla over</button>
      </div>`;
    }}

    return `<div class="item ${{it.status}}">
      <div class="row">
        <span>${{icon}}</span>
        <span style="flex:1">${{esc(it.original)}}</span>
        ${{it.result ? `<span style="opacity:0.6;font-size:11px">${{esc(it.result)}}</span>` : ''}}
      </div>
      ${{extra}}
    </div>`;
  }}).join('');
}}

async function picnicSearchItem(idx, query) {{
  const items = window._picnicItems;
  items[idx].status = 'busy';
  items[idx].search = query;
  updatePicnicProgress();

  try {{
    const sRes = await fetch(picnicUrl + '/api/search?q=' + encodeURIComponent(query), {{
      headers: {{'x-session-key': picnicSession}}
    }});

    if (sRes.status === 401) {{
      picnicSession = '';
      localStorage.removeItem('bd_picnic_session');
      showToast('Sessie verlopen, log opnieuw in');
      $('picnicSetup').style.display = 'block';
      $('picnicSend').style.display = 'none';
      return 'expired';
    }}

    const sData = await sRes.json();
    const products = (sData.products || []);

    if (products.length === 0) {{
      items[idx].status = 'fail';
      items[idx].result = 'Niet gevonden - probeer andere zoekterm';
      items[idx].products = [];
    }} else if (products.length === 1) {{
      // Only 1 result: add directly
      return await picnicAddProduct(idx, products[0]);
    }} else {{
      // Multiple results: let user choose
      items[idx].status = 'choose';
      items[idx].result = products.length + ' resultaten - kies er een';
      items[idx].products = products;
    }}
  }} catch(e) {{
    items[idx].status = 'fail';
    items[idx].result = 'Server niet bereikbaar';
    items[idx].products = [];
  }}
  updatePicnicProgress();
  return items[idx].status;
}}

async function picnicAddProduct(idx, product) {{
  const items = window._picnicItems;
  try {{
    const aRes = await fetch(picnicUrl + '/api/cart/add', {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/json',
        'x-session-key': picnicSession
      }},
      body: JSON.stringify({{ productId: product.id, quantity: 1 }})
    }});

    if (aRes.ok) {{
      items[idx].status = 'ok';
      items[idx].result = product.name;
      window._picnicAdded++;
      updatePicnicProgress();
      return 'ok';
    }} else {{
      items[idx].status = 'fail';
      items[idx].result = 'Toevoegen mislukt - probeer opnieuw';
      updatePicnicProgress();
      return 'fail';
    }}
  }} catch(e) {{
    items[idx].status = 'fail';
    items[idx].result = 'Fout bij toevoegen';
    updatePicnicProgress();
    return 'fail';
  }}
}}

async function picnicChoose(itemIdx, productIdx) {{
  const items = window._picnicItems;
  const product = items[itemIdx].products[productIdx];
  items[itemIdx].status = 'busy';
  items[itemIdx].result = 'Toevoegen...';
  updatePicnicProgress();
  await picnicAddProduct(itemIdx, product);
  checkPicnicDone();
}}

async function picnicRetry(idx) {{
  const input = document.getElementById('retry' + idx);
  const query = input ? input.value.trim() : '';
  if (!query) return;
  await picnicSearchItem(idx, query);
  checkPicnicDone();
}}

function picnicSkipItem(idx) {{
  const items = window._picnicItems;
  items[idx].status = 'skip';
  items[idx].result = 'Overgeslagen';
  window._picnicFailed++;
  updatePicnicProgress();
  checkPicnicDone();
}}

function checkPicnicDone() {{
  const items = window._picnicItems || [];
  const pending = items.filter(it => it.status === 'wait' || it.status === 'busy').length;
  if (pending === 0) {{
    const waiting = items.filter(it => it.status === 'choose' || it.status === 'fail').length;
    if (waiting === 0) {{
      const a = window._picnicAdded;
      const s = items.filter(it => it.status === 'skip').length;
      showToast(`${{a}} producten toegevoegd aan Picnic` + (s > 0 ? `, ${{s}} overgeslagen` : ''));
    }}
  }}
}}

async function picnicAddAll() {{
  const items = window._picnicItems || [];
  if (!items.length) return;
  if (!picnicUrl || !picnicSession) {{ showToast('Log eerst in bij Picnic'); return; }}

  $('picnicStartBtn').disabled = true;
  $('picnicStartBtn').textContent = 'Bezig met zoeken...';
  window._picnicAdded = 0;
  window._picnicFailed = 0;

  for (let i = 0; i < items.length; i++) {{
    if (items[i].status !== 'wait') continue;
    const result = await picnicSearchItem(i, items[i].search);
    if (result === 'expired') return;
    await new Promise(r => setTimeout(r, 300));
  }}

  $('picnicStartBtn').disabled = false;

  // Check if there are items needing attention
  const needsAttention = items.filter(it => it.status === 'choose' || it.status === 'fail').length;
  if (needsAttention > 0) {{
    $('picnicStartBtn').textContent = needsAttention + ' product' + (needsAttention > 1 ? 'en' : '') + ' nodig actie';
  }} else {{
    $('picnicStartBtn').textContent = 'Alles zoeken en toevoegen';
    const a = window._picnicAdded;
    showToast(`Klaar! ${{a}} producten toegevoegd aan Picnic`);
  }}
}}

// Weekmenu
let weekMenu = JSON.parse(localStorage.getItem('bd_weekmenu') || '{{}}');

function getWeekDays() {{
  const days = ['Zondag','Maandag','Dinsdag','Woensdag','Donderdag','Vrijdag','Zaterdag'];
  const today = new Date();
  // Start from today, show 7 days
  const result = [];
  for (let i = 0; i < 7; i++) {{
    const d = new Date(today);
    d.setDate(today.getDate() + i);
    const key = d.toISOString().split('T')[0]; // YYYY-MM-DD
    const dayName = days[d.getDay()];
    const label = i === 0 ? 'Vandaag' : i === 1 ? 'Morgen' : dayName;
    const dateStr = d.getDate() + '/' + (d.getMonth() + 1);
    result.push({{ key, dayName, label, dateStr, isToday: i === 0 }});
  }}
  return result;
}}

function saveWeekMenu() {{
  localStorage.setItem('bd_weekmenu', JSON.stringify(weekMenu));
}}

function openWeekMenu() {{
  renderWeekMenu();
  $('weekMenuOverlay').classList.add('open');
}}

function renderWeekMenu() {{
  const days = getWeekDays();
  // Clean old entries (older than today)
  const todayKey = days[0].key;
  for (const k of Object.keys(weekMenu)) {{
    if (k < todayKey) delete weekMenu[k];
  }}
  saveWeekMenu();

  // Build recipe options for dropdown — only recipes added to shopping list
  const recipeOpts = shopRecipes.map(i => R[i] ? `<option value="${{i}}">${{esc(R[i].name)}} (E${{R[i].ebook}})</option>` : '').join('');

  $('weekMenuContent').innerHTML = days.map(day => {{
    const recipeIdx = weekMenu[day.key];
    const hasRecipe = recipeIdx !== undefined && recipeIdx !== null && R[recipeIdx];
    const recipe = hasRecipe ? R[recipeIdx] : null;
    const img = hasRecipe && IMGS[recipeIdx] ? IMGS[recipeIdx] : '';

    return `<div class="weekmenu-day">
      <div class="weekmenu-day-header">
        <h3>${{day.label}} <span style="font-weight:400;color:var(--text-light);font-size:12px">${{day.dateStr}}</span></h3>
        <span class="day-badge ${{day.isToday ? 'today' : ''}}">${{day.dayName}}</span>
      </div>
      ${{hasRecipe ? `
        <div class="weekmenu-recipe">
          ${{img ? `<img src="${{img}}" alt="">` : ''}}
          <div class="wm-info">
            <div class="wm-name">${{esc(recipe.name)}}</div>
            <div class="wm-meta">${{recipe.category}}${{recipe.time ? ' \\u2022 ' + recipe.time : ''}}${{recipe.portions ? ' \\u2022 ' + recipe.portions + 'p' : ''}}</div>
          </div>
          <button class="weekmenu-remove" onclick="removeFromMenu('${{day.key}}')" title="Verwijder">\\u2717</button>
        </div>
        <div class="weekmenu-add" style="padding-top:0">
          <button class="add-btn" onclick="showMenuRecipe('${{day.key}}')" style="font-size:12px;padding:8px">Recept weergeven</button>
        </div>
      ` : `
        <div class="weekmenu-add">
          ${{recipeOpts ? `
            <select onchange="assignRecipe('${{day.key}}', this.value)">
              <option value="">Kies een recept...</option>
              ${{recipeOpts}}
            </select>
          ` : `<p style="color:var(--text-light);font-size:13px;text-align:center;padding:8px 0">Voeg eerst recepten toe aan je boodschappenlijst</p>`}}
        </div>
      `}}
    </div>`;
  }}).join('');

  // Update sync code
  updateSyncCode();
}}

function assignRecipe(dayKey, recipeIdx) {{
  if (recipeIdx === '') return;
  weekMenu[dayKey] = parseInt(recipeIdx);
  saveWeekMenu();
  renderWeekMenu();
}}

function removeFromMenu(dayKey) {{
  delete weekMenu[dayKey];
  saveWeekMenu();
  renderWeekMenu();
}}

function showMenuRecipe(dayKey) {{
  const recipeIdx = weekMenu[dayKey];
  if (recipeIdx === undefined || !R[recipeIdx]) return;
  const r = R[recipeIdx];
  const img = IMGS[recipeIdx] || '';
  $('recipeViewContent').innerHTML = `
    ${{img ? `<img src="${{img}}" style="width:100%;max-height:220px;object-fit:cover;border-radius:12px;margin-bottom:12px">` : ''}}
    <h2 style="margin-bottom:4px">${{esc(r.name)}}</h2>
    <div style="color:var(--text-light);font-size:13px;margin-bottom:16px">${{r.category}}${{r.time ? ' \\u2022 ' + r.time : ''}}${{r.portions ? ' \\u2022 ' + r.portions + 'p' : ''}}</div>
    ${{r.ingredients.length ? `
    <h4 style="margin-bottom:8px">&#129379; Ingredi&euml;nten</h4>
    <ul style="margin-bottom:16px;padding-left:20px">${{r.ingredients.map(i => `<li style="padding:3px 0">${{esc(i)}}</li>`).join('')}}</ul>
    ` : ''}}
    ${{r.steps.length ? `
    <h4 style="margin-bottom:8px">&#128293; Bereiding</h4>
    <div>${{r.steps.map((s, si) => `<div style="display:flex;gap:10px;padding:6px 0"><span class="step-num">${{si+1}}</span><span style="line-height:1.5">${{esc(s)}}</span></div>`).join('')}}</div>
    ` : ''}}
  `;
  $('recipeViewOverlay').classList.add('open');
}}

function updateSyncCode() {{
  // Encode weekmenu as compact shareable string
  const data = JSON.stringify(weekMenu);
  const code = btoa(unescape(encodeURIComponent(data)));
  $('syncCode').value = code;
}}

function copySyncCode() {{
  const code = $('syncCode').value;
  if (navigator.clipboard) {{
    navigator.clipboard.writeText(code).then(() => showToast('Code gekopieerd!'));
  }} else {{
    $('syncCode').select();
    document.execCommand('copy');
    showToast('Code gekopieerd!');
  }}
}}

function applySyncCode() {{
  const code = $('syncCodeInput').value.trim();
  if (!code) {{ showToast('Plak eerst een code'); return; }}
  try {{
    const data = JSON.parse(decodeURIComponent(escape(atob(code))));
    if (typeof data === 'object') {{
      weekMenu = data;
      saveWeekMenu();
      renderWeekMenu();
      showToast('Weekmenu geladen van partner!');
      $('syncCodeInput').value = '';
    }} else {{
      showToast('Ongeldige code');
    }}
  }} catch(e) {{
    showToast('Ongeldige code');
  }}
}}

{decrypt_js}
{init_call}
</script>
</body>
</html>'''

    return html


def main():
    import sys
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    print("Broodje Dunner Recepten Extractor")
    print("=" * 40)

    all_recipes = []

    # Map filenames to ebook numbers
    pdf_files = []
    for fname in os.listdir(FOLDER):
        if fname.lower().endswith('.pdf'):
            # Extract ebook number from filename
            match = re.search(r'(\d+)', fname)
            if match:
                num = int(match.group(1))
                pdf_files.append((os.path.join(FOLDER, fname), num))

    pdf_files.sort(key=lambda x: x[1])

    for path, ebook_num in pdf_files:
        print(f"\nVerwerking E-book {ebook_num}: {os.path.basename(path)}")
        recipes = extract_recipes_from_ebook(path, ebook_num)
        print(f"  -> {len(recipes)} recepten gevonden")
        for r in recipes:
            print(f"     - {r['name']} ({len(r['ingredients'])} ing, {len(r['steps'])} stappen)")
        all_recipes.extend(recipes)

    # Deduplicate
    before = len(all_recipes)
    all_recipes = deduplicate_recipes(all_recipes)
    print(f"\nTotaal: {before} recepten, {len(all_recipes)} na deduplicatie")

    # Sort by ebook then name
    all_recipes.sort(key=lambda r: (r['ebook'], r['name']))

    # Get password for encryption
    password = get_password()
    if password:
        print(f"\n🔒 Wachtwoordbeveiliging ACTIEF — recepten worden versleuteld")
    else:
        print(f"\n⚠️  Geen wachtwoord gevonden! Maak een .env bestand met APP_PASSWORD=jouwwachtwoord")
        print(f"   Of stel environment variable APP_PASSWORD in.")

    # Build HTML
    html = build_html(all_recipes, password=password)

    output_path = os.path.join(FOLDER, 'recepten_app.html')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\nApp gegenereerd: {output_path}")
    print(f"Totaal {len(all_recipes)} unieke recepten uit 7 e-books!")
    print("\nGebruik:")
    print("1. Open het bestand in Chrome op je Android telefoon")
    print("2. Tik op de 3 puntjes rechtsbovenin")
    print("3. Kies 'Toevoegen aan startscherm'")
    print("4. Nu heb je een app-achtige ervaring!")
    print("5. Deel het bestand met je huisgenoot (via WhatsApp/email)")


if __name__ == '__main__':
    main()
