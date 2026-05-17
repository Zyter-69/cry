"""
cryptolab_gui.py
────────────────────────────────────────────────────────────────────────────
CryptoLab — Suite Cryptographique Complète
Palette : noir profond ↔ violet sombre

Sections :
  • Tableau de bord
  • Chiffrement Classique  (César, Vigenère, Hill, OTP)
  • Chiffrement Symétrique (RC4, DES/3DES, AES)
  • Chiffrement Asymétrique(RSA, Diffie-Hellman, ElGamal, ECC)
  • Hachage               (MD5, SHA-256, SHA-512, HMAC)
  • Signatures Numériques  (RSA-PSS, ElGamal, DSA/ECDSA)
  • Communications Sécurisées (TCP, Bluetooth, UDP Chat, Vote)

Lancement : python cryptolab_gui.py
────────────────────────────────────────────────────────────────────────────
"""
import os, sys, time, hashlib, struct, secrets, threading, socket, queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ROOT)
# Ensure every subpackage folder is on sys.path and has __init__.py
for _sub in ("classical", "symmetric", "asymmetric", "hashing", "protocols", "utils"):
    _sp = os.path.join(_ROOT, _sub)
    if os.path.isdir(_sp):
        if _sp not in sys.path:
            sys.path.insert(0, _sp)
        _init = os.path.join(_sp, "__init__.py")
        if not os.path.exists(_init):
            open(_init, "w").close()

# ── pycryptodome ──────────────────────────────────────────────────────────────
try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

# ── Paillier ──────────────────────────────────────────────────────────────────
_PAILLIER = False
Paillier   = None
for _p in ("protocols.homomorphic", "homomorphic"):
    try:
        import importlib as _il
        _m = _il.import_module(_p)
        Paillier  = _m.Paillier
        _PAILLIER = True
        break
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════
# PALETTE & FONTS
# ═══════════════════════════════════════════════════════════════════════════
K   = "#07000d"   # background
S   = "#0d0120"   # sidebar
C   = "#130126"   # card
H   = "#1a002e"   # section header
A   = "#6d28d9"   # accent violet
B   = "#8b5cf6"   # violet light
G   = "#a78bfa"   # lavender
D   = "#2e1065"   # border
T   = "#ede9f6"   # primary text
DIM = "#9370b8"   # secondary text
MUT = "#4c2880"   # muted text
OK  = "#34d399"   # green success
ERR = "#f87171"   # red error
WRN = "#fbbf24"   # amber warning
INP = "#160030"   # input background
SEL = "#3b0764"   # selected / highlight

FM  = ("Courier",   10)
FB  = ("Helvetica", 10)
FBB = ("Helvetica", 10, "bold")
FT  = ("Helvetica", 13, "bold")
FH  = ("Helvetica", 16, "bold")
FS  = ("Helvetica",  9)

TCP_PORT      = 19876
UDP_PORT_BASE = 19900


def now() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════
# CRYPTO HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def aes_enc(data: bytes, key: bytes):
    if _CRYPTO:
        nonce = secrets.token_bytes(16)
        c     = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = c.encrypt_and_digest(data)
        return ct, nonce, tag
    ks = hashlib.sha256(key).digest()
    ct = bytes(b ^ ks[i % 32] for i, b in enumerate(data))
    return ct, b"\x00"*16, b"\x00"*16


def aes_dec(ct, key, nonce, tag):
    if _CRYPTO:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    ks = hashlib.sha256(key).digest()
    return bytes(b ^ ks[i % 32] for i, b in enumerate(ct))


def rsa_keygen(bits=2048):
    if _CRYPTO:
        k = RSA.generate(bits)
        return k, k.publickey()
    return None, None


def rsa_enc(data, pub):
    if _CRYPTO and pub:
        return PKCS1_OAEP.new(pub).encrypt(data)
    return data


def rsa_dec(data, priv):
    if _CRYPTO and priv:
        return PKCS1_OAEP.new(priv).decrypt(data)
    return data


def _send_frame(s, data):
    s.sendall(struct.pack("!I", len(data)) + data)


def _recv_frame(s):
    def _exact(n):
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c: return b""
            buf += c
        return buf
    raw = _exact(4)
    if not raw: return b""
    return _exact(struct.unpack("!I", raw)[0])


# ═══════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _append(w: tk.Text, line: str, tag: str = ""):
    w.configure(state="normal")
    w.insert("end", line + "\n", tag)
    w.see("end")
    w.configure(state="disabled")


def _clear(w: tk.Text):
    w.configure(state="normal")
    w.delete("1.0", "end")
    w.configure(state="disabled")


def _log(parent, height=10, tags=None) -> tk.Text:
    w = tk.Text(parent, bg=S, fg=T, font=FM, bd=0, state="disabled",
                wrap="word", padx=8, pady=8, height=height,
                selectbackground=D, selectforeground=T)
    default_tags = {"ok": OK, "err": ERR, "warn": WRN, "info": G,
                    "sent": B, "recv": OK, "sys": WRN, "crypto": G,
                    "key": G, "hash": B, "sig": OK, "dim": DIM}
    if tags:
        default_tags.update(tags)
    for name, color in default_tags.items():
        w.tag_config(name, foreground=color)
    return w


def _entry(parent, var, width=None, **kw):
    e = tk.Entry(parent, textvariable=var, bg=INP, fg=T,
                 insertbackground=T, bd=0, font=FB, relief="flat",
                 highlightbackground=D, highlightthickness=1, **kw)
    if width:
        e.configure(width=width)
    return e


def _btn(parent, text, cmd, accent=A, fg=T, **kw):
    return tk.Button(parent, text=text, command=cmd,
                     bg=accent, fg=fg, font=FBB, bd=0, relief="flat",
                     padx=12, pady=6, activebackground=B,
                     activeforeground=T, cursor="hand2", **kw)


def _label(parent, text, font=FS, fg=DIM, **kw):
    return tk.Label(parent, text=text, font=font, bg=C, fg=fg, **kw)


def _card(parent, padx=0, pady=0, **kw):
    return tk.Frame(parent, bg=C, highlightbackground=D,
                    highlightthickness=1, **kw)


def _bar(parent, color=A, **kw):
    f = tk.Frame(parent, bg=color, padx=14, pady=10, **kw)
    return f


def _sep(parent):
    return tk.Frame(parent, bg=D, height=1)


def _section_hdr(parent, icon, title, subtitle):
    hdr = tk.Frame(parent, bg=H, padx=30, pady=18)
    hdr.pack(fill="x")
    tk.Label(hdr, text=f"{icon}  {title}", font=FT, bg=H, fg=T).pack(anchor="w")
    tk.Label(hdr, text=subtitle, font=FS, bg=H, fg=DIM).pack(anchor="w")
    return hdr


def _combo(parent, var, values, **kw):
    return ttk.Combobox(parent, textvariable=var, values=values,
                        state="readonly", font=FB, **kw)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    NAV = [
        ("🏠", "Accueil",            "dash"),
        ("📜", "Classique",          "classic"),
        ("🔒", "Symétrique",         "symmetric"),
        ("🗝",  "Asymétrique",        "asymmetric"),
        ("#",  "Hachage",            "hash"),
        ("✍",  "Signatures",         "signature"),
        ("🌐", "Communications",     "comms"),
    ]

    def __init__(self):
        super().__init__()
        self.title("CryptoLab — Suite Cryptographique Complète")
        self.geometry("1300x800")
        self.minsize(1050, 680)
        self.configure(bg=K)
        self._ttk_style()
        self._build()
        self.show("dash")

    def _ttk_style(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        for w in ("TCombobox",):
            st.configure(w, fieldbackground=INP, background=C,
                         foreground=T, selectbackground=A,
                         selectforeground=T, arrowcolor=DIM,
                         bordercolor=D, lightcolor=D, darkcolor=D)
            st.map(w, fieldbackground=[("readonly", INP)],
                   foreground=[("readonly", T)])

    def _build(self):
        # sidebar
        sb = tk.Frame(self, bg=S, width=200)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        lf = tk.Frame(sb, bg=S, pady=20)
        lf.pack(fill="x")
        tk.Label(lf, text="🔐", font=("Helvetica", 28), bg=S, fg=B).pack()
        tk.Label(lf, text="CryptoLab", font=FT, bg=S, fg=T).pack()
        tk.Label(lf, text="Suite Cryptographique",
                 font=FS, bg=S, fg=DIM).pack(pady=(2, 0))

        _sep(sb).pack(fill="x", padx=16, pady=6)

        self._nav: dict[str, tk.Button] = {}
        for icon, label, key in self.NAV:
            b = tk.Button(sb, text=f"  {icon}  {label}", anchor="w",
                          font=FB, bg=S, fg=DIM,
                          activebackground=C, activeforeground=T,
                          bd=0, relief="flat", pady=10, padx=14,
                          cursor="hand2",
                          command=lambda k=key: self.show(k))
            b.pack(fill="x")
            self._nav[key] = b

        _sep(sb).pack(fill="x", padx=16, pady=6, side="bottom")
        self._stlbl = tk.Label(sb, text="Prêt", font=FS, bg=S, fg=DIM)
        self._stlbl.pack(side="bottom", anchor="w", padx=14, pady=(0, 4))
        tk.Label(sb, text="● Système", font=FS, bg=S, fg=OK).pack(
            side="bottom", anchor="w", padx=14)

        self._content = tk.Frame(self, bg=K)
        self._content.pack(side="left", fill="both", expand=True)

        pages = [
            ("dash",       Dashboard),
            ("classic",    ClassicSection),
            ("symmetric",  SymmetricSection),
            ("asymmetric", AsymmetricSection),
            ("hash",       HashSection),
            ("signature",  SignatureSection),
            ("comms",      CommsSection),
        ]
        self._frames = {}
        for key, cls in pages:
            f = cls(self._content, self)
            f.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._frames[key] = f

    def show(self, key: str):
        for k, b in self._nav.items():
            b.configure(bg=C if k == key else S,
                        fg=B if k == key else DIM)
        for k, f in self._frames.items():
            (f.lift if k == key else f.lower)()

    def set_status(self, msg: str, color: str = DIM):
        self._stlbl.configure(text=msg, fg=color)


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════

class Dashboard(tk.Frame):
    CARDS = [
        ("📜", "Chiffrement Classique",
         "César · Vigenère · Hill · OTP\nAnalyse fréquentielle · Kasiski · IC",
         "classic", "#3b0764"),
        ("🔒", "Chiffrement Symétrique",
         "RC4 · DES / 3DES · AES-128/192/256\nModes ECB · CBC · CTR · GCM",
         "symmetric", "#1e1065"),
        ("🗝", "Chiffrement Asymétrique",
         "RSA · Diffie-Hellman · ElGamal · ECC\nOAEP · ECIES · ECDH",
         "asymmetric", "#065f46"),
        ("#",  "Fonctions de Hachage",
         "MD5 · SHA-256 · SHA-512 · SHA-3\nHMAC · Avalanche · Intégrité",
         "hash", "#78350f"),
        ("✍",  "Signatures Numériques",
         "RSA-PSS · ElGamal · DSA · ECDSA\nAuthentification · Non-répudiation",
         "signature", A),
        ("🌐", "Communications Sécurisées",
         "TCP/IP · Bluetooth · UDP Chat\nVote homomorphe (Paillier)",
         "comms", "#4c1d95"),
    ]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=H, padx=35, pady=28)
        hdr.pack(fill="x")
        tk.Label(hdr, text="CryptoLab — Suite Cryptographique Complète",
                 font=FH, bg=H, fg=T).pack(anchor="w")
        tk.Label(hdr,
                 text="Chiffrement Classique  ·  Symétrique  ·  Asymétrique  ·  Hachage  ·  Signatures  ·  Protocoles",
                 font=FS, bg=H, fg=DIM).pack(anchor="w", pady=(4, 0))

        if not _CRYPTO:
            bar = tk.Frame(self, bg="#2d1500", pady=8, padx=25)
            bar.pack(fill="x")
            tk.Label(bar,
                     text="⚠  pycryptodome introuvable — mode dégradé actif.  pip install pycryptodome",
                     font=FS, bg="#2d1500", fg=WRN).pack(anchor="w")

        area = tk.Frame(self, bg=K, padx=35, pady=24)
        area.pack(fill="both", expand=True)

        for i, (icon, title, desc, target, color) in enumerate(self.CARDS):
            row, col = divmod(i, 3)
            card = tk.Frame(area, bg=C, highlightbackground=D,
                            highlightthickness=1, cursor="hand2")
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            area.grid_rowconfigure(row, weight=1)
            area.grid_columnconfigure(col, weight=1)

            tk.Frame(card, bg=color, width=4).pack(side="left", fill="y")
            body = tk.Frame(card, bg=C, padx=16, pady=14)
            body.pack(side="left", fill="both", expand=True)

            tk.Label(body, text=f"{icon}  {title}", font=FBB,
                     bg=C, fg=T).pack(anchor="w")
            tk.Label(body, text=desc, font=FS, bg=C, fg=DIM,
                     justify="left", wraplength=300).pack(anchor="w", pady=(6, 12))
            _btn(body, "Ouvrir →", lambda t=target: self.app.show(t),
                 accent=color).pack(anchor="w")

            for w in (card, body):
                w.bind("<Button-1>", lambda e, t=target: self.app.show(t))


# ═══════════════════════════════════════════════════════════════════════════
# CHIFFREMENT CLASSIQUE
# ═══════════════════════════════════════════════════════════════════════════

class ClassicSection(tk.Frame):
    ALGOS = ["César", "Vigenère", "Hill 2×2", "OTP (Vernam)"]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._build()

    def _build(self):
        _section_hdr(self, "📜", "Chiffrement Classique",
                     "César · Vigenère · Hill · One-Time Pad — analyse et cryptanalyse")

        # algo selector
        sel_bar = tk.Frame(self, bg=S, padx=20, pady=10)
        sel_bar.pack(fill="x")
        self._algo_var = tk.StringVar(value=self.ALGOS[0])
        for algo in self.ALGOS:
            rb = tk.Radiobutton(sel_bar, text=algo, variable=self._algo_var,
                                value=algo, font=FBB, bg=S, fg=DIM,
                                selectcolor=A, activebackground=S,
                                activeforeground=T, cursor="hand2",
                                command=self._switch_algo, pady=4, padx=6)
            rb.pack(side="left")

        self._pages: dict[str, tk.Frame] = {}
        container = tk.Frame(self, bg=K)
        container.pack(fill="both", expand=True)

        for name, cls in [("César", CesarPanel), ("Vigenère", VigenerePanel),
                           ("Hill 2×2", HillPanel), ("OTP (Vernam)", OTPPanel)]:
            p = cls(container)
            p.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._pages[name] = p

        self._switch_algo()

    def _switch_algo(self):
        sel = self._algo_var.get()
        for k, b in self._nav_btns().items() if hasattr(self, "_nav_btns") else []:
            pass
        for name, frame in self._pages.items():
            (frame.lift if name == sel else frame.lower)()

    def _nav_btns(self):
        return {}


class CesarPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=1)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        # Left: encrypt/decrypt
        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        b = _bar(lf, A)
        b.pack(fill="x", pady=(0, 10))
        tk.Label(b, text="Chiffrement / Déchiffrement", font=FBB, bg=A, fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C)
        row1.pack(fill="x", padx=14, pady=4)
        tk.Label(row1, text="Texte :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="Bonjour le monde")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        row2 = tk.Frame(lf, bg=C)
        row2.pack(fill="x", padx=14, pady=4)
        tk.Label(row2, text="Décalage k :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._k = tk.StringVar(value="7")
        _entry(row2, self._k, width=6).pack(side="left")

        btnrow = tk.Frame(lf, bg=C)
        btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Chiffrer", self._encrypt).pack(side="left")
        _btn(btnrow, "Déchiffrer", self._decrypt, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Force Brute", self._brute, accent=SEL).pack(side="left", padx=(6,0))
        _btn(btnrow, "Analyse IC", self._ic, accent="#065f46").pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        # Right: info
        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        b2 = _bar(rf, SEL)
        b2.pack(fill="x", pady=(0, 10))
        tk.Label(b2, text="Propriétés", font=FBB, bg=SEL, fg=T).pack(side="left")
        info = (
            "Chiffre de substitution monoalphabétique.\n\n"
            "Principe : C = (P + k) mod 26\n\n"
            "Sécurité : très faible — seulement 26 clés\n"
            "possibles, cassable en quelques secondes.\n\n"
            "Attaques :\n"
            "  • Force brute (26 essais)\n"
            "  • Analyse fréquentielle (chi²)\n"
            "  • Indice de coïncidence (IC ≈ 0.074 pour le français)\n\n"
            "Usage historique : Jules César (–50 av. J.C.)"
        )
        tk.Label(rf, text=info, font=FS, bg=C, fg=DIM,
                 justify="left", wraplength=320).pack(anchor="nw", pady=6)

    def _run_cesar(self, action):
        try:
            from cesar import chiffrer_cesar, dechiffrer_cesar, afficher_analyse, force_brute_cesar
            txt = self._txt.get()
            k   = int(self._k.get())
            if action == "enc":
                res = chiffrer_cesar(txt, k)
                _append(self._log, f"[{now()}] Chiffré (k={k}) : {res}", "ok")
            elif action == "dec":
                res = dechiffrer_cesar(txt, k)
                _append(self._log, f"[{now()}] Déchiffré (k={k}) : {res}", "ok")
            elif action == "brute":
                from cesar import force_brute_cesar
                crypto = chiffrer_cesar(txt, k)
                _append(self._log, f"[{now()}] Cryptogramme : {crypto}", "warn")
                for ki, score, texte in force_brute_cesar(crypto, top_n=5):
                    _append(self._log, f"  k={ki:2d}  score={score:.3f}  → {texte[:50]}", "info")
            elif action == "ic":
                from cesar import analyse_complete_cesar
                crypto = chiffrer_cesar(txt, k)
                res = analyse_complete_cesar(crypto)
                _append(self._log, f"[{now()}] IC = {res['ic']:.4f}  (français ≈ 0.074)", "key")
                _append(self._log, f"  Clé probable : k = {res['k_par_frequences']}", "ok")
                _append(self._log, f"  Déchiffré    : {res['dechiffre_freq'][:60]}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module cesar.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _encrypt(self): self._run_cesar("enc")
    def _decrypt(self): self._run_cesar("dec")

    def _brute(self):
        try:
            from cesar import force_brute_cesar
            crypto = self._txt.get()  # ← utiliser directement le texte entré
            _append(self._log, f"[{now()}] Force brute sur : {crypto}", "warn")
            for ki, score, texte in force_brute_cesar(crypto, top_n=5):
                _append(self._log, f"  k={ki:2d}  score={score:.3f}  → {texte[:50]}", "info")
        except ImportError:
            _append(self._log, "⚠ Module cesar.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _ic(self):
        try:
            from cesar import analyse_complete_cesar
            crypto = self._txt.get()  # ← directement sans rechiffrer
            res = analyse_complete_cesar(crypto)
            _append(self._log, f"[{now()}] IC = {res['ic']:.4f}  (français ≈ 0.074)", "key")
            _append(self._log, f"  Clé probable : k = {res['k_par_frequences']}", "ok")
            _append(self._log, f"  Déchiffré    : {res['dechiffre_freq'][:60]}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module cesar.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")


class VigenerePanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        b = _bar(lf, "#1e1065")
        b.pack(fill="x", pady=(0, 10))
        tk.Label(b, text="Vigenère", font=FBB, bg="#1e1065", fg=T).pack(side="left")

        for lbl, attr, val in [("Texte :", "_txt", "les sciences sont belles"),
                                ("Clé :", "_key", "CRYPTO")]:
            row = tk.Frame(lf, bg=C); row.pack(fill="x", pady=3)
            tk.Label(row, text=lbl, font=FS, bg=C, fg=DIM, width=7, anchor="w").pack(side="left")
            setattr(self, attr, tk.StringVar(value=val))
            _entry(row, getattr(self, attr)).pack(side="left", fill="x", expand=True)

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Chiffrer", self._enc).pack(side="left")
        _btn(btnrow, "Déchiffrer", self._dec, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Cryptanalyse (Kasiski+IC)", self._analyse, accent=SEL).pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        b2 = _bar(rf, "#1e1065")
        b2.pack(fill="x", pady=(0, 10))
        tk.Label(b2, text="Propriétés", font=FBB, bg="#1e1065", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Chiffre polyalphabétique.\n\n"
            "Principe :\nC[i] = (P[i] + K[i mod|K|]) mod 26\n\n"
            "Sécurité :\n|K| = |M| → équivalent OTP\n"
            "|K| court → vulnérable\n\n"
            "Attaques :\n• Test de Kasiski\n• Indice de coïncidence\n• Analyse chi²"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _enc(self):
        try:
            from vigenere import chiffrer_vigenere
            enc = chiffrer_vigenere(self._txt.get(), self._key.get())
            _append(self._log, f"[{now()}] Chiffré   : {enc}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module vigenere.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _dec(self):
        try:
            from vigenere import dechiffrer_vigenere
            dec = dechiffrer_vigenere(self._txt.get(), self._key.get())
            _append(self._log, f"[{now()}] Déchiffré : {dec}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module vigenere.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _analyse(self):
        try:
            from vigenere import chiffrer_vigenere, cryptanalyse_vigenere
            txt = self._txt.get()
            cle = self._key.get()
            crypto = chiffrer_vigenere(txt * 3, cle)
            _append(self._log, f"[{now()}] Cryptogramme (×3 pour Kasiski) : {crypto[:60]}…", "warn")
            res = cryptanalyse_vigenere(crypto)
            _append(self._log, f"  Longueur de clé probable : {res['longueur_probable']}", "info")
            _append(self._log, f"  Clé retrouvée            : {res['cle_probable']}", "key")
            _append(self._log, f"  Déchiffré                : {res['texte_dechiffre'][:80]}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module vigenere.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")


class HillPanel(tk.Frame):
    CLE_2x2 = [[3, 3], [2, 5]]

    def __init__(self, master):
        super().__init__(master, bg=K)
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        b = _bar(lf, "#065f46")
        b.pack(fill="x", pady=(0, 10))
        tk.Label(b, text="Hill 2×2", font=FBB, bg="#065f46", fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="Texte :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="CRYPTOGRAPHIE")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        tk.Label(lf, text=f"Clé 2×2 utilisée : {self.CLE_2x2}",
                 font=FM, bg=C, fg=G).pack(anchor="w", pady=4)

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Chiffrer", self._enc).pack(side="left")
        _btn(btnrow, "Déchiffrer", self._dec, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Attaque clair connu", self._attack, accent=SEL).pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        b2 = _bar(rf, "#065f46")
        b2.pack(fill="x", pady=(0, 10))
        tk.Label(b2, text="Propriétés", font=FBB, bg="#065f46", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Chiffre par blocs matriciel.\n\n"
            "Principe :\nC = K × P  mod 26\n\n"
            "Clé valide si :\ngcd(det(K), 26) = 1\n\n"
            "Vulnérabilité :\nAttaque à clair connu.\nN paires suffisent\n"
            "pour retrouver K.\n\n"
            "K = C × P⁻¹  mod 26"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _enc(self):
        try:
            from hill import chiffrer_hill
            enc = chiffrer_hill(self._txt.get(), self.CLE_2x2)
            _append(self._log, f"[{now()}] Chiffré   : {enc}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module hill.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _dec(self):
        try:
            from hill import dechiffrer_hill
            dec = dechiffrer_hill(self._txt.get(), self.CLE_2x2)
            _append(self._log, f"[{now()}] Déchiffré : {dec}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module hill.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _attack(self):
        def _run():
            try:
                from hill import chiffrer_hill, attaque_clair_connu
                import random, string
                _append(self._log, f"[{now()}] Lancement de l'attaque à clair connu…", "warn")
                for _ in range(40):
                    paires = []
                    for __ in range(2):
                        clair   = ''.join(random.choices(string.ascii_uppercase, k=2))
                        chiffre = chiffrer_hill(clair, self.CLE_2x2)
                        paires.append((clair, chiffre))
                    res = attaque_clair_connu(paires, 2)
                    if res.get("succes"):
                        self.after(0, lambda r=res, p=paires: (
                            _append(self._log, f"  Paires : {p}", "info"),
                            _append(self._log, f"  Clé réelle    : {self.CLE_2x2}", "info"),
                            _append(self._log, f"  Clé retrouvée : {r['cle_retrouvee']}", "key"),
                            _append(self._log, f"  Succès ✓", "ok")
                        ))
                        return
                self.after(0, lambda: _append(self._log, "  Aucune paire inversible trouvée.", "err"))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ Module hill.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()


class OTPPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._key = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        b = _bar(lf, "#78350f")
        b.pack(fill="x", pady=(0, 10))
        tk.Label(b, text="One-Time Pad (Vernam)", font=FBB, bg="#78350f", fg=T).pack(side="left")

        for lbl, attr, val in [("Message 1 :", "_m1", "Le mot de passe est ALPHA"),
                                ("Message 2 :", "_m2", "Rendez-vous a minuit ici")]:
            row = tk.Frame(lf, bg=C); row.pack(fill="x", pady=3)
            tk.Label(row, text=lbl, font=FS, bg=C, fg=DIM, width=10, anchor="w").pack(side="left")
            setattr(self, attr, tk.StringVar(value=val))
            _entry(row, getattr(self, attr)).pack(side="left", fill="x", expand=True)

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Chiffrer M1", self._enc).pack(side="left")
        _btn(btnrow, "Déchiffrer", self._dec, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Vuln. réutilisation", self._vuln, accent=SEL).pack(side="left", padx=(6,0))
        _btn(btnrow, "Crib Dragging", self._crib, accent="#065f46").pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        b2 = _bar(rf, "#78350f")
        b2.pack(fill="x", pady=(0, 10))
        tk.Label(b2, text="Propriétés", font=FBB, bg="#78350f", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Sécurité parfaite (Shannon 1949).\n\n"
            "Principe :\nC = M ⊕ K\n\n"
            "Conditions :\n• |K| = |M|\n• K aléatoire\n• Usage unique\n\n"
            "Vulnérabilité :\nRéutilisation de clé :\nC1 ⊕ C2 = M1 ⊕ M2\n\n"
            "→ Crib dragging permet de\nrécupérer M1 et M2"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _enc(self):
        try:
            from otp import chiffrer_texte
            ct, key = chiffrer_texte(self._m1.get())
            self._key = key
            self._ct  = ct
            _append(self._log, f"[{now()}] Clé (hex)   : {key.hex()}", "key")
            _append(self._log, f"[{now()}] Chiffré     : {ct.hex()}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module otp.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _dec(self):
        try:
            from otp import dechiffrer_texte
            if not self._key:
                _append(self._log, "⚠ Chiffrez d'abord.", "warn"); return
            dec = dechiffrer_texte(self._ct, self._key)
            _append(self._log, f"[{now()}] Déchiffré   : {dec}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module otp.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _vuln(self):
        try:
            from otp import demo_reutilisation_cle
            res = demo_reutilisation_cle(self._m1.get(), self._m2.get())
            _append(self._log, f"[{now()}] C1 ⊕ C2 = {res['xor_c1_c2_hex'][:48]}…", "warn")
            _append(self._log, f"  M1 ⊕ M2 = {res['xor_m1_m2_hex'][:48]}…", "info")
            _append(self._log, f"  Identiques : {res['xor_egal']}  ← clé annulée !", "ok")
            self._xor = res["_xor"]
        except ImportError:
            _append(self._log, "⚠ Module otp.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _crib(self):
        try:
            from otp import demo_reutilisation_cle, crib_dragging
            if not hasattr(self, "_xor"):
                self._vuln()
            for crib in ["Le ", "Rendez", "mot"]:
                hits = crib_dragging(self._xor, crib, seuil_score=1.0)
                if hits:
                    _append(self._log, f"  Crib '{crib}' → pos={hits[0]['position']}  '{hits[0]['fragment_m2']}'", "key")
        except ImportError:
            _append(self._log, "⚠ Module otp.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")


# ═══════════════════════════════════════════════════════════════════════════
# CHIFFREMENT SYMÉTRIQUE
# ═══════════════════════════════════════════════════════════════════════════

class SymmetricSection(tk.Frame):
    ALGOS = ["RC4", "DES / 3DES", "AES"]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._build()

    def _build(self):
        _section_hdr(self, "🔒", "Chiffrement Symétrique",
                     "RC4 · DES / Triple-DES · AES-128/192/256 — modes ECB, CBC, CTR, GCM")

        sel_bar = tk.Frame(self, bg=S, padx=20, pady=10)
        sel_bar.pack(fill="x")
        self._algo_var = tk.StringVar(value=self.ALGOS[0])
        for algo in self.ALGOS:
            tk.Radiobutton(sel_bar, text=algo, variable=self._algo_var,
                           value=algo, font=FBB, bg=S, fg=DIM,
                           selectcolor=A, activebackground=S,
                           activeforeground=T, cursor="hand2",
                           command=self._switch, pady=4, padx=8).pack(side="left")

        self._pages: dict[str, tk.Frame] = {}
        cont = tk.Frame(self, bg=K)
        cont.pack(fill="both", expand=True)
        for name, cls in [("RC4", RC4Panel), ("DES / 3DES", DESPanel), ("AES", AESPanel)]:
            p = cls(cont)
            p.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._pages[name] = p
        self._switch()

    def _switch(self):
        sel = self._algo_var.get()
        for name, frame in self._pages.items():
            (frame.lift if name == sel else frame.lower)()


class RC4Panel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, A).pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="RC4 — Chiffrement par flot",
                 font=FBB, bg=A, fg=T).pack(side="left")

        for lbl, attr, val in [("Clé :", "_key", "SecretKey"), ("Texte :", "_txt", "Hello, RC4!")]:
            row = tk.Frame(lf, bg=C); row.pack(fill="x", pady=3)
            tk.Label(row, text=lbl, font=FS, bg=C, fg=DIM, width=7, anchor="w").pack(side="left")
            setattr(self, attr, tk.StringVar(value=val))
            _entry(row, getattr(self, attr)).pack(side="left", fill="x", expand=True)

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Chiffrer/Déchiffrer", self._enc).pack(side="left")

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, A).pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés",
                 font=FBB, bg=A, fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Chiffrement par flot (stream cipher).\n\n"
            "Phases :\n1. KSA — Key Scheduling Algorithm\n"
            "2. PRGA — Pseudo-Random Generation\n\n"
            "Opération :\nC[i] = P[i] ⊕ K[i]\n\n"
            "État : S[256] (permutation)\n\n"
            "⚠ Déprécié :\n• Biais statistiques (RC4 bias)\n"
            "• Vulnérable aux IV faibles (WEP)\n"
            "• Banni dans TLS 1.3\n\n"
            "→ Utiliser AES-GCM en production"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _enc(self):
        try:
            from rc4 import encrypt_text, decrypt_text
            cle = self._key.get()
            txt = self._txt.get()
            ct  = encrypt_text(txt, cle)
            dec = decrypt_text(ct, cle)
            _append(self._log, f"[{now()}] Clé       : {cle}", "key")
            _append(self._log, f"[{now()}] Chiffré   : {ct.hex()}", "ok")
            _append(self._log, f"[{now()}] Déchiffré : {dec}", "ok")
            _append(self._log, f"⚠ RC4 est déprécié — utiliser AES-GCM", "warn")
        except ImportError:
            # Fallback pure Python RC4
            key = self._key.get().encode()
            txt = self._txt.get().encode()
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
            i = j = 0
            ct = []
            for byte in txt:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                ct.append(byte ^ S[(S[i] + S[j]) % 256])
            ct = bytes(ct)
            _append(self._log, f"[{now()}] [Fallback RC4 pur Python]", "warn")
            _append(self._log, f"[{now()}] Chiffré   : {ct.hex()}", "ok")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")


class DESPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._params = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, "#1e1065").pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="DES / Triple-DES",
                 font=FBB, bg="#1e1065", fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="Texte :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="Message DES exemple")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        row2 = tk.Frame(lf, bg=C); row2.pack(fill="x", padx=14, pady=3)
        tk.Label(row2, text="Algo :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._mode = tk.StringVar(value="3DES")
        _combo(row2, self._mode, ["DES", "3DES"], width=10).pack(side="left")

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Chiffrer", self._enc).pack(side="left")
        _btn(btnrow, "Déchiffrer", self._dec, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Comparer ECB vs CBC", self._compare, accent=SEL).pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, "#1e1065").pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés",
                 font=FBB, bg="#1e1065", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "DES — Data Encryption Standard\n\n"
            "Taille bloc : 64 bits\nClé effective : 56 bits\n"
            "Structure : réseau Feistel (16 tours)\n\n"
            "⚠ DES cassé (1999, EFF DES Cracker)\n\n"
            "3DES = E(K3) ∘ D(K2) ∘ E(K1)\n"
            "Sécurité effective : 112 bits\n\n"
            "⚠ 3DES déprécié par NIST (2019)\n\n"
            "Faiblesse ECB :\nBlocs identiques → CT identiques\n"
            "→ fuite de structure"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _enc(self):
        try:
            from des_cipher import encrypt_text
            self._params = encrypt_text(self._txt.get(), use_3des=(self._mode.get()=="3DES"))
            _append(self._log, f"[{now()}] Algo : {self._params['algorithm']}", "info")
            _append(self._log, f"[{now()}] Clé  : {self._params['key'].hex()}", "key")
            _append(self._log, f"[{now()}] IV   : {self._params['iv'].hex()}", "key")
            _append(self._log, f"[{now()}] CT   : {self._params['ciphertext'].hex()[:48]}…", "ok")
        except ImportError:
            _append(self._log, "⚠ Module des_cipher.py non trouvé (pycryptodome requis).", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _dec(self):
        try:
            from des_cipher import decrypt_text
            if not self._params:
                _append(self._log, "⚠ Chiffrez d'abord.", "warn"); return
            dec = decrypt_text(self._params)
            _append(self._log, f"[{now()}] Déchiffré : {dec}", "ok")
        except ImportError:
            _append(self._log, "⚠ Module des_cipher.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _compare(self):
        try:
            from des_cipher import compare_ecb_cbc
            txt = ("BLOC_REPETITIF  " * 8).encode()
            res = compare_ecb_cbc(txt)
            _append(self._log, f"[{now()}] Clé DES : {res['key']}", "key")
            _append(self._log, f"  ECB blocs identiques : {res['ecb_repeated_blocks']}", "warn")
            _append(self._log, f"  CBC blocs identiques : {res['cbc_repeated_blocks']}", "ok")
            if res['ecb_repeated_blocks'] > 0:
                _append(self._log, "  ⚠ ECB : structure visible dans le CT !", "err")
            _append(self._log, "  ✓ CBC : chaînage masque toute répétition.", "ok")
        except ImportError:
            _append(self._log, "⚠ Module des_cipher.py non trouvé.", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")


class AESPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._params = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, "#065f46").pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="AES — Advanced Encryption Standard",
                 font=FBB, bg="#065f46", fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="Texte :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="Message confidentiel AES-256!")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        row2 = tk.Frame(lf, bg=C); row2.pack(fill="x", padx=14, pady=3)
        tk.Label(row2, text="Mode :", font=FS, bg=C, fg=DIM, width=5, anchor="w").pack(side="left")
        self._mode = tk.StringVar(value="GCM")
        _combo(row2, self._mode, ["GCM", "CBC", "CTR", "ECB"], width=8).pack(side="left", padx=(0, 12))
        tk.Label(row2, text="Taille clé :", font=FS, bg=C, fg=DIM).pack(side="left")
        self._ks = tk.StringVar(value="256")
        _combo(row2, self._ks, ["128", "192", "256"], width=6).pack(side="left")

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Chiffrer", self._enc).pack(side="left")
        _btn(btnrow, "Déchiffrer", self._dec, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Avalanche 1-bit", self._avalanche, accent=SEL).pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, "#065f46").pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés",
                 font=FBB, bg="#065f46", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Standard depuis 2001 (Rijndael).\n\n"
            "Bloc : 128 bits\nClés : 128/192/256 bits\n"
            "Tours : 10/12/14\n\n"
            "Modes :\n• ECB — sans IV (déconseillé)\n"
            "• CBC — chaînage XOR\n• CTR — compteur\n"
            "• GCM — authentifié ✓\n\n"
            "Sécurité :\n• Résistant aux attaques connues\n"
            "• AES-NI accélération matérielle\n"
            "• NIST post-quantum safe\n\n"
            "→ Standard recommandé"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _enc(self):
        try:
            from aes_cipher import encrypt_text
            self._params = encrypt_text(self._txt.get(), mode=self._mode.get())
            _append(self._log, f"[{now()}] Mode : AES-{self._ks.get()}-{self._mode.get()}", "info")
            _append(self._log, f"[{now()}] Clé  : {self._params['key'].hex()[:32]}…", "key")
            _append(self._log, f"[{now()}] CT   : {self._params['ciphertext'].hex()[:48]}…", "ok")
        except ImportError:
            # Fallback with pycryptodome directly
            try:
                key = secrets.token_bytes(int(self._ks.get()) // 8)
                ct, nonce, tag = aes_enc(self._txt.get().encode(), key)
                self._params = {"key": key, "ciphertext": ct, "nonce": nonce, "tag": tag, "mode": "GCM"}
                _append(self._log, f"[{now()}] [Fallback direct pycryptodome]", "warn")
                _append(self._log, f"[{now()}] Clé : {key.hex()[:32]}…", "key")
                _append(self._log, f"[{now()}] CT  : {ct.hex()[:48]}…", "ok")
            except Exception as e2:
                _append(self._log, f"⚠ aes_cipher.py manquant + fallback échoué : {e2}", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _dec(self):
        try:
            from aes_cipher import decrypt_text
            if not self._params:
                _append(self._log, "⚠ Chiffrez d'abord.", "warn"); return
            dec = decrypt_text(self._params)
            _append(self._log, f"[{now()}] Déchiffré : {dec}", "ok")
        except ImportError:
            if self._params and "nonce" in self._params:
                try:
                    pt = aes_dec(self._params["ciphertext"], self._params["key"],
                                 self._params["nonce"], self._params["tag"])
                    _append(self._log, f"[{now()}] Déchiffré : {pt.decode()}", "ok")
                except Exception as e2:
                    _append(self._log, f"Erreur fallback : {e2}", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _avalanche(self):
        try:
            key = secrets.token_bytes(32)
            msg = self._txt.get().encode().ljust(16, b"\x00")[:16]
            ct1, n1, t1 = aes_enc(msg, key)
            msg2 = bytearray(msg); msg2[0] ^= 0x01
            ct2, n2, t2 = aes_enc(bytes(msg2), key)
            diff = bin(int(ct1.hex(), 16) ^ int(ct2.hex(), 16)).count("1")
            total = len(ct1) * 8
            _append(self._log, f"[{now()}] Avalanche : {diff}/{total} bits différents ({diff/total*100:.1f}%)", "info")
        except Exception as e:
            _append(self._log, f"Erreur avalanche : {e}", "err")


# ═══════════════════════════════════════════════════════════════════════════
# CHIFFREMENT ASYMÉTRIQUE
# ═══════════════════════════════════════════════════════════════════════════

class AsymmetricSection(tk.Frame):
    ALGOS = ["RSA", "Diffie-Hellman", "ElGamal"]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._build()

    def _build(self):
        _section_hdr(self, "🗝", "Chiffrement Asymétrique",
                     "RSA · Diffie-Hellman · ElGamal")

        sel_bar = tk.Frame(self, bg=S, padx=20, pady=10)
        sel_bar.pack(fill="x")
        self._algo_var = tk.StringVar(value=self.ALGOS[0])
        for algo in self.ALGOS:
            tk.Radiobutton(sel_bar, text=algo, variable=self._algo_var,
                           value=algo, font=FBB, bg=S, fg=DIM,
                           selectcolor=A, activebackground=S,
                           activeforeground=T, cursor="hand2",
                           command=self._switch, pady=4, padx=8).pack(side="left")

        self._pages: dict[str, tk.Frame] = {}
        cont = tk.Frame(self, bg=K)
        cont.pack(fill="both", expand=True)
        for name, cls in [("RSA", RSAPanel), ("Diffie-Hellman", DHPanel),
                           ("ElGamal", ElGamalPanel), ("ECC", ECCPanel)]:
            p = cls(cont)
            p.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._pages[name] = p
        self._switch()

    def _switch(self):
        sel = self._algo_var.get()
        for name, frame in self._pages.items():
            (frame.lift if name == sel else frame.lower)()


class RSAPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._priv = self._pub = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, A).pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="RSA — Rivest-Shamir-Adleman",
                 font=FBB, bg=A, fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="Texte :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="Message secret RSA")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        row2 = tk.Frame(lf, bg=C); row2.pack(fill="x", padx=14, pady=3)
        tk.Label(row2, text="Bits :", font=FS, bg=C, fg=DIM, width=8, anchor="w").pack(side="left")
        self._bits = tk.StringVar(value="2048")
        _combo(row2, self._bits, ["1024", "2048", "4096"], width=8).pack(side="left")

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Générer clés", self._keygen).pack(side="left")
        _btn(btnrow, "Chiffrer", self._enc, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Déchiffrer", self._dec, accent=SEL).pack(side="left", padx=(6,0))
        _btn(btnrow, "Hybride RSA+AES", self._hybrid, accent="#065f46").pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, A).pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés", font=FBB, bg=A, fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Cryptographie à clé publique.\n\n"
            "Génération :\nn = p·q (p, q premiers)\n"
            "e = 65537\nd = e⁻¹ mod λ(n)\n\n"
            "Chiffrement :\nC = Mᵉ mod n  (OAEP)\n"
            "M = Cᵈ mod n\n\n"
            "Taille max (OAEP) :\n2048-bit → 214 octets\n\n"
            "Sécurité basée sur :\nDifficulté de factoriser n\n\n"
            "→ Hybride RSA+AES pour\n   les fichiers volumineux"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _keygen(self):
        bits = int(self._bits.get())
        _append(self._log, f"[{now()}] Génération RSA-{bits}…", "warn")
        def _run():
            try:
                from rsa_cipher import generate_keypair
                self._priv, self._pub = generate_keypair(bits)
                n_hex = hex(self._priv.n)
                self.after(0, lambda: _append(self._log,
                    f"[{now()}] Clé RSA-{bits} générée ✓\n  n = {n_hex[:20]}…", "ok"))
            except ImportError:
                if _CRYPTO:
                    self._priv, self._pub = rsa_keygen(bits)
                    self.after(0, lambda: _append(self._log,
                        f"[{now()}] Clé RSA-{bits} générée (fallback) ✓", "ok"))
                else:
                    self.after(0, lambda: _append(self._log, "⚠ pycryptodome requis.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()

    def _enc(self):
        try:
            if not self._pub:
                _append(self._log, "⚠ Générez les clés d'abord.", "warn"); return
            ct = rsa_enc(self._txt.get().encode(), self._pub)
            self._ct = ct
            _append(self._log, f"[{now()}] CT ({len(ct)} B) : {ct.hex()[:48]}…", "ok")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _dec(self):
        try:
            if not self._priv or not hasattr(self, "_ct"):
                _append(self._log, "⚠ Chiffrez d'abord.", "warn"); return
            pt = rsa_dec(self._ct, self._priv)
            _append(self._log, f"[{now()}] Déchiffré : {pt.decode()}", "ok")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _hybrid(self):
        def _run():
            try:
                from rsa_cipher import generate_keypair, hybrid_encrypt, hybrid_decrypt
                import time as _t
                if not self._priv:
                    self._priv, self._pub = generate_keypair(2048)
                payload = os.urandom(1024 * 1024)
                t0 = _t.perf_counter()
                bundle = hybrid_encrypt(payload, self._pub)
                pt     = hybrid_decrypt(bundle, self._priv)
                elapsed = (_t.perf_counter() - t0) * 1000
                ok = pt == payload
                self.after(0, lambda: (
                    _append(self._log, f"[{now()}] Hybride RSA-2048 + AES-256-GCM (1 Mo)", "info"),
                    _append(self._log, f"  RSA-OAEP (32 octets) : {bundle['t_rsa_ms']:.2f} ms", "key"),
                    _append(self._log, f"  AES-GCM  (1 Mo)     : {bundle['t_aes_ms']:.2f} ms", "key"),
                    _append(self._log, f"  Total                : {elapsed:.2f} ms", "info"),
                    _append(self._log, f"  Déchiffrement OK     : {ok} ✓", "ok")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ rsa_cipher.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()


class DHPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, "#3b0764").pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="Diffie-Hellman — Échange de clés",
                 font=FBB, bg="#3b0764", fg=T).pack(side="left")

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Simuler échange Alice ↔ Bob", self._run).pack(side="left")
        _btn(btnrow, "Simuler attaque MitM", self._mitm, accent=ERR).pack(side="left", padx=(6,0))

        self._log = _log(lf, height=18)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, "#3b0764").pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés", font=FBB, bg="#3b0764", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Échange de clés sur canal public.\n\n"
            "Protocole :\n1. Alice : a secret, A = gᵃ mod p\n"
            "2. Bob   : b secret, B = gᵇ mod p\n"
            "3. Alice : K = Bᵃ mod p\n"
            "4. Bob   : K = Aᵇ mod p\n\n"
            "Sécurité basée sur :\nProblème du logarithme discret\n\n"
            "Vulnérabilité :\nAttaque MitM sans authentification\n\n"
            "Contre-mesure :\nSignatures ECDSA des\nclés publiques échangées"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _run(self):
        def _do():
            try:
                from diffie_hellman import DHParty
                _append(self._log, f"[{now()}] Génération des paramètres DH…", "warn")
                alice = DHParty()
                bob   = DHParty(p=alice.p, g=alice.g)
                ka = alice.derive_aes_key(bob.public_key)
                kb = bob.derive_aes_key(alice.public_key)
                self.after(0, lambda: (
                    _append(self._log, f"  p = {hex(alice.p)[:20]}… ({alice.p.bit_length()} bits)", "info"),
                    _append(self._log, f"  A (pub Alice) = {hex(alice.public_key)[:18]}…", "key"),
                    _append(self._log, f"  B (pub Bob)   = {hex(bob.public_key)[:18]}…", "key"),
                    _append(self._log, f"  Clé Alice : {ka.hex()}", "ok"),
                    _append(self._log, f"  Clé Bob   : {kb.hex()}", "ok"),
                    _append(self._log, f"  Identiques : {ka == kb} ✓", "ok")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ diffie_hellman.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_do, daemon=True).start()

    def _mitm(self):
        def _do():
            try:
                from diffie_hellman import DHParty
                _append(self._log, f"\n[{now()}] ══ Simulation attaque MitM ══", "warn")
                alice = DHParty()
                bob   = DHParty(p=alice.p, g=alice.g)
                eve   = DHParty(p=alice.p, g=alice.g)

                ka_eve = alice.derive_aes_key(eve.public_key)
                kb_eve = bob.derive_aes_key(eve.public_key)
                self.after(0, lambda: (
                    _append(self._log, "  Ève intercepte et substitue ses propres valeurs.", "warn"),
                    _append(self._log, f"  Clé Alice-Ève : {ka_eve.hex()[:24]}…", "err"),
                    _append(self._log, f"  Clé Bob-Ève   : {kb_eve.hex()[:24]}…", "err"),
                    _append(self._log, "  ⚠ Alice et Bob ont des clés DIFFÉRENTES !", "err"),
                    _append(self._log, "  ✓ Contre-mesure : signer les échanges (ECDSA)", "ok")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ diffie_hellman.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_do, daemon=True).start()


class ElGamalPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._eg = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, "#78350f").pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="ElGamal — Chiffrement Probabiliste",
                 font=FBB, bg="#78350f", fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="M entier :", font=FS, bg=C, fg=DIM, width=10, anchor="w").pack(side="left")
        self._m = tk.StringVar(value="12345")
        _entry(row1, self._m, width=12).pack(side="left")

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Générer clés (512-bit)", self._keygen, accent="#78350f").pack(side="left")
        _btn(btnrow, "Chiffrer M", self._enc, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Non-déterminisme", self._nondeter, accent=SEL).pack(side="left", padx=(6,0))
        _btn(btnrow, "Malléabilité E(2M)", self._malleability, accent=ERR).pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, "#78350f").pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés", font=FBB, bg="#78350f", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Chiffrement probabiliste.\n\n"
            "Clé pub : (p, g, h=gˣ mod p)\n"
            "Clé priv : x\n\n"
            "Chiffrement :\nk aléatoire à chaque appel\n"
            "C1 = gᵏ mod p\n"
            "C2 = M·hᵏ mod p\n\n"
            "Déchiffrement :\ns = C1ˣ mod p\n"
            "M = C2·s⁻¹ mod p\n\n"
            "Propriétés :\n• IND-CPA (randomisé)\n"
            "• Malléable (multiplicatif)\n\n"
            "CT = 2× RSA de même taille"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _keygen(self):
        _append(self._log, f"[{now()}] Génération ElGamal-512…", "warn")
        def _run():
            try:
                from elgamal import ElGamal
                self._eg = ElGamal(bits=512)
                p, g, h  = self._eg.public_key
                self.after(0, lambda: (
                    _append(self._log, f"[{now()}] p = {hex(p)[:18]}… ({p.bit_length()} bits)", "key"),
                    _append(self._log, f"  g = {g}", "info"),
                    _append(self._log, f"  h = {hex(h)[:18]}… (clé publique)", "ok")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ elgamal.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()

    def _enc(self):
        try:
            if not self._eg:
                _append(self._log, "⚠ Générez les clés d'abord.", "warn"); return
            M = int(self._m.get())
            C1, C2 = self._eg.encrypt_int(M)
            self._last = (C1, C2)
            dec = self._eg.decrypt_int(C1, C2)
            _append(self._log, f"[{now()}] M = {M}", "info")
            _append(self._log, f"  C1 = {hex(C1)[:20]}…", "ok")
            _append(self._log, f"  C2 = {hex(C2)[:20]}…", "ok")
            _append(self._log, f"  D(E(M)) = {dec}  ✓", "ok")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _nondeter(self):
        try:
            if not self._eg:
                _append(self._log, "⚠ Générez les clés d'abord.", "warn"); return
            M  = int(self._m.get())
            E1 = self._eg.encrypt_int(M)
            E2 = self._eg.encrypt_int(M)
            _append(self._log, f"[{now()}] Non-déterminisme (même M={M}) :", "info")
            _append(self._log, f"  Enc₁ = ({hex(E1[0])[:12]}…, {hex(E1[1])[:12]}…)", "key")
            _append(self._log, f"  Enc₂ = ({hex(E2[0])[:12]}…, {hex(E2[1])[:12]}…)", "key")
            _append(self._log, f"  Égaux : {E1 == E2}  ← k différent à chaque chiffrement", "ok")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _malleability(self):
        try:
            if not self._eg or not hasattr(self, "_last"):
                _append(self._log, "⚠ Chiffrez M d'abord.", "warn"); return
            M = int(self._m.get())
            C1, C2 = self._last
            forged  = (C1, (2 * C2) % self._eg.p)
            dec_f   = self._eg.decrypt_int(*forged)
            expected = (2 * M) % self._eg.p
            _append(self._log, f"[{now()}] Malléabilité : E(2M) forgé sans connaître M ni x", "warn")
            _append(self._log, f"  D(forgé) = {dec_f}", "info")
            _append(self._log, f"  2M mod p = {expected}", "info")
            _append(self._log, f"  Succès   : {dec_f == expected} ✓", "ok")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")


class ECCPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=K)
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, "#1e3a5f").pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1],
                 text="ECC — Cryptographie sur Courbes Elliptiques",
                 font=FBB, bg="#1e3a5f", fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="Message :", font=FS, bg=C, fg=DIM, width=10, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="Message secret via ECIES")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Courbe y²=x³+7 (mod 97)", self._tiny, accent="#1e3a5f").pack(side="left")
        _btn(btnrow, "ECDH P-256", self._ecdh, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "ECIES Chiffrer/Déchiffrer", self._ecies, accent=SEL).pack(side="left", padx=(6,0))

        self._log = _log(lf, height=16)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, "#1e3a5f").pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés", font=FBB, bg="#1e3a5f", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "y² = x³ + ax + b  (mod p)\n\n"
            "ECDLP : Q = k·P est facile,\nretrouve k depuis Q est infaisable.\n\n"
            "Avantage :\nECC-256 ≈ RSA-3072 en sécurité\nClés beaucoup plus courtes\n\n"
            "ECDH :\nSecret partagé via multiplication\nscalaire réciproque\n\n"
            "ECIES :\nChiffrement hybride intégré\n(clé éphémère + AES-GCM)\n\n"
            "→ Perfect Forward Secrecy"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _tiny(self):
        def _run():
            try:
                from ecc import TinyEllipticCurve
                curve = TinyEllipticCurve(0, 7, 97)
                G = (1, 28)
                lines = [f"[{now()}] Courbe y²=x³+7 (mod 97), G={G}"]
                for k in [1, 2, 3, 5, 7, 10]:
                    kG = curve.scalar_mul(k, G)
                    lines.append(f"  {k:>2}·G = {str(kG):<20}  sur courbe: {curve.is_on_curve(kG)}")
                P = curve.scalar_mul(3, G)
                Q = curve.scalar_mul(5, G)
                R = curve.point_add(P, Q)
                lines.append(f"  3G + 5G = {R}  (= 8G = {curve.scalar_mul(8,G)}) ✓")
                self.after(0, lambda: [_append(self._log, l, "info") for l in lines])
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ ecc.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()

    def _ecdh(self):
        def _run():
            try:
                from ecc import ECDHParty
                alice = ECDHParty("Alice")
                bob   = ECDHParty("Bob")
                ka    = alice.derive_aes_key(bob.pub)
                kb    = bob.derive_aes_key(alice.pub)
                match = ka == kb
                self.after(0, lambda: (
                    _append(self._log, f"[{now()}] ECDH P-256", "info"),
                    _append(self._log, f"  Clé Alice : {ka.hex()}", "key"),
                    _append(self._log, f"  Clé Bob   : {kb.hex()}", "key"),
                    _append(self._log, f"  Identiques : {match} ✓", "ok")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ ecc.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()

    def _ecies(self):
        def _run():
            try:
                from ecc import ECDHParty, ecies_encrypt, ecies_decrypt
                bob   = ECDHParty("Bob")
                msg   = self._txt.get().encode()
                bundle = ecies_encrypt(msg, bob.pub)
                recovered = ecies_decrypt(bundle, bob)
                self.after(0, lambda: (
                    _append(self._log, f"[{now()}] ECIES : {self._txt.get()}", "info"),
                    _append(self._log, f"  Nonce : {bundle['nonce'].hex()}", "key"),
                    _append(self._log, f"  CT    : {bundle['ciphertext'].hex()[:40]}…", "ok"),
                    _append(self._log, f"  Tag   : {bundle['tag'].hex()}", "key"),
                    _append(self._log, f"  Déchiffré : {recovered.decode()}", "ok"),
                    _append(self._log, f"  PFS : clé éphémère détruite ✓", "ok")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ ecc.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════
# HACHAGE
# ═══════════════════════════════════════════════════════════════════════════

class HashSection(tk.Frame):
    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._build()

    def _build(self):
        _section_hdr(self, "#", "Fonctions de Hachage",
                     "MD5 · SHA-256 · SHA-512 · SHA-3 · HMAC — avalanche, intégrité, benchmark")

        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, "#78350f").pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="Hachage & Analyse",
                 font=FBB, bg="#78350f", fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="Message :", font=FS, bg=C, fg=DIM, width=10, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="Hello, Cryptographie!")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        row2 = tk.Frame(lf, bg=C); row2.pack(fill="x", padx=14, pady=3)
        tk.Label(row2, text="Clé HMAC :", font=FS, bg=C, fg=DIM, width=10, anchor="w").pack(side="left")
        self._hmac_key = tk.StringVar(value="cle_secrete")
        _entry(row2, self._hmac_key).pack(side="left", fill="x", expand=True)

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Calculer tous les hashes", self._hash_all).pack(side="left")
        _btn(btnrow, "Effet Avalanche", self._avalanche, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "HMAC-SHA256", self._hmac, accent=SEL).pack(side="left", padx=(6,0))
        _btn(btnrow, "SHA-256 pur Python", self._sha256_pure, accent="#065f46").pack(side="left", padx=(6,0))

        self._log = _log(lf, height=18)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, "#78350f").pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés", font=FBB, bg="#78350f", fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Propriétés requises :\n\n"
            "1. Résistance à la pré-image\n   H(x)=h → trouver x infaisable\n\n"
            "2. Résistance à la 2ème pré-image\n   x≠x', H(x)=H(x') infaisable\n\n"
            "3. Résistance aux collisions\n   x≠x', H(x)=H(x') infaisable\n\n"
            "Comparatif :\n"
            "• MD5    → 128b  ⚠ cassé\n"
            "• SHA-256 → 256b ✓ standard\n"
            "• SHA-512 → 512b ✓ 64-bit CPU\n"
            "• SHA-3   → sponge ✓ \n\n"
            "HMAC :\nH(K ⊕ opad || H(K ⊕ ipad || M))\n"
            "Authentification + intégrité"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _hash_all(self):
        try:
            from sha_hash import hash_all
            res = hash_all(self._txt.get())
            _append(self._log, f"[{now()}] Message : {self._txt.get()[:50]}", "info")
            for algo, digest in res.items():
                bits = len(digest) * 4
                _append(self._log, f"  {algo:<10}: ({bits:3}b) {digest}", "hash")
        except ImportError:
            # Fallback hashlib
            import hashlib
            msg = self._txt.get().encode()
            _append(self._log, f"[{now()}] Message : {self._txt.get()[:50]}", "info")
            for algo in ["md5", "sha256", "sha512", "sha3_256"]:
                d = hashlib.new(algo, msg).hexdigest()
                _append(self._log, f"  {algo:<12}: {d}", "hash")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _avalanche(self):
        import hashlib
        msg1 = self._txt.get().encode()
        msg2 = bytearray(msg1) if msg1 else b"x"
        if msg2: msg2[0] ^= 0x01
        msg2 = bytes(msg2)
        _append(self._log, f"[{now()}] Avalanche (1 bit flippé) :", "info")
        for algo in ["md5", "sha256", "sha512"]:
            h1 = int(hashlib.new(algo, msg1).hexdigest(), 16)
            h2 = int(hashlib.new(algo, msg2).hexdigest(), 16)
            diff  = bin(h1 ^ h2).count("1")
            total = hashlib.new(algo).digest_size * 8
            _append(self._log, f"  {algo:<8}: {diff}/{total} bits ({diff/total*100:.1f}%) ≈ 50%?", "key")

    def _hmac(self):
        import hmac as _hmac, hashlib
        key = self._hmac_key.get().encode()
        msg = self._txt.get().encode()
        mac = _hmac.new(key, msg, hashlib.sha256).hexdigest()
        _append(self._log, f"[{now()}] HMAC-SHA256 :", "info")
        _append(self._log, f"  Clé : {self._hmac_key.get()}", "key")
        _append(self._log, f"  MAC : {mac}", "ok")

        # Verify
        valid = _hmac.compare_digest(
            _hmac.new(key, msg, hashlib.sha256).hexdigest(), mac)
        tampered_valid = _hmac.compare_digest(
            _hmac.new(key, msg + b"X", hashlib.sha256).hexdigest(), mac)
        _append(self._log, f"  Vérif. msg original : {valid} ✓", "ok")
        _append(self._log, f"  Vérif. msg altéré   : {tampered_valid} ✗", "err")

    def _sha256_pure(self):
        def _run():
            try:
                from sha256_pure import validate_against_hashlib, sha256_hex
                import hashlib
                _append(self._log, f"[{now()}] SHA-256 pur Python vs hashlib :", "info")
                msg = self._txt.get().encode()
                mine   = sha256_hex(msg)
                ref    = hashlib.sha256(msg).hexdigest()
                match  = mine == ref
                self.after(0, lambda: (
                    _append(self._log, f"  pur Python : {mine}", "hash"),
                    _append(self._log, f"  hashlib    : {ref}", "hash"),
                    _append(self._log, f"  Identiques : {match} ✓", "ok")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ sha256_pure.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════
# SIGNATURES NUMÉRIQUES
# ═══════════════════════════════════════════════════════════════════════════

class SignatureSection(tk.Frame):
    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._build()

    def _build(self):
        _section_hdr(self, "✍", "Signatures Numériques",
                     "RSA-PSS · ElGamal · DSA · ECDSA — authenticité, intégrité, non-répudiation")

        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=20, pady=14)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        lf = _card(main)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        _bar(lf, A).pack(fill="x", pady=(0, 10))
        tk.Label(lf.winfo_children()[-1], text="Signature & Vérification",
                 font=FBB, bg=A, fg=T).pack(side="left")

        row1 = tk.Frame(lf, bg=C); row1.pack(fill="x", padx=14, pady=3)
        tk.Label(row1, text="Message :", font=FS, bg=C, fg=DIM, width=10, anchor="w").pack(side="left")
        self._txt = tk.StringVar(value="Document à signer officiellement")
        _entry(row1, self._txt).pack(side="left", fill="x", expand=True)

        row2 = tk.Frame(lf, bg=C); row2.pack(fill="x", padx=14, pady=3)
        tk.Label(row2, text="Schéma :", font=FS, bg=C, fg=DIM, width=10, anchor="w").pack(side="left")
        self._scheme = tk.StringVar(value="RSA-PSS")
        _combo(row2, self._scheme, ["RSA-PSS", "ECDSA (P-256)"], width=14).pack(side="left")

        btnrow = tk.Frame(lf, bg=C); btnrow.pack(fill="x", padx=14, pady=8)
        _btn(btnrow, "Signer", self._sign).pack(side="left")
        _btn(btnrow, "Vérifier (original)", self._verify, accent=MUT).pack(side="left", padx=(6,0))
        _btn(btnrow, "Vérifier (altéré)", self._verify_tampered, accent=ERR).pack(side="left", padx=(6,0))


        self._log = _log(lf, height=18)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        rf = _card(main)
        rf.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        _bar(rf, A).pack(fill="x", pady=(0, 10))
        tk.Label(rf.winfo_children()[-1], text="Propriétés", font=FBB, bg=A, fg=T).pack(side="left")
        tk.Label(rf, text=(
            "Protocole :\nSigner  : S = Sign(SK, H(M))\n"
            "Vérifier: Verify(PK, M, S) ∈ {0,1}\n\n"
            "Garanties :\n• Authenticité\n• Intégrité\n• Non-répudiation\n\n"
            "RSA-PSS :\nS = H(M)ᵈ mod n (avec padding)\n\n"
            "ECDSA :\nk aléatoire\nR = (kG).x mod q\nS = k⁻¹(H(M)+xR) mod q\n\n"
            "ElGamal :\nk aléatoire\nR = gᵏ mod p\nS = k⁻¹(H(M)−xR) mod q\n\n"
            "⚠ k unique à chaque signature !\n(réutilisation → fuite de x)"
        ), font=FS, bg=C, fg=DIM, justify="left", wraplength=280).pack(anchor="nw", pady=6)

    def _sign(self):
        scheme = self._scheme.get()
        msg    = self._txt.get()
        _append(self._log, f"[{now()}] Signature {scheme}…", "warn")
        def _run():
            try:
                if scheme == "RSA-PSS":
                    from rsa_cipher import generate_keypair, sign
                    self._priv_s, self._pub_s = generate_keypair(2048)
                    self._sig = sign(msg.encode(), self._priv_s)
                    self.after(0, lambda: (
                        _append(self._log, f"[{now()}] RSA-PSS 2048-bit", "info"),
                        _append(self._log, f"  Sig ({len(self._sig)} B) : {self._sig.hex()[:48]}…", "ok")
                    ))
                else:
                    from signature import ECDSASignature
                    self._ecdsa = ECDSASignature("P-256")
                    self._sig_ec = self._ecdsa.sign(msg)
                    self.after(0, lambda: (
                        _append(self._log, f"[{now()}] ECDSA P-256", "info"),
                        _append(self._log, f"  Signature : {str(self._sig_ec)[:50]}…", "ok")
                    ))
            except ImportError as ie:
                self.after(0, lambda: _append(self._log, f"⚠ Module manquant : {ie}", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()

    def _verify(self):
        try:
            scheme = self._scheme.get()
            msg    = self._txt.get()
            if scheme == "RSA-PSS":
                from rsa_cipher import verify_signature
                if not hasattr(self, "_sig"):
                    _append(self._log, "⚠ Signez d'abord.", "warn"); return
                ok = verify_signature(msg.encode(), self._sig, self._pub_s)
                _append(self._log, f"[{now()}] Vérif. RSA-PSS : {ok} ✓", "ok" if ok else "err")
            else:
                from signature import ECDSASignature
                if not hasattr(self, "_ecdsa"):
                    _append(self._log, "⚠ Signez d'abord.", "warn"); return
                ok = ECDSASignature.verify(msg, self._sig_ec, self._ecdsa.public_key)
                _append(self._log, f"[{now()}] Vérif. ECDSA : {ok} ✓", "ok" if ok else "err")
        except ImportError as ie:
            _append(self._log, f"⚠ Module manquant : {ie}", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _verify_tampered(self):
        try:
            scheme = self._scheme.get()
            msg    = self._txt.get() + " [ALTÉRÉ]"
            if scheme == "RSA-PSS":
                from rsa_cipher import verify_signature
                if not hasattr(self, "_sig"):
                    _append(self._log, "⚠ Signez d'abord.", "warn"); return
                ok = verify_signature(msg.encode(), self._sig, self._pub_s)
                _append(self._log, f"[{now()}] Vérif. message altéré : {ok} ✗", "err")
            else:
                from signature import ECDSASignature
                if not hasattr(self, "_ecdsa"):
                    _append(self._log, "⚠ Signez d'abord.", "warn"); return
                ok = ECDSASignature.verify(msg, self._sig_ec, self._ecdsa.public_key)
                _append(self._log, f"[{now()}] Vérif. message altéré : {ok} ✗", "err")
        except ImportError as ie:
            _append(self._log, f"⚠ Module manquant : {ie}", "err")
        except Exception as e:
            _append(self._log, f"Erreur : {e}", "err")

    def _elgamal_sign(self):
        def _run():
            try:
                from signature import ElGamalSignature
                msg  = self._txt.get()
                eg   = ElGamalSignature(bits=512)
                sig  = eg.sign(msg)
                ok   = eg.verify(msg, sig)
                bad  = eg.verify(msg + "X", sig)
                self.after(0, lambda: (
                    _append(self._log, f"[{now()}] ElGamal Signature (512-bit)", "info"),
                    _append(self._log, f"  r = {sig[0] % (10**10)}…   s = {sig[1] % (10**10)}…", "key"),
                    _append(self._log, f"  Vérif. original : {ok} ✓", "ok"),
                    _append(self._log, f"  Vérif. altéré   : {bad} ✗", "err")
                ))
            except ImportError:
                self.after(0, lambda: _append(self._log, "⚠ signature.py non trouvé.", "err"))
            except Exception as e:
                self.after(0, lambda: _append(self._log, f"Erreur : {e}", "err"))
        threading.Thread(target=_run, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════
# COMMUNICATIONS SÉCURISÉES (ex gui_tp6)
# ═══════════════════════════════════════════════════════════════════════════

class CommsSection(tk.Frame):
    SUB_NAV = [
        ("🔌", "TCP / IP",  "tcp"),
        ("📡", "Bluetooth", "bt"),
        ("💬", "UDP Chat",  "udp"),
        ("🗳",  "Vote",      "vote"),
    ]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._build()

    def _build(self):
        _section_hdr(self, "🌐", "Communications Sécurisées",
                     "TCP/IP · Bluetooth · UDP Chat · Vote homomorphe (Paillier)")

        sel_bar = tk.Frame(self, bg=S, padx=20, pady=10)
        sel_bar.pack(fill="x")
        self._sub_var = tk.StringVar(value="tcp")
        for icon, label, key in self.SUB_NAV:
            tk.Radiobutton(sel_bar, text=f"{icon} {label}",
                           variable=self._sub_var, value=key,
                           font=FBB, bg=S, fg=DIM,
                           selectcolor=A, activebackground=S,
                           activeforeground=T, cursor="hand2",
                           command=self._switch_sub, pady=4, padx=8).pack(side="left")

        self._pages: dict[str, tk.Frame] = {}
        cont = tk.Frame(self, bg=K)
        cont.pack(fill="both", expand=True)
        for key, cls in [("tcp", TCPSection), ("bt", BTSection),
                          ("udp", UDPSection), ("vote", VoteSection)]:
            p = cls(cont, self.app)
            p.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._pages[key] = p
        self._switch_sub()

    def _switch_sub(self):
        sel = self._sub_var.get()
        for name, frame in self._pages.items():
            (frame.lift if name == sel else frame.lower)()


# ── TCP Section (preserved from original) ─────────────────────────────────

class TCPSection(tk.Frame):
    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app      = app
        self._s_sock  = self._s_conn = self._c_sock = None
        self._s_key   = self._c_key  = None
        self._running = False
        self._sq: queue.Queue = queue.Queue()
        self._cq: queue.Queue = queue.Queue()
        self._build()
        self._poll()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=14, pady=10)
        main.grid_columnconfigure(0, weight=1)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        self._alice_pane = self._peer(main, "🔑 Alice — Serveur", True)
        self._alice_pane.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        self._bob_pane = self._peer(main, "📨 Bob — Client", False)
        self._bob_pane.grid(row=0, column=1, sticky="nsew", padx=(5,0))

        plog_f = tk.Frame(self, bg=C, padx=12, pady=8)
        plog_f.pack(fill="x", padx=14, pady=(0,10))
        tk.Label(plog_f, text="Journal du protocole RSA-2048 + AES-256-GCM",
                 font=FBB, bg=C, fg=G).pack(anchor="w")
        self._plog = _log(plog_f, height=4)
        self._plog.pack(fill="x")

    def _peer(self, parent, title, is_server):
        pane = tk.Frame(parent, bg=C, highlightbackground=D, highlightthickness=1)
        color = A if is_server else "#3b0764"
        bar   = _bar(pane, color)
        bar.pack(fill="x")
        tk.Label(bar, text=title, font=FBB, bg=color, fg=T).pack(side="left")
        st_var = tk.StringVar(value="○ Déconnecté")
        st_lbl = tk.Label(bar, textvariable=st_var, font=FS, bg=color, fg=WRN)
        st_lbl.pack(side="right")

        ctrl = tk.Frame(pane, bg=C, padx=10, pady=6)
        ctrl.pack(fill="x")
        if is_server:
            self._a_st = st_var; self._a_st_lbl = st_lbl
            self._port_var = tk.StringVar(value=str(TCP_PORT))
            tk.Label(ctrl, text="Port:", font=FS, bg=C, fg=DIM).pack(side="left")
            tk.Entry(ctrl, textvariable=self._port_var, width=6,
                     bg=INP, fg=T, insertbackground=T, bd=0, font=FM).pack(side="left", padx=4)
            self._srv_btn = _btn(ctrl, "Démarrer", self._toggle_server)
            self._srv_btn.pack(side="left", padx=(6,0))
        else:
            self._b_st = st_var; self._b_st_lbl = st_lbl
            self._conn_btn = _btn(ctrl, "Connecter", self._connect_client, accent=MUT, fg=DIM)
            self._conn_btn.pack(side="left")

        log = _log(pane, height=9)
        log.pack(fill="both", expand=True, padx=8, pady=(0,4))

        ir = tk.Frame(pane, bg=C, padx=8, pady=6)
        ir.pack(fill="x")
        msg_var = tk.StringVar()
        e = _entry(ir, msg_var)
        e.pack(side="left", fill="x", expand=True)
        cmd = self._send_server if is_server else self._send_client
        if is_server: self._a_log = log; self._a_msg = msg_var
        else:          self._b_log = log; self._b_msg = msg_var
        sb = _btn(ir, "Envoyer 🔒", cmd)
        sb.pack(side="right", padx=(6,0))
        e.bind("<Return>", lambda _: cmd())
        return pane

    def _toggle_server(self):
        if not self._running:
            self._running = True
            self._srv_btn.configure(text="Arrêter", bg=ERR)
            port = int(self._port_var.get())
            self._sq.put(("sys", f"[{now()}] Serveur démarré port {port}…"))
            self._plog_put(f"[{now()}] SERVER bind 127.0.0.1:{port}", "info")
            threading.Thread(target=self._srv_fn, args=(port,), daemon=True).start()
        else:
            self._running = False
            for s in (self._s_conn, self._s_sock):
                try: s and s.close()
                except: pass
            self._s_key = None
            self._srv_btn.configure(text="Démarrer", bg=A)
            self._a_st.set("○ Déconnecté"); self._a_st_lbl.configure(fg=WRN)

    def _srv_fn(self, port):
        try:
            self._s_sock = socket.socket()
            self._s_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._s_sock.bind(("127.0.0.1", port))
            self._s_sock.listen(1)
            self._sq.put(("st", "● En attente…", WRN))
            conn, addr = self._s_sock.accept()
            self._s_conn = conn
            self._sq.put(("sys", f"[{now()}] Connexion {addr[0]}:{addr[1]}"))
            self._plog_put(f"[{now()}] TCP connexion de {addr}", "ok")
            priv, pub = rsa_keygen(2048)
            if priv:
                pub_pem = pub.export_key()
                _send_frame(conn, pub_pem)
                self._plog_put(f"[{now()}] → pub RSA-2048 ({len(pub_pem)} B)", "info")
                enc_key = _recv_frame(conn)
                self._s_key = rsa_dec(enc_key, priv)
                self._plog_put(f"[{now()}] HANDSHAKE OK  clé={self._s_key.hex()[:24]}…", "ok")
            else:
                _send_frame(conn, b"NO_RSA"); _recv_frame(conn)
                self._s_key = hashlib.sha256(b"fallback").digest()
                self._plog_put(f"[{now()}] MODE DÉGRADÉ", "warn")
            self._sq.put(("st", "● Connecté", OK))
            self._sq.put(("enable_conn_btn", None, None))
            while self._running:
                conn.settimeout(0.5)
                try:
                    frame = _recv_frame(conn)
                    if not frame: break
                    nonce, tag, ct = frame[:16], frame[16:32], frame[32:]
                    msg = aes_dec(ct, self._s_key, nonce, tag).decode()
                    self._sq.put(("recv", f"[{now()}] 📨 Bob : {msg}"))
                except socket.timeout: continue
                except: break
        except Exception as e:
            if self._running:
                self._sq.put(("err", f"[{now()}] Erreur serveur : {e}"))

    def _send_server(self):
        msg = self._a_msg.get().strip()
        if not msg or not self._s_conn or not self._s_key: return
        ct, nonce, tag = aes_enc(msg.encode(), self._s_key)
        try:
            _send_frame(self._s_conn, nonce + tag + ct)
            _append(self._a_log, f"[{now()}] 🔒 Vous : {msg}", "sent")
            self._a_msg.set("")
        except Exception as e:
            _append(self._a_log, f"[{now()}] Erreur : {e}", "err")

    def _connect_client(self):
        if self._c_sock: return
        port = int(self._port_var.get())
        _append(self._b_log, f"[{now()}] Connexion à 127.0.0.1:{port}…", "sys")
        threading.Thread(target=self._cli_fn, args=(port,), daemon=True).start()

    def _cli_fn(self, port):
        try:
            s = socket.socket()
            s.connect(("127.0.0.1", port))
            self._c_sock = s
            self._cq.put(("sys", f"[{now()}] Connecté au serveur."))
            pub_pem = _recv_frame(s)
            if pub_pem == b"NO_RSA":
                _send_frame(s, b"OK")
                self._c_key = hashlib.sha256(b"fallback").digest()
            else:
                from Crypto.PublicKey import RSA as _R
                srv_pub = _R.import_key(pub_pem)
                self._c_key = secrets.token_bytes(32)
                enc_k = rsa_enc(self._c_key, srv_pub)
                _send_frame(s, enc_k)
                self._plog_put(f"[{now()}] HANDSHAKE OK  clé={self._c_key.hex()[:24]}…", "ok")
            self._cq.put(("st", "● Connecté", OK))
            while True:
                s.settimeout(0.5)
                try:
                    frame = _recv_frame(s)
                    if not frame: break
                    nonce, tag, ct = frame[:16], frame[16:32], frame[32:]
                    msg = aes_dec(ct, self._c_key, nonce, tag).decode()
                    self._cq.put(("recv", f"[{now()}] 📨 Alice : {msg}"))
                except socket.timeout: continue
                except: break
        except Exception as e:
            self._cq.put(("err", f"[{now()}] Erreur client : {e}"))

    def _send_client(self):
        msg = self._b_msg.get().strip()
        if not msg or not self._c_sock or not self._c_key: return
        ct, nonce, tag = aes_enc(msg.encode(), self._c_key)
        try:
            _send_frame(self._c_sock, nonce + tag + ct)
            _append(self._b_log, f"[{now()}] 🔒 Vous : {msg}", "sent")
            self._b_msg.set("")
        except Exception as e:
            _append(self._b_log, f"[{now()}] Erreur : {e}", "err")

    def _plog_put(self, msg, tag=""):
        self._sq.put(("__plog__", msg, tag))

    def _poll(self):
        for q, log, st_var, st_lbl in [
            (self._sq, self._a_log, self._a_st, self._a_st_lbl),
            (self._cq, self._b_log, self._b_st, self._b_st_lbl),
        ]:
            while not q.empty():
                try:
                    item = q.get_nowait()
                    kind = item[0]
                    if kind == "sys":    _append(log, item[1], "sys")
                    elif kind == "recv": _append(log, item[1], "recv")
                    elif kind == "err":  _append(log, item[1], "err")
                    elif kind == "st":   st_var.set(item[1]); st_lbl.configure(fg=item[2])
                    elif kind == "enable_conn_btn":
                        self._conn_btn.configure(bg=A, fg=T)
                    elif kind == "__plog__":
                        _append(self._plog, item[1], item[2])
                except: pass
        self.after(120, self._poll)


# ── Bluetooth Section ──────────────────────────────────────────────────────

class BTSection(tk.Frame):
    DEVICES = [
        ("B8:27:EB:1A:2F:3C", "Raspberry Pi 4",  -65),
        ("A4:C3:F0:8E:5D:11", "Laptop Ubuntu",    -72),
        ("00:1A:7D:DA:71:13", "Android Phone",    -57),
        ("DC:A6:32:B1:9E:47", "ESP32-WROOM",      -80),
        ("F0:18:98:E3:B4:2A", "Arduino Nano 33",  -69),
    ]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._connected = False
        self._key = None
        self._device = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=14, pady=10)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=3)
        main.grid_rowconfigure(0, weight=1)

        lf = tk.Frame(main, bg=C, highlightbackground=D, highlightthickness=1)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        bar = _bar(lf, SEL); bar.pack(fill="x")
        tk.Label(bar, text="Appareils Bluetooth", font=FBB, bg=SEL, fg=T).pack(side="left")
        self._scan_btn = _btn(bar, "Scan 🔍", self._scan, accent="#4c1d95")
        self._scan_btn.pack(side="right")
        self._devlist = tk.Listbox(lf, bg=S, fg=T, font=FM, bd=0,
                                   selectbackground=A, selectforeground=T,
                                   activestyle="none", height=9)
        self._devlist.pack(fill="both", expand=True, padx=8, pady=8)
        self._devlist.bind("<<ListboxSelect>>", self._on_select)
        self._pair_btn = _btn(lf, "Appairer et connecter", self._pair, accent=MUT, fg=DIM)
        self._pair_btn.pack(fill="x", padx=8, pady=(0,8))

        rf = tk.Frame(main, bg=C, highlightbackground=D, highlightthickness=1)
        rf.grid(row=0, column=1, sticky="nsew", padx=(5,0))
        bar2 = _bar(rf, SEL); bar2.pack(fill="x")
        tk.Label(bar2, text="Transfert chiffré RFCOMM", font=FBB, bg=SEL, fg=T).pack(side="left")
        self._bt_stlbl = tk.Label(bar2, text="○ Non connecté", font=FS, bg=SEL, fg=WRN)
        self._bt_stlbl.pack(side="right")
        self._bt_log = _log(rf, height=14)
        self._bt_log.pack(fill="both", expand=True, padx=8, pady=8)
        ir = tk.Frame(rf, bg=C, padx=8, pady=6); ir.pack(fill="x")
        self._bt_msg = tk.StringVar()
        e = _entry(ir, self._bt_msg); e.pack(side="left", fill="x", expand=True)
        sb = _btn(ir, "Envoyer 🔒", self._bt_send, accent=SEL)
        sb.pack(side="right", padx=(6,0))
        e.bind("<Return>", lambda _: self._bt_send())

    def _scan(self):
        self._devlist.delete(0, "end")
        self._scan_btn.configure(text="Scan…", state="disabled")
        def _do():
            time.sleep(1.0)
            for mac, name, rssi in self.DEVICES:
                self._devlist.insert("end", f"  {name:<22}  {rssi} dBm")
                time.sleep(0.1)
            self.after(0, lambda: self._scan_btn.configure(text="Scan 🔍", state="normal"))
            self.after(0, lambda: _append(self._bt_log,
                f"[{now()}] {len(self.DEVICES)} appareils trouvés.", "sys"))
        threading.Thread(target=_do, daemon=True).start()

    def _on_select(self, _):
        sel = self._devlist.curselection()
        if sel:
            self._device = self.DEVICES[sel[0]]
            self._pair_btn.configure(bg=A, fg=T)

    def _pair(self):
        if not self._device: return
        mac, name, rssi = self._device
        def _do():
            time.sleep(0.6)
            self.after(0, lambda: _append(self._bt_log,
                f"[{now()}] Connexion à {name} ({mac})…", "sys"))
            time.sleep(0.5)
            priv, pub = rsa_keygen(2048)
            if priv:
                self._key = secrets.token_bytes(32)
                enc_k = rsa_enc(self._key, pub)
                self.after(0, lambda: (
                    _append(self._bt_log, f"[{now()}] Clé AES chiffrée RSA ({len(enc_k)} B)", "crypto"),
                    _append(self._bt_log, f"  Clé : {self._key.hex()[:32]}…", "crypto")
                ))
            else:
                self._key = hashlib.sha256(b"bt_demo").digest()
            self._connected = True
            self.after(0, lambda: self._bt_stlbl.configure(text=f"● {name}", fg=OK))
            self.after(0, lambda: _append(self._bt_log, f"[{now()}] Canal RFCOMM sécurisé ✓", "recv"))
        threading.Thread(target=_do, daemon=True).start()

    def _bt_send(self):
        msg = self._bt_msg.get().strip()
        if not msg: return
        if not self._connected:
            messagebox.showwarning("Bluetooth", "Connectez-vous d'abord."); return
        ct, nonce, tag = aes_enc(msg.encode(), self._key)
        _append(self._bt_log, f"[{now()}] 🔒 Envoyé : «{msg}»", "sent")
        _append(self._bt_log, f"  nonce={nonce.hex()[:16]}…  ct={ct.hex()[:24]}…", "crypto")
        self._bt_msg.set("")
        def _sim():
            time.sleep(0.25)
            try:
                pt = aes_dec(ct, self._key, nonce, tag)
                self.after(0, lambda: _append(self._bt_log,
                    f"[{now()}] 📨 Reçu : «{pt.decode()}»", "recv"))
            except Exception as e:
                self.after(0, lambda: _append(self._bt_log, f"Erreur : {e}", "err"))
        threading.Thread(target=_sim, daemon=True).start()


# ── UDP Chat Section ───────────────────────────────────────────────────────

class UDPSection(tk.Frame):
    USERS = [
        ("Alice",   UDP_PORT_BASE,     "#8b5cf6"),
        ("Bob",     UDP_PORT_BASE + 1, "#7c3aed"),
        ("Charlie", UDP_PORT_BASE + 2, "#6d28d9"),
    ]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app = app
        self._user_idx  = 0
        self._socks     = [None, None, None]
        self._running   = False
        self._group_key = hashlib.sha256(b"udp_group_key_demo").digest()
        self._mq: queue.Queue = queue.Queue()
        self._build()
        self._poll()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=14, pady=10)
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        cf = tk.Frame(main, bg=C, highlightbackground=D, highlightthickness=1)
        cf.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        bar = _bar(cf, "#1e1065"); bar.pack(fill="x")
        tk.Label(bar, text="Salon sécurisé AES-256-GCM", font=FBB, bg="#1e1065", fg=T).pack(side="left")
        self._udp_st = tk.Label(bar, text="○ Hors ligne", font=FS, bg="#1e1065", fg=WRN)
        self._udp_st.pack(side="right")
        tags = {u[0]: u[2] for u in self.USERS}
        tags.update({"sys": WRN, "info": G})
        self._chat = _log(cf, height=14, tags=tags)
        self._chat.pack(fill="both", expand=True, padx=8, pady=(8,0))
        ir = tk.Frame(cf, bg=C, padx=8, pady=6); ir.pack(fill="x")
        self._umsg = tk.StringVar()
        e = _entry(ir, self._umsg); e.pack(side="left", fill="x", expand=True)
        _btn(ir, "Envoyer 🔒", self._udp_send, accent="#1e1065").pack(side="right", padx=(6,0))
        e.bind("<Return>", lambda _: self._udp_send())

        rp = tk.Frame(main, bg=C, highlightbackground=D, highlightthickness=1)
        rp.grid(row=0, column=1, sticky="nsew")
        bar2 = _bar(rp, "#1e1065"); bar2.pack(fill="x")
        tk.Label(bar2, text="Participants", font=FBB, bg="#1e1065", fg=T).pack(anchor="w")
        self._user_btns = []
        for i, (name, port, color) in enumerate(self.USERS):
            b = tk.Button(rp, text=f"  ● {name}  (:{port})", anchor="w",
                          font=FBB, bg=C, fg=color, bd=0, relief="flat",
                          padx=12, pady=8, activebackground=D, cursor="hand2",
                          command=lambda idx=i: self._sel_user(idx))
            b.pack(fill="x"); self._user_btns.append(b)
        _sep(rp).pack(fill="x", padx=10, pady=6)
        self._net_btn = _btn(rp, "Démarrer le réseau", self._toggle_net)
        self._net_btn.pack(fill="x", padx=10)
        _sep(rp).pack(fill="x", padx=10, pady=8)
        tk.Label(rp, text="Clé de groupe :", font=FS, bg=C, fg=DIM).pack(anchor="w", padx=12)
        k = self._group_key.hex()
        tk.Label(rp, text=k[:16]+"\n"+k[16:32], font=FM, bg=C, fg=G).pack(anchor="w", padx=12)
        _sep(rp).pack(fill="x", padx=10, pady=6)
        tk.Label(rp, text="Identité :", font=FS, bg=C, fg=DIM).pack(anchor="w", padx=12)
        self._id_lbl = tk.Label(rp, text=self.USERS[0][0], font=FBB,
                                bg=C, fg=self.USERS[0][2])
        self._id_lbl.pack(anchor="w", padx=12)
        self._sel_user(0)

    def _sel_user(self, idx):
        self._user_idx = idx
        n, _, c = self.USERS[idx]
        self._id_lbl.configure(text=n, fg=c)
        for i, b in enumerate(self._user_btns):
            b.configure(bg=D if i == idx else C)

    def _toggle_net(self):
        if not self._running:
            self._running = True
            self._net_btn.configure(text="Arrêter le réseau", bg=ERR)
            self._udp_st.configure(text="● En ligne", fg=OK)
            for i, (_, port, _) in enumerate(self.USERS):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("127.0.0.1", port)); s.settimeout(0.3)
                    self._socks[i] = s
                    threading.Thread(target=self._recv, args=(i,), daemon=True).start()
                except Exception as e:
                    self._mq.put(("sys", f"Erreur port {port}: {e}"))
            self._mq.put(("sys", f"[{now()}] Réseau UDP — 3 participants"))
        else:
            self._running = False
            for i, s in enumerate(self._socks):
                if s:
                    try: s.close()
                    except: pass
                    self._socks[i] = None
            self._net_btn.configure(text="Démarrer le réseau", bg=A)
            self._udp_st.configure(text="○ Hors ligne", fg=WRN)

    def _recv(self, idx):
        s = self._socks[idx]
        while self._running and s:
            try:
                data, _ = s.recvfrom(8192)
                sender  = data[:16].rstrip(b"\x00").decode(errors="replace")
                nonce, tag, ct = data[16:32], data[32:48], data[48:]
                pt  = aes_dec(ct, self._group_key, nonce, tag)
                msg = pt.decode()
                color = next((u[2] for u in self.USERS if u[0] == sender), T)
                self._mq.put(("msg", sender, msg, color))
            except socket.timeout: continue
            except: continue

    def _udp_send(self):
        msg = self._umsg.get().strip()
        if not msg or not self._running: return
        name, my_port, color = self.USERS[self._user_idx]
        ct, nonce, tag = aes_enc(msg.encode(), self._group_key)
        frame = name.encode().ljust(16, b"\x00") + nonce + tag + ct
        for _, port, _ in self.USERS:
            # ← envoie à TOUS les ports y compris le sien
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(frame, ("127.0.0.1", port));
                s.close()
            except:
                pass
        # ← supprimer le self._mq.put() direct
        self._umsg.set("")

    def _poll(self):
        while not self._mq.empty():
            try:
                item = self._mq.get_nowait()
                if item[0] == "msg":
                    _, sender, msg, color = item
                    self._chat.configure(state="normal")
                    self._chat.insert("end", f"[{now()}] ", "sys")
                    self._chat.insert("end", f"{sender}: ", sender)
                    self._chat.insert("end", msg + "\n")
                    self._chat.see("end")
                    self._chat.configure(state="disabled")
                elif item[0] in ("sys", "info"):
                    _append(self._chat, item[1], item[0])
            except: pass
        self.after(120, self._poll)


# ── Vote Section ───────────────────────────────────────────────────────────

class VoteSection(tk.Frame):
    CANDIDATES = ["Alice Dupont", "Bob Martin", "Charlie Lambert"]
    VOTERS     = [f"Électeur {i}" for i in range(1, 7)]
    ICONS      = ["🟣", "🔵", "🟢"]

    def __init__(self, master, app: App):
        super().__init__(master, bg=K)
        self.app       = app
        self._paillier = None
        self._paillier_ok = False
        self._votes    = []
        self._tallies  = None
        self._results  = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=K)
        main.pack(fill="both", expand=True, padx=14, pady=10)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=3)
        main.grid_rowconfigure(0, weight=1)

        lf = tk.Frame(main, bg=C, highlightbackground=D, highlightthickness=1)
        lf.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        bar = _bar(lf, "#4c1d95"); bar.pack(fill="x")
        tk.Label(bar, text="Isoloir numérique", font=FBB, bg="#4c1d95", fg=T).pack(side="left")

        vf = tk.Frame(lf, bg=C, padx=14, pady=10); vf.pack(fill="x")
        tk.Label(vf, text="Identité :", font=FS, bg=C, fg=DIM).pack(anchor="w")
        self._voter_var = tk.StringVar(value=self.VOTERS[0])
        _combo(vf, self._voter_var, self.VOTERS, width=14).pack(anchor="w", pady=4)
        _sep(lf).pack(fill="x", padx=10)
        tk.Label(lf, text="Candidat :", font=FBB, bg=C, fg=T, pady=8).pack(padx=14, anchor="w")
        self._vote_var = tk.IntVar(value=-1)
        for i, (c, ico) in enumerate(zip(self.CANDIDATES, self.ICONS)):
            tk.Radiobutton(lf, text=f"  {ico}  {c}", variable=self._vote_var,
                           value=i, font=FB, bg=C, fg=T, selectcolor=A,
                           activebackground=C, cursor="hand2", pady=5).pack(anchor="w", padx=18)
        _sep(lf).pack(fill="x", padx=10, pady=8)
        self._init_btn = _btn(lf, "⚙  Initialiser Paillier", self._init_paillier, accent=MUT, fg=DIM)
        self._init_btn.pack(fill="x", padx=12, pady=3)
        self._vote_btn = _btn(lf, "🔒  Voter (chiffrer)", self._cast, accent=MUT, fg=DIM)
        self._vote_btn.configure(state="disabled")
        self._vote_btn.pack(fill="x", padx=12, pady=3)
        self._p_lbl = tk.Label(lf, text="Paillier non initialisé", font=FS, bg=C, fg=ERR)
        self._p_lbl.pack(pady=4)

        rf = tk.Frame(main, bg=C, highlightbackground=D, highlightthickness=1)
        rf.grid(row=0, column=1, sticky="nsew")
        bbar = _bar(rf, "#4c1d95"); bbar.pack(fill="x")
        tk.Label(bbar, text="Urne  &  Résultats", font=FBB, bg="#4c1d95", fg=T).pack(side="left")
        self._vote_ct = tk.Label(bbar, text="0 vote(s)", font=FS, bg="#4c1d95", fg=DIM)
        self._vote_ct.pack(side="right")
        self._vlog = _log(rf, height=11)
        self._vlog.pack(fill="both", expand=True, padx=8, pady=8)
        btnrow = tk.Frame(rf, bg=C, padx=8, pady=6); btnrow.pack(fill="x")
        _btn(btnrow, "∑ Dépouillement", self._tally, accent="#4c1d95").pack(side="left")
        _btn(btnrow, "🔓 Révéler", self._reveal, accent=A).pack(side="left", padx=(6,0))
        _btn(btnrow, "↺", self._reset, accent=H, fg=DIM).pack(side="right")
        bars_f = tk.Frame(rf, bg=C, padx=12, pady=8); bars_f.pack(fill="x")
        self._bars = []
        for c, ico in zip(self.CANDIDATES, self.ICONS):
            row = tk.Frame(bars_f, bg=C); row.pack(fill="x", pady=3)
            tk.Label(row, text=f"{ico} {c}", font=FB, bg=C, fg=T,
                     width=18, anchor="w").pack(side="left")
            cv = tk.Canvas(row, bg=D, height=14, width=200, bd=0, highlightthickness=0)
            cv.pack(side="left", padx=6)
            cv.create_rectangle(0, 0, 0, 14, fill=A, outline="", tags="bar")
            lbl = tk.Label(row, text="—", font=FBB, bg=C, fg=DIM, width=4)
            lbl.pack(side="left")
            self._bars.append((cv, lbl))

    def _init_paillier(self):
        if not _PAILLIER:
            self._p_lbl.configure(text="Simulation (sans Paillier)", fg=WRN)
            self._paillier_ok = True
            self._vote_btn.configure(bg=A, fg=T, state="normal")
            return
        self._init_btn.configure(text="Génération…", state="disabled")
        def _do():
            try:
                self._paillier = Paillier(bits=256)
                self.after(0, self._paillier_ready)
            except Exception as e:
                self.after(0, lambda: self._init_btn.configure(text="⚙ Réessayer", state="normal"))
        threading.Thread(target=_do, daemon=True).start()

    def _paillier_ready(self):
        self._paillier_ok = True
        self._init_btn.configure(text="✓ Paillier prêt", bg=OK, fg="#000", state="disabled")
        self._p_lbl.configure(text="Paillier 256-bit actif", fg=OK)
        self._vote_btn.configure(bg=A, fg=T, state="normal")
        _append(self._vlog, f"[{now()}] Paillier initialisé  n={hex(self._paillier.n)[:16]}…", "sys")

    def _cast(self):
        voter = self._voter_var.get()
        cand  = self._vote_var.get()
        if cand < 0: messagebox.showwarning("Vote", "Choisissez un candidat."); return
        if any(v["voter"] == voter for v in self._votes):
            messagebox.showwarning("Vote", f"{voter} a déjà voté."); return
        if not self._paillier_ok:
            messagebox.showwarning("Vote", "Initialisez Paillier d'abord."); return
        if self._paillier and _PAILLIER:
            enc = [self._paillier.encrypt(1 if i == cand else 0)
                   for i in range(len(self.CANDIDATES))]
        else:
            enc = [1 + int.from_bytes(secrets.token_bytes(8), "big") if i == cand
                   else int.from_bytes(hashlib.sha256(f"{voter}{i}".encode()).digest(), "big")
                   for i in range(len(self.CANDIDATES))]
        self._votes.append({"voter": voter, "cand": cand, "enc": enc})
        self._vote_ct.configure(text=f"{len(self._votes)} vote(s)")
        _append(self._vlog, f"[{now()}] ✓ {voter} — vote chiffré déposé", "vote")
        for i, e in enumerate(enc):
            _append(self._vlog, f"   Cand. {i+1}: {hex(e)[:16]}…", "tally")
        used = {v["voter"] for v in self._votes}
        for v in self.VOTERS:
            if v not in used: self._voter_var.set(v); break
        self._vote_var.set(-1)

    def _tally(self):
        if not self._votes: messagebox.showwarning("Dépouillement", "Aucun vote."); return
        _append(self._vlog, f"\n[{now()}] ══ Dépouillement homomorphe ══", "sys")
        if self._paillier and _PAILLIER:
            self._tallies = []
            for i in range(len(self.CANDIDATES)):
                acc = self._paillier.encrypt(0)
                for v in self._votes:
                    acc = self._paillier.add_ciphertexts(acc, v["enc"][i])
                self._tallies.append(acc)
                _append(self._vlog, f"   Cand. {i+1} total chiffré = {hex(acc)[:16]}…", "tally")
        else:
            self._tallies = [sum(1 for v in self._votes if v["cand"]==i)
                             for i in range(len(self.CANDIDATES))]
            for i, t in enumerate(self._tallies):
                _append(self._vlog, f"   Cand. {i+1} total simulé = {t}", "tally")
        _append(self._vlog, "   → Votes individuels restent chiffrés ✓", "sys")

    def _reveal(self):
        if self._tallies is None: messagebox.showwarning("Résultats", "Dépouillez d'abord."); return
        if self._paillier and _PAILLIER:
            self._results = [self._paillier.decrypt(t) for t in self._tallies]
        else:
            self._results = list(self._tallies)
        _append(self._vlog, f"\n[{now()}] ══ RÉSULTATS OFFICIELS ══", "result")
        mx    = max(self._results)
        total = sum(self._results) or 1
        for i, (c, ico, score) in enumerate(zip(self.CANDIDATES, self.ICONS, self._results)):
            crown = " 🏆" if score == mx and mx > 0 else ""
            _append(self._vlog, f"   {ico} {c:<20} {score} vote(s){crown}", "result")
            cv, lbl = self._bars[i]
            w = int((score / total) * 200)
            cv.coords("bar", 0, 0, max(w, 1), 14)
            lbl.configure(text=str(score), fg=OK)

    def _reset(self):
        self._votes.clear(); self._tallies = None; self._results = None
        self._vote_var.set(-1); self._voter_var.set(self.VOTERS[0])
        self._vote_ct.configure(text="0 vote(s)")
        _clear(self._vlog)
        for cv, lbl in self._bars:
            cv.coords("bar", 0, 0, 0, 14); lbl.configure(text="—", fg=DIM)


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = App()
    app.mainloop()