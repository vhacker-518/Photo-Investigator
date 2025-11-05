#!/usr/bin/env python3
"""
image_search_safe_full.py
Safe Image Search GUI with:
 - EXIF reading
 - Screenshot detection (heuristic)
 - OCR (pytesseract) with simple Pillow preprocessing
 - Reverse search: Google Lens, Bing, TinEye, Yandex (manual or auto-upload with consent)
 - Leak check (safe filename-based web scan, no upload)
 - Save report as TXT or PDF
 - Works on Python 3.14 without OpenCV
Requirements:
 pip install pillow exifread piexif requests colorama pytesseract fpdf
Install Tesseract OCR separately and set TESSERACT_CMD below if needed.
"""

import os, sys, threading, webbrowser, requests, json, re, traceback
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageOps, ImageFilter, ImageEnhance, ExifTags

# Optional: configure Tesseract binary path (change if installed elsewhere)
TESSERACT_CMD = r"C:\Program Files\Tesseract-OCR\tesseract.exe"  # change if necessary, or set to None if in PATH

# Try import pytesseract; if missing, set to None and app will warn
try:
    import pytesseract
    if TESSERACT_CMD and Path(TESSERACT_CMD).exists():
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD
except Exception:
    pytesseract = None

# PDF support
try:
    from fpdf import FPDF
    HAVE_FPDF = True
except Exception:
    HAVE_FPDF = False

# UI theme
BANNER_BG = "#063306"
WINDOW_BG = "#0b3a0b"
PANEL_BG = "#0f2f0f"
TEXT_FG = "#e8f5e9"
GOOD_COLOR = "#3ad43a"
BAD_COLOR = "#ff4242"

# Leak keywords for filename-based scan (no upload)
LEAK_KEYWORDS = ["leak","leaked","leaks","breach","dump","pastebin","dox","exposed","reddit","4chan","imgur","onlyfans"]

# ------------------- Helpers -------------------
def safe_str(v):
    if v is None: return None
    try:
        return v.decode(errors="ignore") if isinstance(v, (bytes,bytearray)) else str(v)
    except:
        return None

def human_size(b):
    try: return f"{b/1024/1024:.2f} MB"
    except: return str(b)

def read_all_metadata(path):
    tags = {}
    try:
        im = Image.open(path)
        tags["Format"] = im.format
        tags["Width"], tags["Height"] = im.size
        try:
            exif = im.getexif()
            if exif:
                for k,v in exif.items():
                    tags[ExifTags.TAGS.get(k,k)] = v
        except:
            pass
    except Exception:
        pass
    # exifread
    try:
        import exifread
        with open(path,"rb") as f:
            er = exifread.process_file(f, details=False)
        for k,v in er.items(): tags[k] = safe_str(v)
    except:
        pass
    # piexif
    try:
        import piexif
        px = piexif.load(path)
        for ifd,d in px.items():
            for tag,val in d.items():
                tag_name = piexif.TAGS.get(ifd,{}).get(tag,{}).get("name", f"{ifd}.{tag}")
                if isinstance(val,(bytes,bytearray)):
                    try: val = val.decode(errors="ignore")
                    except: pass
                tags[tag_name] = val
    except:
        pass
    # filesystem fallback
    try:
        st = os.stat(path)
        tags["_filesystem_mtime"] = datetime.fromtimestamp(st.st_mtime)
        tags["_filesize_bytes"] = st.st_size
    except:
        pass
    return tags

# Simple preprocessing with Pillow to improve OCR speed/accuracy (no OpenCV)
def preprocess_image_for_ocr(path, max_side=1600, enhance_text=True):
    img = Image.open(path)
    # Resize to reasonable size
    w,h = img.size
    max_wh = max(w,h)
    if max_wh > max_side:
        scale = max_side / max_wh
        img = img.resize((int(w*scale), int(h*scale)), Image.Resampling.LANCZOS)
    if img.mode not in ("RGB","L"):
        img = img.convert("RGB")
    gray = img.convert("L")
    gray = ImageOps.autocontrast(gray, cutoff=1)
    gray = gray.filter(ImageFilter.UnsharpMask(radius=1, percent=120, threshold=3))
    gray = gray.filter(ImageFilter.MedianFilter(size=3))
    if enhance_text:
        gray = ImageEnhance.Contrast(gray).enhance(1.3)
    return gray

def fast_ocr_path(path, lang='eng', psm=6, oem=1):
    if not pytesseract:
        raise RuntimeError("pytesseract not available")
    img = preprocess_image_for_ocr(path, max_side=1600)
    config = f"--oem {oem} --psm {psm}"
    try:
        text = pytesseract.image_to_string(img, lang=lang, config=config)
    except Exception:
        # fallback without config
        text = pytesseract.image_to_string(img)
    return text.strip()

# Heuristic screenshot detection (no cv2)
COMMON_SCREEN_RES = {(1920,1080),(1366,768),(1600,900),(1536,864),(1440,900),(2560,1440),(3840,2160),(1280,720)}
UI_KEYWORDS = ["start","taskbar","system information","about this mac","control panel","file explorer","windows","macos","settings","task manager"]

def is_probable_screenshot(path, metadata):
    # 1) if EXIF exists -> likely photo
    for k in metadata.keys():
        if isinstance(k,str) and ("DateTime" in k or "Make" in k or "Model" in k):
            return False
    # 2) resolution
    try:
        w = int(metadata.get("Width") or 0)
        h = int(metadata.get("Height") or 0)
        if (w,h) in COMMON_SCREEN_RES or (h,w) in COMMON_SCREEN_RES:
            return True
        if w and h and w>=1000 and abs((w/h)-1.78) < 0.15:
            return True
    except:
        pass
    # 3) OCR keywords
    try:
        txt = fast_ocr_path(path, lang='eng', psm=6)
        cnt = sum(1 for kw in UI_KEYWORDS if kw in (txt or "").lower())
        if cnt >= 1:
            return True
    except Exception:
        pass
    return False

# ------------------- Upload helpers (consent only) -------------------
def upload_0x0st(file_path, timeout=30):
    url = "https://0x0.st"
    with open(file_path,"rb") as f:
        resp = requests.post(url, files={"file": f}, timeout=timeout)
    if resp.status_code == 200:
        return resp.text.strip()
    raise Exception(f"0x0.st upload failed: {resp.status_code} {resp.text[:200]}")

def upload_file_io(file_path, timeout=30):
    url = "https://file.io"
    with open(file_path,"rb") as f:
        resp = requests.post(url, files={"file": f}, timeout=timeout)
    if resp.status_code in (200,201):
        try:
            j = resp.json()
            for key in ("link","url","file"):
                if isinstance(j, dict) and j.get(key) and isinstance(j.get(key), str) and j.get(key).startswith("http"):
                    return j.get(key)
            txt = json.dumps(j)
            import re
            m = re.search(r"https?://[^\s'\"}]+", txt)
            if m: return m.group(0)
        except:
            pass
    raise Exception(f"file.io upload failed: {resp.status_code} {resp.text[:200]}")

def try_upload_with_fallback(file_path, ui_callback=None):
    last_exc = None
    try:
        if ui_callback: ui_callback("Uploading to 0x0.st ...")
        pub = upload_0x0st(file_path)
        if ui_callback: ui_callback("Uploaded to 0x0.st")
        return pub
    except Exception as e:
        last_exc = e
        if ui_callback: ui_callback(f"0x0.st failed: {e}; trying file.io ...")
    try:
        pub = upload_file_io(file_path)
        if ui_callback: ui_callback("Uploaded to file.io")
        return pub
    except Exception as e2:
        if ui_callback: ui_callback(f"file.io failed: {e2}")
        raise Exception(f"Both uploads failed: 0x0.st error: {last_exc} | file.io error: {e2}")

def open_reverse_searches(public_url):
    enc = requests.utils.requote_uri(public_url)
    urls = [
        f"https://www.google.com/searchbyimage?image_url={enc}",
        f"https://www.bing.com/images/search?q=imgurl:{enc}&view=detailv2",
        f"https://yandex.com/images/search?rpt=imageview&url={enc}",
        f"https://tineye.com/search?url={enc}"
    ]
    for u in urls:
        webbrowser.open_new_tab(u)

# ------------------- Leak scan (safe, filename-based) -------------------
def scan_page_for_keywords(url, timeout=10):
    try:
        headers = {"User-Agent":"Mozilla/5.0 ImageSearch/1.0"}
        r = requests.get(url, headers=headers, timeout=timeout)
        txt = r.text.lower()
        hits = {kw: txt.count(kw) for kw in LEAK_KEYWORDS if kw in txt}
        return {"url":url, "ok":True, "hits":hits, "total": sum(hits.values())}
    except Exception as e:
        return {"url":url, "ok":False, "error": str(e), "hits":{}, "total":0}

def assess_risk(total_hits, hosts):
    if total_hits == 0: return "Low"
    if total_hits <= 3: return "Medium"
    return "High"

# ------------------- Report saving -------------------
def save_report_txt(report, default_name="image_report.txt"):
    save_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default_name, filetypes=[("Text files","*.txt")])
    if not save_path: return None
    try:
        with open(save_path,"w",encoding="utf-8") as f:
            f.write("IMAGE SEARCH REPORT\n")
            f.write(json.dumps(report, ensure_ascii=False, indent=2))
        return save_path
    except Exception as e:
        messagebox.showerror("Save failed", str(e))
        return None

def save_report_pdf(report, default_name="image_report.pdf"):
    if not HAVE_FPDF:
        messagebox.showwarning("PDF library missing", "FPDF library not installed. Install with: pip install fpdf")
        return None
    save_path = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile=default_name, filetypes=[("PDF files","*.pdf")])
    if not save_path: return None
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 8, "IMAGE SEARCH REPORT", ln=True)
        pdf.ln(4)
        def add_kv(k,v):
            pdf.set_font("Arial", style="B", size=11)
            pdf.multi_cell(0, 6, f"{k}:")
            pdf.set_font("Arial", size=11)
            if isinstance(v, (dict, list)):
                pdf.multi_cell(0,6, json.dumps(v, ensure_ascii=False, indent=2))
            else:
                pdf.multi_cell(0,6, str(v))
            pdf.ln(1)
        for k in ("file","timestamp","metadata","is_screenshot","ocr_text_excerpt","public_url","leak_summary"):
            if k in report:
                add_kv(k, report[k])
        pdf.output(save_path)
        return save_path
    except Exception as e:
        messagebox.showerror("PDF save failed", str(e))
        return None

# ------------------- GUI App -------------------
class ImageSearchApp:
    def __init__(self, master):
        self.master = master
        master.title("IMAGE SEARCH — SAFE & FULL")
        master.configure(bg=WINDOW_BG)
        master.geometry("1100x760")

        # banner
        banner = tk.Frame(master, bg=BANNER_BG, pady=8)
        banner.pack(fill=tk.X, padx=6, pady=6)
        tk.Label(banner, text="IMAGE SEARCH", font=("Segoe UI Black", 30, "bold"), bg=BANNER_BG, fg="white").pack()
        tk.Label(banner, text="snap: ml-ftt", font=("Segoe UI", 12), bg=BANNER_BG, fg="white").pack()

        # controls
        ctrl = tk.Frame(master, bg=WINDOW_BG)
        ctrl.pack(fill=tk.X, padx=10, pady=(6,4))
        self.select_btn = ttk.Button(ctrl, text="📁 Select Image(s)", command=self.select_files)
        self.select_btn.grid(row=0, column=0, padx=6)
        self.analyze_btn = ttk.Button(ctrl, text="🔎 Analyze", command=self.analyze_selected, state="disabled")
        self.analyze_btn.grid(row=0, column=1, padx=6)
        self.ocr_btn = ttk.Button(ctrl, text="🧾 Detect PC Specs (OCR)", command=self.detect_specs, state="disabled")
        self.ocr_btn.grid(row=0, column=2, padx=6)
        self.open_sites_btn = ttk.Button(ctrl, text="🌐 Open Reverse Sites (manual)", command=self.open_reverse_sites, state="disabled")
        self.open_sites_btn.grid(row=0, column=3, padx=6)
        self.upload_search_btn = ttk.Button(ctrl, text="⬆️ Upload & Search (consent)", command=self.upload_and_search_prompt, state="disabled")
        self.upload_search_btn.grid(row=0, column=4, padx=6)
        self.leak_btn = ttk.Button(ctrl, text="🔎 Check for Leaks (safe)", command=self.check_leaks_safe, state="disabled")
        self.leak_btn.grid(row=0, column=5, padx=6)
        self.save_btn = ttk.Button(ctrl, text="💾 Save Report", command=self.save_report, state="disabled")
        self.save_btn.grid(row=0, column=6, padx=6)
        self.pdf_btn = ttk.Button(ctrl, text="📄 Save PDF (optional)", command=self.save_pdf, state="disabled")
        self.pdf_btn.grid(row=0, column=7, padx=6)
        self.settings_btn = ttk.Button(ctrl, text="⚙️ Settings", command=self.open_settings)
        self.settings_btn.grid(row=0, column=8, padx=6)

        # main layout
        main = tk.Frame(master, bg=WINDOW_BG)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        left = tk.Frame(main, bg=WINDOW_BG)
        left.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(left, text="Selected files:", bg=WINDOW_BG, fg=TEXT_FG).pack(anchor="w")
        self.file_listbox = tk.Listbox(left, width=60, height=18)
        self.file_listbox.pack(padx=4, pady=6)
        self.file_listbox.bind("<<ListboxSelect>>", self.on_select)

        mid = tk.Frame(main, bg=WINDOW_BG)
        mid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12,8))
        tk.Label(mid, text="Metadata (concise):", bg=WINDOW_BG, fg=TEXT_FG).pack(anchor="w")
        self.meta_text = tk.Text(mid, width=70, height=14, bg=PANEL_BG, fg=TEXT_FG, font=("Consolas",11))
        self.meta_text.pack(pady=(4,8))
        self.meta_text.tag_config("found", foreground=GOOD_COLOR)
        self.meta_text.tag_config("missing", foreground=BAD_COLOR)
        tk.Label(mid, text="Preview:", bg=WINDOW_BG, fg=TEXT_FG).pack(anchor="w")
        self.preview_label = tk.Label(mid, bg="black", width=60, height=12)
        self.preview_label.pack(fill=tk.BOTH, expand=True, pady=(6,4))

        right = tk.Frame(main, bg=WINDOW_BG)
        right.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(right, text="Detected PC Specs & OCR:", bg=WINDOW_BG, fg=TEXT_FG).pack(anchor="w")
        self.specs_text = tk.Text(right, width=40, height=12, bg=PANEL_BG, fg=TEXT_FG, font=("Consolas",11))
        self.specs_text.pack(pady=(4,8))
        self.specs_text.tag_config("good", foreground=GOOD_COLOR)
        self.specs_text.tag_config("bad", foreground=BAD_COLOR)
        tk.Label(right, text="History:", bg=WINDOW_BG, fg=TEXT_FG).pack(anchor="w")
        self.history_listbox = tk.Listbox(right, width=40, height=8)
        self.history_listbox.pack(pady=(4,8))

        # status
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(master, textvariable=self.status_var, bg=WINDOW_BG, fg=TEXT_FG, anchor="w").pack(fill=tk.X, padx=10, pady=(0,8))

        # state
        self.selected_files = []
        self.history = []
        self.last_public_url = None
        self.bing_key = None
        self.bing_endpoint = None

    # -------- UI actions --------
    def select_files(self):
        paths = filedialog.askopenfilenames(title="Select images", filetypes=[("All files","*.*")])
        if not paths: return
        self.selected_files = list(paths)
        self.file_listbox.delete(0, tk.END)
        for p in self.selected_files: self.file_listbox.insert(tk.END, p)
        self.analyze_btn.config(state="normal"); self.ocr_btn.config(state="normal")
        self.open_sites_btn.config(state="normal"); self.upload_search_btn.config(state="normal")
        self.leak_btn.config(state="normal"); self.save_btn.config(state="normal"); self.pdf_btn.config(state="normal")
        self.status_var.set(f"{len(self.selected_files)} file(s) selected")

    def on_select(self, event):
        sel = self.file_listbox.curselection()
        if not sel: return
        idx = sel[0]; path = self.selected_files[idx]
        self.show_metadata(path); self.show_preview(path)

    def show_metadata(self, path):
        tags = read_all_metadata(path)
        self.meta_text.configure(state="normal"); self.meta_text.delete("1.0", tk.END)
        self.meta_text.insert(tk.END, f"File: {Path(path).name}\n")
        make = model = None
        for k,v in tags.items():
            kl = str(k).lower()
            if ('make' in kl or 'manufacturer' in kl) and not make: make = safe_str(v)
            if 'model' in kl and not model: model = safe_str(v)
        if make or model: self.meta_text.insert(tk.END, f"  Device: {(make or '')} {(model or '')}\n", "found")
        else: self.meta_text.insert(tk.END, "  Device: Not Found\n", "missing")
        dt = None
        for k in ("DateTimeOriginal","DateTimeDigitized","CreateDate","DateTime"):
            if k in tags:
                dt = safe_str(tags[k]); break
        if dt: self.meta_text.insert(tk.END, f"  Date: {dt}\n", "found")
        else:
            fs = tags.get("_filesystem_mtime")
            if fs: self.meta_text.insert(tk.END, f"  Date: Not Found (fallback: {fs})\n", "missing")
            else: self.meta_text.insert(tk.END, "  Date: Not Found\n", "missing")
        w = tags.get("Width"); h = tags.get("Height")
        if w and h: self.meta_text.insert(tk.END, f"  Resolution: {w}x{h}\n", "found")
        else: self.meta_text.insert(tk.END, "  Resolution: Not Found\n", "missing")
        size = tags.get("_filesize_bytes")
        if size: self.meta_text.insert(tk.END, f"  Size: {human_size(size)}\n", "found")
        else: self.meta_text.insert(tk.END, "  Size: Not Found\n", "missing")
        self.meta_text.configure(state="disabled")

    def show_preview(self, path):
        try:
            im = Image.open(path)
            w,h = im.size
            max_w, max_h = 520, 360
            ratio = min(max_w/w, max_h/h, 1.0)
            nw, nh = int(w*ratio), int(h*ratio)
            from PIL import ImageTk
            im2 = im.resize((nw, nh), Image.Resampling.LANCZOS)
            self.tkimg = ImageTk.PhotoImage(im2)
            self.preview_label.configure(image=self.tkimg, text="")
        except Exception:
            self.preview_label.configure(text="Preview not available", image="")

    def analyze_selected(self):
        if not self.selected_files:
            messagebox.showinfo("No files","Select files first.")
            return
        path = self.selected_files[0]
        self.show_metadata(path); self.show_preview(path)
        self.status_var.set("Analysis complete")

    def detect_specs(self):
        if not self.selected_files:
            messagebox.showinfo("No files","Select files first.")
            return
        path = self.selected_files[0]
        self.status_var.set("Detecting screenshot & running OCR...")
        threading.Thread(target=self._detect_specs_bg, args=(path,), daemon=True).start()

    def _detect_specs_bg(self, path):
        try:
            tags = read_all_metadata(path)
            is_ss = is_probable_screenshot(path, tags)
            ocr_text = ""
            if pytesseract:
                try:
                    ocr_text = fast_ocr_path(path, lang='eng', psm=6)
                except Exception as e:
                    ocr_text = ""
            specs = {}
            # extract basic specs by regex from OCR
            if ocr_text:
                cpu = re.search(r"(Intel.*?Core[^,\n]+|AMD.*?Ryzen[^,\n]*)", ocr_text, re.I)
                gpu = re.search(r"(NVIDIA.*?(?:RTX|GTX|GeForce)?[^\n,;]*|AMD\s*Radeon[^\n,;]*)", ocr_text, re.I)
                ram = re.search(r"(\d{1,3}\s?GB\s?(?:RAM)?)", ocr_text, re.I)
                os_ = re.search(r"(Windows\s*(?:10|11|7|8|XP)?|macOS|Ubuntu|Debian|Linux)", ocr_text, re.I)
                if cpu: specs['CPU'] = cpu.group(0).strip()
                if gpu: specs['GPU'] = gpu.group(0).strip()
                if ram: specs['RAM'] = ram.group(0).strip()
                if os_: specs['OS'] = os_.group(0).strip()
            # update UI
            self.specs_text.configure(state="normal"); self.specs_text.delete("1.0", tk.END)
            self.specs_text.insert(tk.END, f"Likely screenshot: {'YES' if is_ss else 'NO'}\n\n")
            if specs:
                for k,v in specs.items():
                    self.specs_text.insert(tk.END, f"{k}: {v}\n", "good")
            else:
                self.specs_text.insert(tk.END, "No specs detected via OCR.\n", "bad")
            # OCR excerpt
            if ocr_text:
                self.specs_text.insert(tk.END, "\nOCR snippet:\n")
                self.specs_text.insert(tk.END, ocr_text[:800] + ("\n..." if len(ocr_text)>800 else "\n"))
            self.specs_text.configure(state="disabled")
            # append to history
            entry = {"time": datetime.utcnow().isoformat(sep=' '), "file": path, "is_screenshot": bool(is_ss), "specs": specs, "ocr_snippet": ocr_text[:1000]}
            self.history.insert(0, entry)
            self.update_history()
            self.status_var.set("OCR & detection finished")
        except Exception as e:
            traceback.print_exc()
            self.status_var.set(f"Detect error: {e}")

    def open_reverse_sites(self):
        webbrowser.open_new_tab("https://images.google.com/")
        webbrowser.open_new_tab("https://tineye.com/")
        webbrowser.open_new_tab("https://yandex.com/images/")
        webbrowser.open_new_tab("https://www.bing.com/visualsearch")
        self.status_var.set("Opened reverse search sites (manual upload)")

    def upload_and_search_prompt(self):
        if not self.selected_files:
            messagebox.showinfo("No files","Select files first.")
            return
        if not messagebox.askyesno("Consent required", "This WILL upload the selected image to an anonymous host for reverse search. Do you consent?"):
            return
        path = self.selected_files[0]
        threading.Thread(target=self._upload_and_search_worker, args=(path,), daemon=True).start()

    def _upload_and_search_worker(self, path):
        try:
            self.status_var.set("Uploading image for reverse search...")
            pub = try_upload_with_fallback(path, ui_callback=self.status_var.set)
            self.last_public_url = pub
            try:
                self.master.clipboard_clear(); self.master.clipboard_append(pub)
            except:
                pass
            open_reverse_searches(pub)
            self.history.insert(0, {"time": datetime.utcnow().isoformat(sep=' '), "file": path, "public_url": pub})
            self.update_history()
            self.status_var.set("Upload successful; reverse search tabs opened")
        except Exception as e:
            messagebox.showerror("Upload failed", f"Upload failed: {e}")
            self.open_reverse_sites()

    def check_leaks_safe(self):
        if not self.selected_files:
            messagebox.showinfo("No files","Select files first.")
            return
        path = self.selected_files[0]
        filename = Path(path).name
        self.status_var.set("Scanning web for filename-based leak indicators (no upload)...")
        def worker():
            queries = [
                f'{filename} leak',
                f'{filename} leaked',
                f'"{filename}" pastebin',
                f'{filename} site:reddit.com',
            ]
            total = 0; hosts=set(); details=[]
            for q in queries:
                qurl = "https://www.bing.com/search?q=" + requests.utils.requote_uri(q)
                res = scan_page_for_keywords(qurl)
                details.append(res)
                total += res.get("total",0)
                if res.get("total",0)>0 and res.get("ok"):
                    try:
                        page = requests.get(qurl, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
                        found_hosts = set(re.findall(r"https?://([^/]+)/", page.text.lower()))
                        for hk in ("pastebin.com","4chan.org","imgur.com","onlyfans.com","reddit.com"):
                            if any(hk in h for h in found_hosts): hosts.add(hk)
                    except:
                        pass
            risk = assess_risk(total, hosts)
            summary = {"filename": filename, "total_hits": total, "hosts": list(hosts), "risk": risk, "details": details}
            self.history.insert(0, {"time": datetime.utcnow().isoformat(sep=' '), "file": path, "leak_check": summary})
            self.update_history()
            self.master.after(0, lambda: self.show_leak_summary(summary))
            self.status_var.set("Leak-check finished")
        threading.Thread(target=worker, daemon=True).start()

    def show_leak_summary(self, summary):
        win = tk.Toplevel(self.master); win.title("Leak Check Summary")
        txt = tk.Text(win, width=100, height=30); txt.pack(padx=8,pady=8)
        txt.insert(tk.END, json.dumps(summary, ensure_ascii=False, indent=2))
        txt.configure(state="disabled")
        tk.Button(win, text="Copy", command=lambda: (self.master.clipboard_clear(), self.master.clipboard_append(json.dumps(summary, ensure_ascii=False, indent=2)))).pack(pady=6)

    def save_report(self):
        if not self.selected_files:
            messagebox.showinfo("No files","Select files first.")
            return
        path = self.selected_files[0]
        tags = read_all_metadata(path)
        ocr_text = ""
        try:
            if pytesseract:
                ocr_text = fast_ocr_path(path, lang='eng', psm=6)
        except:
            ocr_text = ""
        report = {
            "file": path,
            "timestamp": datetime.utcnow().isoformat(sep=' '),
            "metadata": {k: safe_str(v) for k,v in tags.items()},
            "is_screenshot": is_probable_screenshot(path, tags),
            "ocr_text_excerpt": ocr_text[:4000],
            "public_url": self.last_public_url
        }
        p = save_report_txt(report, default_name=Path(path).stem + "_report.txt")
        if p:
            messagebox.showinfo("Saved", f"Report saved: {p}")

    def save_pdf(self):
        if not HAVE_FPDF:
            messagebox.showwarning("Missing library", "FPDF not installed. Install: pip install fpdf")
            return
        if not self.selected_files:
            messagebox.showinfo("No files","Select files first.")
            return
        path = self.selected_files[0]
        tags = read_all_metadata(path)
        ocr_text = ""
        try:
            if pytesseract:
                ocr_text = fast_ocr_path(path, lang='eng', psm=6)
        except:
            ocr_text = ""
        report = {
            "file": path,
            "timestamp": datetime.utcnow().isoformat(sep=' '),
            "metadata": {k: safe_str(v) for k,v in tags.items()},
            "is_screenshot": is_probable_screenshot(path, tags),
            "ocr_text_excerpt": ocr_text[:4000],
            "public_url": self.last_public_url
        }
        p = save_report_pdf(report, default_name=Path(path).stem + "_report.pdf")
        if p:
            messagebox.showinfo("Saved", f"PDF report saved: {p}")

    def update_history(self):
        self.history_listbox.delete(0, tk.END)
        for ent in self.history[:200]:
            label = f"{Path(ent['file']).name if ent.get('file') else '-'} - {ent.get('time', ent.get('timestamp','-'))}"
            self.history_listbox.insert(tk.END, label)

    def open_settings(self):
        def save():
            self.bing_key = key_var.get().strip() or None
            self.bing_endpoint = endpoint_var.get().strip() or None
            sw.destroy()
            self.status_var.set("Settings saved")
        sw = tk.Toplevel(self.master); sw.title("Settings - Optional Bing API")
        tk.Label(sw, text="Bing Subscription Key (optional):").pack(anchor="w", padx=8, pady=(8,0))
        key_var = tk.StringVar(value=self.bing_key or "")
        tk.Entry(sw, textvariable=key_var, width=80).pack(padx=8,pady=4)
        tk.Label(sw, text="Custom endpoint (optional):").pack(anchor="w", padx=8)
        endpoint_var = tk.StringVar(value=self.bing_endpoint or "")
        tk.Entry(sw, textvariable=endpoint_var, width=80).pack(padx=8,pady=4)
        tk.Button(sw, text="Save", command=save).pack(pady=8)

# ------------------- Run -------------------
def main():
    root = tk.Tk()
    app = ImageSearchApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
