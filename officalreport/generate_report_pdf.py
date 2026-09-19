import base64
import os
import shutil
import subprocess

def generate_all_pdfs():
    work_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(work_dir, ".."))
    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    
    if not os.path.exists(chrome_path):
        print(f"[-] Chrome executable not found at {chrome_path}")
        return

    # 1. Official Project Report PDF
    print("[*] Generating VibeGuard_Project_Report.pdf...")
    template_path = os.path.join(work_dir, "report_template.html")
    html_out_path = os.path.join(work_dir, "VibeGuard_Project_Report.html")
    pdf_out_path = os.path.join(work_dir, "VibeGuard_Project_Report.pdf")
    root_pdf_path = os.path.join(root_dir, "VibeGuard_Project_Report.pdf")

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    def get_b64(fname):
        img_path = os.path.join(work_dir, fname)
        with open(img_path, "rb") as f:
            return "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")

    s1 = get_b64("Screenshot 1.png")
    s2 = get_b64("Screenshot 2.png")
    s3 = get_b64("Screenshot 3.png")
    html_content = template.replace("{{SCREENSHOT_1}}", s1).replace("{{SCREENSHOT_2}}", s2).replace("{{SCREENSHOT_3}}", s3)

    with open(html_out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    render_pdf(chrome_path, html_out_path, pdf_out_path, root_pdf_path)

    # 2. PO & PSO Mapping PDF
    print("[*] Generating VibeGuard_PO_PSO_Mapping.pdf...")
    po_html = os.path.join(work_dir, "po_pso_mapping_template.html")
    po_pdf = os.path.join(work_dir, "VibeGuard_PO_PSO_Mapping.pdf")
    root_po_pdf = os.path.join(root_dir, "VibeGuard_PO_PSO_Mapping.pdf")
    render_pdf(chrome_path, po_html, po_pdf, root_po_pdf)

    # 3. SDG Mapping PDF
    print("[*] Generating VibeGuard_SDG_Mapping.pdf...")
    sdg_html = os.path.join(work_dir, "sdg_mapping_template.html")
    sdg_pdf = os.path.join(work_dir, "VibeGuard_SDG_Mapping.pdf")
    root_sdg_pdf = os.path.join(root_dir, "VibeGuard_SDG_Mapping.pdf")
    render_pdf(chrome_path, sdg_html, sdg_pdf, root_sdg_pdf)

    # 4. Problem Statement PDF
    print("[*] Generating VibeGuard_Problem_Statement.pdf...")
    ps_html = os.path.join(work_dir, "problem_statement_template.html")
    ps_pdf = os.path.join(work_dir, "VibeGuard_Problem_Statement.pdf")
    root_ps_pdf = os.path.join(root_dir, "VibeGuard_Problem_Statement.pdf")
    render_pdf(chrome_path, ps_html, ps_pdf, root_ps_pdf)

    # 5. Outcome PDF
    print("[*] Generating VibeGuard_Outcome.pdf...")
    oc_html = os.path.join(work_dir, "outcome_template.html")
    oc_pdf = os.path.join(work_dir, "VibeGuard_Outcome.pdf")
    root_oc_pdf = os.path.join(root_dir, "VibeGuard_Outcome.pdf")
    render_pdf(chrome_path, oc_html, oc_pdf, root_oc_pdf)

def render_pdf(chrome_path, src_html, dest_pdf, root_dest_pdf):
    cmd = [
        chrome_path,
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        "--no-pdf-header-footer",
        f"--print-to-pdf={dest_pdf}",
        src_html
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0 and os.path.exists(dest_pdf):
        sz = os.path.getsize(dest_pdf)
        print(f"[+] Successfully generated: {dest_pdf} ({sz} bytes)")
        try:
            shutil.copyfile(dest_pdf, root_dest_pdf)
            print(f"[+] Copied to root: {root_dest_pdf}")
        except PermissionError:
            print(f"[!] Note: {root_dest_pdf} is currently open in another program. File updated in {dest_pdf}")
        except Exception as e:
            print(f"[!] Warning copying to root: {e}")
    else:
        print(f"[-] Failed to generate {dest_pdf}: {res.stderr}")

if __name__ == "__main__":
    generate_all_pdfs()
