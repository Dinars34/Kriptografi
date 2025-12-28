# Nama File: app.py
import streamlit as st
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image
from io import BytesIO

# Import custom modules
from sbox_core import SBoxConstructor, PredefinedMatrices
from sbox_validation import SBoxValidator
from sbox_testing import SBoxCryptoTest
from sbox_io import SBoxIO
from aes_cipher import AESCipher, AESImageCipher, generate_key_from_password
from encryption_stats import EncryptionStats  # Pastikan file encryption_stats.py ada di folder yang sama

# ==========================================
# 1. KONFIGURASI HALAMAN & CSS BARU
# ==========================================
st.set_page_config(
    page_title="Cryptographic S-Box Forge",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
<style>
    [data-testid="stSidebar"] {display: none;}
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .block-container {padding-top: 1rem; padding-bottom: 2rem;}
    
    .main-title {
        font-family: 'Helvetica Neue', sans-serif;
        font-size: 3rem;
        font-weight: 800;
        background: -webkit-linear-gradient(45deg, #1e3c72, #2a5298);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    
    .status-card {
        background-color: #f8f9fa;
        border-left: 5px solid #1e3c72;
        padding: 15px;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
        background-color: transparent;
        border-bottom: 2px solid #e0e0e0;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 4px 4px 0px 0px;
        color: #4a4a4a;
        font-weight: 600;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #e3f2fd;
        color: #1e3c72;
        border-bottom: 3px solid #1e3c72;
    }

    .content-card {
        background: white;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #e0e0e0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 2. STATE MANAGEMENT
# ==========================================
if 'sbox' not in st.session_state: st.session_state.sbox = None
if 'sbox_name' not in st.session_state: st.session_state.sbox_name = None
if 'validation_results' not in st.session_state: st.session_state.validation_results = None
if 'test_results' not in st.session_state: st.session_state.test_results = None
if 'encrypted_text' not in st.session_state: st.session_state.encrypted_text = None
if 'encrypted_image' not in st.session_state: st.session_state.encrypted_image = None

# ==========================================
# 3. HELPER COMPONENTS
# ==========================================
def display_status_bar():
    if st.session_state.sbox is not None:
        st.markdown(f"""
        <div class="status-card">
            <div>
                <span style="font-size: 1.2rem; font-weight: bold;">🛡️ ACTIVE ENGINE:</span>
                <span style="font-size: 1.2rem; color: #1e3c72; margin-left: 10px;">{st.session_state.sbox_name}</span>
            </div>
            <div style="font-size: 0.9rem; color: #666;">Ready for Analysis & Encryption</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-card" style="border-left: 5px solid #dc3545;">
            <div><span style="font-size: 1.2rem; font-weight: bold; color: #dc3545;">⚠️ NO S-BOX LOADED</span></div>
            <div style="font-size: 0.9rem;">Please construct or import an S-box in the <b>Forge</b> tab.</div>
        </div>
        """, unsafe_allow_html=True)

# ==========================================
# 4. MAIN APP STRUCTURE
# ==========================================
def main():
    st.markdown('<div class="main-title">A E G I S</div>', unsafe_allow_html=True)
    st.markdown('<div style="text-align: center; color: #666; margin-bottom: 20px;">Advanced Encryption Generator & Integrated S-box System</div>', unsafe_allow_html=True)
    
    display_status_bar()
    
    tab_forge, tab_lab, tab_vault, tab_data = st.tabs([
        "🔨 FORGE (Construct)", "🧪 LAB (Analyze)", "🔐 VAULT (Encrypt)", "💾 DATA (I/O)"
    ])
    
    # --- TAB 1: FORGE ---
    with tab_forge:
        col_controls, col_preview = st.columns([1, 1.5], gap="large")
        with col_controls:
            st.markdown("### ⚙️ Configuration")
            with st.container(border=True):
                matrix_option = st.selectbox("Affine Matrix Model:",
                    ["AES (Original)", "K4 (Paper)", "K44 (Best - Paper)", "K81 (Paper)", "K111 (Paper)", "K128 (Paper)", "Custom"])
                
                custom_matrix_text = ""
                if matrix_option == "Custom":
                    st.info("Input 8x8 binary matrix")
                    custom_matrix_text = st.text_area("Matrix Data:", value="1 0 0 0 1 1 1 1\n" * 8, height=150)
                
                constant_option = st.selectbox("Constant Vector:", ["AES (0x63)", "Custom"])
                custom_constant = "11000110"
                if constant_option == "Custom":
                    custom_constant = st.text_input("8-bit binary:", value="11000110")
                
                st.markdown("---")
                if st.button("🚀 Build", type="primary", use_container_width=True):
                    construct_sbox_action(matrix_option, custom_matrix_text, constant_option, custom_constant)

        with col_preview:
            st.markdown("### 👁️ S-Box Preview")
            if st.session_state.sbox is not None:
                preview_mode1, preview_mode2 = st.tabs(["🔥 Heatmap", "🔢 S-box Generated"])
                with preview_mode1:
                    fig = px.imshow(st.session_state.sbox, labels=dict(x="Col", y="Row", color="Value"),
                                   x=[str(i) for i in range(16)], y=[str(i) for i in range(16)],
                                   color_continuous_scale="Viridis", text_auto=True)
                    fig.update_layout(height=450, margin=dict(l=0, r=0, t=0, b=0))
                    st.plotly_chart(fig, use_container_width=True)
                
                with preview_mode2:
                    st.markdown("#### Raw Values")
                    display_format = st.radio("Display Format:", ["Decimal", "Hexadecimal", "Binary"], horizontal=True)
                    df = pd.DataFrame(st.session_state.sbox)
                    df.index = [f"Row {i}" for i in range(16)]
                    df.columns = [f"Col {i}" for i in range(16)]
                    
                    if display_format == "Hexadecimal": df_display = df.applymap(lambda x: f"{x:02X}")
                    elif display_format == "Binary": df_display = df.applymap(lambda x: f"{x:08b}")
                    else: df_display = df
                    st.dataframe(df_display, use_container_width=True, height=400)

                st.markdown("---")
                if st.button("Run Quick Validation Check", use_container_width=True):
                     validate_sbox_action()
            else:
                st.info("Initiate construction to visualize the S-box matrix.")

    # --- TAB 2: LAB ---
    with tab_lab:
        if st.session_state.sbox is None:
            st.warning("⚠️ No S-box to analyze.")
        else:
            st.markdown("### 🔬 Cryptographic Analysis")
            with st.expander("🧪 Test Parameters", expanded=True):
                col_sel, col_act = st.columns([3, 1])
                with col_sel:
                    test_selection = st.multiselect("Select Metrics:",
                        ["NL", "SAC", "BIC-NL", "BIC-SAC", "LAP", "DAP", "DU", "AD", "TO", "CI"],
                        default=["NL", "SAC", "BIC-NL", "BIC-SAC", "LAP", "DAP"])
                with col_act:
                    if st.button("Run Analysis", type="primary", use_container_width=True):
                        run_tests_action(test_selection)

            if st.session_state.test_results:
                st.markdown("#### 📊 Analysis Report")
                results = st.session_state.test_results
                m1, m2, m3, m4 = st.columns(4)
                if 'NL' in results: m1.metric("Nonlinearity", f"{results['NL'][0]}", delta="Max 112", delta_color="off")
                if 'SAC' in results: m2.metric("SAC", f"{results['SAC'][0]:.4f}", delta=f"{results['SAC'][0]-0.5:.4f}", delta_color="inverse")
                if 'BIC_SAC' in results: m3.metric("BIC-SAC", f"{results['BIC_SAC'][0]:.4f}", delta="Ideal 0.5", delta_color="off")
                if 'DU' in results: m4.metric("Diff. Uniformity", f"{results['DU'][0]}", delta="Ideal 4", delta_color="inverse")

                st.markdown("#### 📑 Detailed Metrics")
                summary_data = []
                for test_name, (value, details) in results.items():
                    summary_data.append({
                        'Test': test_name,
                        'Value': f"{value:.5f}" if isinstance(value, float) else str(value),
                        'Ideal': details.get('ideal', 'N/A'),
                        'Score': f"{details.get('score', 0):.2f}%"
                    })
                st.dataframe(pd.DataFrame(summary_data), use_container_width=True, hide_index=True)

    # --- TAB 3: VAULT (ENCRYPTION & ANALYSIS) ---
    with tab_vault:
        if st.session_state.sbox is None:
            st.warning("⚠️ Encryption Engine offline. Load an S-box first.")
        else:
            col_text, col_img = st.columns(2, gap="medium")
            
            # --- TEXT ENCRYPTION SECTION ---
            with col_text:
                st.markdown('<div class="content-card">', unsafe_allow_html=True)
                st.subheader("📝 Text Cipher & Analysis")
                
                aes_mode_t = st.selectbox("AES Mode:", ["ECB", "CBC"], key="text_mode")
                password_t = st.text_input("Security Key:", type="password", key="text_pass")
                
                tt1, tt2, tt3 = st.tabs(["Lock", "Unlock", "📊 Analyze"])
                
                with tt1:
                    txt_in = st.text_area("Plaintext:", height=100)
                    if st.button("Encrypt Text", use_container_width=True):
                        text_encrypt_action(txt_in, password_t, aes_mode_t)
                
                with tt2:
                    cipher_in = st.text_area("Ciphertext (Hex):", height=100, 
                                           value=st.session_state.encrypted_text if st.session_state.encrypted_text else "")
                    if st.button("Decrypt Text", use_container_width=True):
                        text_decrypt_action(cipher_in, password_t, aes_mode_t)

                with tt3:
                    st.markdown("##### Text Security Metrics")
                    if st.session_state.encrypted_text:
                        ct_bytes = bytes.fromhex(st.session_state.encrypted_text)
                        entropy = EncryptionStats.calculate_entropy(ct_bytes)
                        st.metric("Ciphertext Entropy", f"{entropy:.4f}", delta="Ideal 8.0")
                        
                        st.markdown("---")
                        st.markdown("**Avalanche Effect Test**")
                        mod_char = st.text_input("Change 1st char of plaintext:", max_chars=1, value="X")
                        if st.button("Run Avalanche Test"):
                            if txt_in and password_t:
                                key = generate_key_from_password(password_t)
                                cipher = AESCipher(st.session_state.sbox, key, mode=aes_mode_t)
                                c1 = cipher.encrypt(txt_in.encode('utf-8'))
                                mod_text = mod_char + txt_in[1:]
                                c2 = cipher.encrypt(mod_text.encode('utf-8'))
                                av_score = EncryptionStats.calculate_avalanche_text(c1, c2)
                                st.metric("Avalanche Effect", f"{av_score:.2f}%", delta="Ideal 50%")
                            else:
                                st.error("Plaintext/Password missing")
                    else:
                        st.info("Encrypt text first.")
                st.markdown('</div>', unsafe_allow_html=True)

# --- IMAGE ENCRYPTION SECTION (FIXED) ---
            with col_img:
                st.markdown('<div class="content-card">', unsafe_allow_html=True)
                st.subheader("🖼️ Image Cipher & Analysis")
                st.info("Max 1MB")
                
                # [FIX 1] Tambahkan Pilihan Mode untuk Gambar
                col_img_pass, col_img_mode = st.columns([2, 1])
                with col_img_pass:
                    img_pass = st.text_input("Security Key:", type="password", key="img_pass")
                with col_img_mode:
                    img_mode = st.selectbox("Mode:", ["ECB", "CBC"], key="img_aes_mode")
                
                it1, it2, it3 = st.tabs(["Lock", "Unlock", "📊 Analyze"])
                
                with it1:
                    img_file = st.file_uploader("Upload Image:", type=['png', 'jpg'], key="img_up")
                    if img_file and st.button("Encrypt Image", use_container_width=True):
                        # [FIX 2] Gunakan img_mode yang dipilih user, bukan hardcode 'ECB'
                        if not img_pass: 
                            st.warning("Password required")
                        else:
                            try:
                                img = Image.open(img_file)
                                img_arr = np.array(img)
                                key = generate_key_from_password(img_pass)
                                # Gunakan img_mode disini
                                cipher = AESImageCipher(st.session_state.sbox, key, mode=img_mode)
                                enc_bytes, meta = cipher.encrypt_image(img_arr)
                                st.session_state.encrypted_image = {'bytes': enc_bytes, 'metadata': meta}
                                st.success(f"Image encrypted in {img_mode} mode ({len(enc_bytes)} bytes)")
                            except Exception as e: 
                                st.error(str(e))
                
                with it2:
                    if st.session_state.encrypted_image:
                        if st.button("Decrypt Current Image", use_container_width=True):
                            try:
                                data = st.session_state.encrypted_image
                                key = generate_key_from_password(img_pass)
                                # Gunakan img_mode disini juga
                                cipher = AESImageCipher(st.session_state.sbox, key, mode=img_mode)
                                dec_arr = cipher.decrypt_image(data['bytes'], data['metadata'])
                                st.image(Image.fromarray(dec_arr.astype('uint8')), caption="Decrypted Result")
                            except Exception as e: 
                                st.error(f"Failed: {str(e)}")
                    else:
                        st.info("Encrypt an image first.")
                        
                with it3:
                    if st.session_state.encrypted_image:
                        enc_bytes = st.session_state.encrypted_image['bytes']
                        
                        st.markdown("##### 1. Histogram Analysis")
                        if st.button("Show Histogram"):
                            hist_data = EncryptionStats.calculate_histogram(enc_bytes)
                            fig = go.Figure(data=[go.Bar(y=hist_data)])
                            fig.update_layout(title="Cipherimage Histogram", height=300, margin=dict(l=0, r=0, t=30, b=0))
                            st.plotly_chart(fig, use_container_width=True)

                        st.markdown("##### 2. Entropy Analysis")
                        entropy = EncryptionStats.calculate_entropy(enc_bytes)
                        st.metric("Entropy Value", f"{entropy:.5f}", delta="Ideal ~8.0")
                        
                        st.markdown("##### 3. Differential Attack (NPCR & UACI)")
                        st.caption(f"Testing with **{img_mode}** mode. (Use CBC for high scores)")
                        
                        if st.button("Run NPCR & UACI Test"):
                            with st.spinner("Running differential analysis..."):
                                try:
                                    if img_file is not None:
                                        img_file.seek(0)
                                        arr_orig = np.array(Image.open(img_file))
                                        
                                        key = generate_key_from_password(img_pass)
                                        
                                        # [FIX 3] KRUSIAL: Gunakan Mode yang dipilih user (img_mode)
                                        # Sebelumnya ini di-hardcode 'ECB', itulah sebabnya hasil Anda rendah
                                        cipher = AESImageCipher(st.session_state.sbox, key, mode=img_mode)
                                        
                                        # 1. Enkripsi Gambar Asli
                                        c1, _ = cipher.encrypt_image(arr_orig)
                                        
                                        # 2. Modifikasi 1 pixel (XOR Flip)
                                        arr_mod = arr_orig.copy()
                                        if len(arr_mod.shape) == 3: 
                                            arr_mod[0,0,0] = arr_mod[0,0,0] ^ 1
                                        else: 
                                            arr_mod[0,0] = arr_mod[0,0] ^ 1
                                            
                                        # 3. Enkripsi Gambar Modifikasi
                                        c2, _ = cipher.encrypt_image(arr_mod)
                                        
                                        # 4. Hitung Statistik
                                        npcr = EncryptionStats.calculate_npcr(c1, c2)
                                        uaci = EncryptionStats.calculate_uaci(c1, c2)
                                        
                                        c1_met, c2_met = st.columns(2)
                                        with c1_met: 
                                            st.metric("NPCR", f"{npcr:.4f}%", delta="Ideal >99.6%")
                                        with c2_met: 
                                            st.metric("UACI", f"{uaci:.4f}%", delta="Ideal ~33.4%")
                                            
                                        if img_mode == "ECB":
                                            st.warning("⚠️ Low NPCR is expected in ECB mode. Switch to CBC for high security.")
                                    else:
                                        st.error("Re-upload original image.")
                                except Exception as e:
                                    st.error(f"Error: {str(e)}")
                    else:
                        st.info("Encrypt an image first.")
                st.markdown('</div>', unsafe_allow_html=True)

    # --- TAB 4: DATA ---
    with tab_data:
        col_ex, col_im = st.columns(2, gap="large")
        with col_ex:
            st.markdown("### 📤 Export S-box")
            with st.container(border=True):
                if st.session_state.sbox is not None:
                    fmt = st.selectbox("Format:", ["Excel (.xlsx)", "CSV (.csv)", "Text (.txt)"])
                    num_fmt = st.radio("Encoding:", ["Decimal", "Hex", "Binary"], horizontal=True)
                    if st.button("Generate Download Link"):
                        export_action(fmt, num_fmt)
                else:
                    st.info("No data to export.")
        with col_im:
            st.markdown("### 📥 Import S-box")
            with st.container(border=True):
                up_file = st.file_uploader("Upload S-box file:", type=['xlsx', 'csv', 'txt'])
                if up_file: import_action(up_file)

# ==========================================
# 5. ACTION LOGIC
# ==========================================
def construct_sbox_action(matrix_opt, custom_mat_txt, const_opt, custom_const):
    try:
        constructor = SBoxConstructor()
        if matrix_opt == "AES (Original)":
            mat = PredefinedMatrices.get_aes_matrix(); name = "AES S-box"
        elif matrix_opt == "Custom":
            rows = custom_mat_txt.strip().split('\n')
            mat = np.array([[int(x) for x in row.split()] for row in rows], dtype=np.uint8)
            name = "Custom S-box"
        else:
            map_mat = {
                "K4 (Paper)": PredefinedMatrices.get_k4(),
                "K44 (Best - Paper)": PredefinedMatrices.get_k44(),
                "K81 (Paper)": PredefinedMatrices.get_k81(),
                "K111 (Paper)": PredefinedMatrices.get_k111(),
                "K128 (Paper)": PredefinedMatrices.get_k128()
            }
            mat = map_mat[matrix_opt]
            name = f"S-box {matrix_opt.split()[0]}"

        if const_opt == "AES (0x63)": const = PredefinedMatrices.get_aes_constant()
        else: const = np.array([[int(x) for x in custom_const]], dtype=np.uint8).T

        sbox = constructor.construct_sbox(mat, const)
        st.session_state.sbox = sbox
        st.session_state.sbox_name = name
        st.rerun()
    except Exception as e: st.error(f"Construction Error: {str(e)}")

def validate_sbox_action():
    validator = SBoxValidator()
    is_valid, results = validator.validate_sbox(st.session_state.sbox)
    if is_valid: st.toast("✅ Valid!", icon="✅")
    else: st.toast("❌ Invalid", icon="❌")
    with st.expander("Validation Details"):
        c1, c2 = st.columns(2)
        c1.metric("Balanced", "PASS" if results['balanced'] else "FAIL")
        c2.metric("Bijective", "PASS" if results['bijective'] else "FAIL")

def run_tests_action(selection):
    with st.spinner("Analyzing..."):
        tester = SBoxCryptoTest(st.session_state.sbox)
        results = {}
        test_map = {
            'NL': tester.test_nonlinearity, 'SAC': tester.test_sac,
            'BIC-NL': tester.test_bic_nl, 'BIC-SAC': tester.test_bic_sac,
            'LAP': tester.test_lap, 'DAP': tester.test_dap,
            'DU': tester.test_differential_uniformity, 'AD': tester.test_algebraic_degree,
            'TO': tester.test_transparency_order, 'CI': tester.test_confusion_index
        }
        for t in selection: results[t] = test_map[t]()
        st.session_state.test_results = results
        st.rerun()

def text_encrypt_action(text, pwd, mode):
    if not text or not pwd: st.warning("Required fields missing"); return
    try:
        key = generate_key_from_password(pwd)
        cipher = AESCipher(st.session_state.sbox, key, mode=mode)
        ct = cipher.encrypt(text.encode('utf-8'))
        st.session_state.encrypted_text = ct.hex()
        st.success("Encrypted!")
    except Exception as e: st.error(str(e))

def text_decrypt_action(hex_text, pwd, mode):
    if not hex_text or not pwd: st.warning("Required fields missing"); return
    try:
        ct = bytes.fromhex(hex_text.strip())
        key = generate_key_from_password(pwd)
        cipher = AESCipher(st.session_state.sbox, key, mode=mode)
        pt = cipher.decrypt(ct).decode('utf-8')
        st.code(pt, language="text")
    except Exception as e: st.error(f"Failed: {str(e)}")

def image_encrypt_action(file, pwd):
    if not pwd: st.warning("Password required"); return
    try:
        img = Image.open(file)
        img_arr = np.array(img)
        key = generate_key_from_password(pwd)
        cipher = AESImageCipher(st.session_state.sbox, key, mode='ECB')
        enc_bytes, meta = cipher.encrypt_image(img_arr)
        st.session_state.encrypted_image = {'bytes': enc_bytes, 'metadata': meta}
        st.success(f"Image encrypted ({len(enc_bytes)} bytes)")
    except Exception as e: st.error(str(e))

def image_decrypt_action(pwd):
    try:
        data = st.session_state.encrypted_image
        key = generate_key_from_password(pwd)
        cipher = AESImageCipher(st.session_state.sbox, key, mode='ECB')
        dec_arr = cipher.decrypt_image(data['bytes'], data['metadata'])
        st.image(Image.fromarray(dec_arr.astype('uint8')), caption="Decrypted Result")
    except Exception as e: st.error(f"Failed: {str(e)}")

def export_action(fmt, num_fmt):
    try:
        name = st.session_state.sbox_name.replace(" ", "_")
        if "Excel" in fmt:
            data = SBoxIO.export_to_excel(st.session_state.sbox, f"{name}.xlsx", [num_fmt.lower()])
            mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            fname = f"{name}.xlsx"
        elif "CSV" in fmt:
            data = SBoxIO.export_to_csv(st.session_state.sbox, num_fmt.lower()).encode()
            mime = "text/csv"; fname = f"{name}.csv"
        else:
            data = SBoxIO.export_to_txt(st.session_state.sbox, num_fmt.lower()).encode()
            mime = "text/plain"; fname = f"{name}.txt"
        st.download_button("⬇️ Download", data, fname, mime)
    except Exception as e: st.error(str(e))

def import_action(file):
    try:
        ftype = file.name.split('.')[-1].lower()
        content = file.read()
        if ftype == 'xlsx': s, box, m = SBoxIO.import_from_excel(content)
        elif ftype == 'csv': s, box, m = SBoxIO.import_from_csv(content.decode())
        else: s, box, m = SBoxIO.import_from_txt(content.decode())
        
        if s:
            st.session_state.sbox = box
            st.session_state.sbox_name = f"Imported: {file.name}"
            st.success("Import Successful!")
            st.rerun()
        else: st.error(m)
    except Exception as e: st.error(str(e))

if __name__ == "__main__":
    main()