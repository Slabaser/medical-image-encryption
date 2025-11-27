import streamlit as st
from PIL import Image
import io
import os
import matplotlib.pyplot as plt
import numpy as np
from src.crypto_engine import ChaoticCipherEngine, SteganographyEngine, load_image_to_bytes, analyze_histogram, calculate_correlation, calculate_hash
from src.crypto_engine import ChaoticCipherEngine, load_image_to_bytes, analyze_histogram, calculate_correlation, calculate_hash

# -----------------------------------------------------------
# STREAMLIT KONFİGÜRASYONU VE ARAYÜZ
# -----------------------------------------------------------

st.set_page_config(
    page_title="SecureLens: Tıbbi Görüntü Analizi",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("SecureLens 🩺 Kaotik Hibrit AES Analiz Uygulaması")
st.markdown("##### Tıbbi Görüntülerin (MRI/X-Ray) Güvenli İletimi İçin Geliştirilmiştir.")

# Session State başlatma
if 'stego' not in st.session_state:
    st.session_state.stego = SteganographyEngine()
if 'engine' not in st.session_state:
    st.session_state.engine = ChaoticCipherEngine()
    st.session_state.key = None
    st.session_state.iv = None
    st.session_state.encrypted_data = None
    st.session_state.original_data = None
    st.session_state.original_hash = None
    st.session_state.decrypted_hash = None

# -----------------------------------------------------------
# SİDEBAR KONTROLLERİ
# -----------------------------------------------------------

# -----------------------------------------------------------
# SİDEBAR KONTROLLERİ (GÜNCELLENMİŞ HALİ)
# -----------------------------------------------------------

with st.sidebar:
    st.header("1. Kontroller")
    uploaded_file = st.file_uploader("Tıbbi Görüntü Seçiniz (PNG/JPG)", type=["png", "jpg", "jpeg"])
    
    # --- YENİ: Gizli Mesaj Girişi ---
    secret_text = st.text_input("Gizlenecek Hasta Notu / TC:", placeholder="Örn: Hasta ID: 123456 - Acil Durum")
    # --------------------------------
    
    if uploaded_file is not None:
        try:
            image_bytes = uploaded_file.read()
            # İlk yüklemede orijinal veriyi al
            if st.session_state.original_data is None: 
                st.session_state.original_data = image_bytes
                st.session_state.original_hash = calculate_hash(image_bytes)
            st.success("Görüntü Yüklendi.")
        except Exception as e:
            st.error(f"Dosya okuma hatası: {e}")

    # Şifreleme Butonu
    if st.button("🔒 Gizle ve Şifrele", disabled=st.session_state.original_data is None):
        if st.session_state.original_data:
            with st.spinner('1. Adım: Veri Gizleniyor (Steganografi)...'):
                # 1. Önce mesajı gizle (Varsa)
                data_to_encrypt = st.session_state.original_data
                if secret_text:
                    try:
                        data_to_encrypt = st.session_state.stego.embed_data(st.session_state.original_data, secret_text)
                        st.info("✅ Hasta notu resmin piksellerine gizlendi.")
                    except ValueError as ve:
                        st.error(f"Hata: {ve}")
                        st.stop()

            with st.spinner('2. Adım: Kaotik Şifreleme Yapılıyor...'):
                # 2. Sonra şifrele
                encrypted_data, duration, key, iv = st.session_state.engine.encrypt_image(data_to_encrypt)
                
                st.session_state.encrypted_data = encrypted_data
                st.session_state.key = key
                st.session_state.iv = iv
                st.session_state.original_hash = calculate_hash(data_to_encrypt) # Hash artık gizli verili halin hash'i
                
                st.success(f"✅ Çift Katmanlı İşlem Başarılı! (Süre: {duration:.2f} ms)")
        else:
            st.warning("Lütfen önce bir görüntü yükleyin.")

    # Şifre Çözme Butonu
    if st.button("🔓 Şifreyi Çöz ve Oku", disabled=st.session_state.encrypted_data is None):
        if st.session_state.encrypted_data and st.session_state.key:
            with st.spinner('Şifre Çözülüyor ve Gizli Veri Aranıyor...'):
                try:
                    # 1. Şifreyi Çöz
                    decrypted_data = st.session_state.engine.decrypt_image(
                        st.session_state.encrypted_data, 
                        st.session_state.key, 
                        st.session_state.iv
                    )
                    st.session_state.decrypted_data = decrypted_data
                    st.session_state.decrypted_hash = calculate_hash(decrypted_data)
                    
                    # 2. Gizli Mesajı Oku
                    extracted_msg = st.session_state.stego.extract_data(decrypted_data)
                    
                    st.success("✅ Şifre Çözme Başarılı.")
                    if extracted_msg:
                        st.markdown(f"### 🕵️ Bulunan Gizli Mesaj:\n**{extracted_msg}**")
                        st.balloons() # Şov olsun diye :)
                    else:
                        st.info("Resim içinde gizli mesaj bulunamadı.")
                        
                except ValueError as e:
                    st.error(f"Şifre çözme hatası: {e}")
                except Exception as e:
                    st.error(f"Genel hata: {e}")

# -----------------------------------------------------------
# ANA PANEL VE GÖRSELLEŞTİRME
# -----------------------------------------------------------

col1, col2, col3 = st.columns(3)

# Sütun 1: Orijinal
with col1:
    st.header("Orijinal Veri")
    if st.session_state.original_data:
        image = Image.open(io.BytesIO(st.session_state.original_data))
        # DÜZELTME: use_container_width kullanıldı
        st.image(image, caption="Yüklenen Tıbbi Görüntü", use_container_width=True)
        
        if st.session_state.original_hash:
            st.caption(f"SHA-256 Hash: {st.session_state.original_hash[:10]}...")
            st.caption(f"Korelasyon: {calculate_correlation(st.session_state.original_data)}")
    else:
        st.info("Görüntü yüklenmeyi bekliyor...")

# Sütun 2: Şifreli / Çözülmüş
with col2:
    st.header("Şifreli / Çözülmüş")
    if st.session_state.encrypted_data:
        try:
            data = np.frombuffer(st.session_state.encrypted_data, dtype=np.uint8)
            size = int(np.sqrt(len(data)))
            # Eğer tam kare değilse sığdırmak için kırpma/ayarlama gerekebilir,
            # görselleştirme için basitçe ilk kare kısmı alıyoruz:
            valid_size = size * size
            noise_array = data[:valid_size].reshape((size, size))
            noise_img = Image.fromarray(noise_array, mode='L')
            
            # DÜZELTME: use_container_width kullanıldı
            st.image(noise_img, caption="🔒 Şifreli Gürültü (Ham Baytlar)", use_container_width=True)
            st.caption("Verinin tamamı şifreli gürültüye dönüşmüştür.")
        except Exception:
            st.warning("Şifreli veri görselleştirilemedi.")
    
    if 'decrypted_data' in st.session_state and st.session_state.decrypted_data:
        st.subheader("✅ Şifresi Çözüldü")
        decrypted_image = Image.open(io.BytesIO(st.session_state.decrypted_data))
        # DÜZELTME: use_container_width kullanıldı
        st.image(decrypted_image, caption="Şifresi Çözülmüş Görüntü (Sağlama)", use_container_width=True)
        
        if st.session_state.original_hash == st.session_state.decrypted_hash:
             st.success("VERİ BÜTÜNLÜĞÜ SAĞLANDI!")
        else:
             st.error("Veri Bütünlüğü Kaybı!")

# Sütun 3: Analiz
with col3:
    st.header("Analiz Raporu")
    st.subheader("Piksel Dağılımı (Histogram)")
    
    if st.session_state.original_data:
        original_hist = analyze_histogram(st.session_state.original_data, is_encrypted=False)
        
        fig, ax = plt.subplots()
        ax.plot(original_hist, color='blue', label='Orijinal Veri')
        ax.set_title("Histogram Analizi")
        ax.set_xlabel("Piksel Değeri")
        ax.set_ylabel("Sıklık")
        
        if st.session_state.encrypted_data:
            encrypted_hist = analyze_histogram(st.session_state.encrypted_data, is_encrypted=True)
            ax.plot(encrypted_hist, color='red', label='Şifreli Gürültü')
            ax.legend()
        
        st.pyplot(fig)
        
        if st.session_state.encrypted_data:
            st.info("Kırmızı çizginin düz olması, şifrelemenin başarısını kanıtlar.")

# Talimatlar
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Güncel Anahtar:** {str(st.session_state.key)[:20]}..." if st.session_state.key else "**Anahtar:** Yok")