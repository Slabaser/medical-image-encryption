### 1. İndirme
```bash
git clone https://github.com/Slabaser/medical-image-encryption.git
cd medical-image-encryption
```

### 2. Kurulum (Conda ile)
```bash
conda create --name medical-env python=3.9 -y
conda activate medical-env
pip install -r requirements.txt
```

### 3. Çalıştırma
```bash
# Önemli: Komutlar ana dizinde çalıştırılmalıdır.
export PYTHONPATH=$PWD
streamlit run src/app_streamlit.py
```
