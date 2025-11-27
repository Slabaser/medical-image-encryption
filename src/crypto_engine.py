import numpy as np
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import hashlib

class ChaoticCipherEngine:
    """
    Tıbbi görüntülerin güvenliği için Kaotik Harita tabanlı hibrit AES-256 motoru.
    Bu sınıf, anahtar üretimi, şifreleme/çözme ve histogram analizi yapar.
    """
    def __init__(self, key_length=32):
        # AES-256 için anahtar uzunluğu (256 bit = 32 byte)
        self.key_length = key_length 
        # Lojistik Harita parametreleri
        self.chaos_rate = 3.999
        self.chaos_seed = 0.5 

    def _generate_chaos_key(self, length):
        """
        Lojistik Harita (Chaos Theory) kullanarak kriptografik anahtar üretir.
        Bu, AES'i standart şifrelemeden ayıran 'güncel' kısımdır.
        """
        x = self.chaos_seed
        chaos_sequence = []
        
        # 1. Isınma (Warm-up): İlk 100 değeri atlar (Tahmin edilebilirliği azaltır)
        for _ in range(100):
            x = self.chaos_rate * x * (1 - x)

        # 2. Anahtar Üretimi
        for _ in range(length):
            x = self.chaos_rate * x * (1 - x)
            # Üretilen float (0-1) değerini 0-255 aralığına taşıyıp byte'a çevir
            byte_val = int((x * 256 * 1000) % 256)
            chaos_sequence.append(byte_val)
            
        return bytes(chaos_sequence)

    def encrypt_image(self, image_data: bytes):
        """
        Görüntü bayt dizisini Kaotik Anahtar ile AES-CBC modunda şifreler.
        Dönüş: Şifreli veri, süre, kullanılan Anahtar ve IV.
        """
        start_time = time.time()
        
        # 1. Kaotik Anahtar ve IV üretimi
        self.key = self._generate_chaos_key(length=self.key_length)
        self.iv = get_random_bytes(16) # Her zaman rastgele 16 byte IV

        # 2. Şifreleme
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # Görüntü bayt dizisi blok boyutuna tamamlanır
        padded_data = pad(image_data, AES.block_size) 
        encrypted_data = cipher.encrypt(padded_data)
        
        duration = (time.time() - start_time) * 1000 # ms cinsinden süre
        
        # 3. Şifre Çözme için kullanılacak bilgileri döndür
        return encrypted_data, duration, self.key, self.iv

    def decrypt_image(self, encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """ Şifreli veriyi çözerek orijinal bayt dizisine döndürür. """
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded_data = cipher.decrypt(encrypted_data)
            # Dolguyu geri al (Padding kaldırma)
            decrypted_data = unpad(decrypted_padded_data, AES.block_size)
            return decrypted_data
        except ValueError as e:
            # Kritik: Anahtar/IV uyuşmadığında bu hata fırlatılır.
            raise ValueError(f"Şifre çözme başarısız! Anahtar/Veri uyumsuzluğu. Hata: {e}")

# --- ANALİZ VE YARDIMCI FONKSİYONLAR ---

def load_image_to_bytes(file_path: str) -> bytes:
    """ Dosya yolundan görüntüyü okur ve bayt dizisine dönüştürür. """
    try:
        img = Image.open(file_path)
        img_byte_array = io.BytesIO()
        # PNG formatı, JPEG'e göre daha az kayıp yaşadığı için şifrelemede daha stabildir.
        img.save(img_byte_array, format='PNG') 
        return img_byte_array.getvalue()
    except Exception as e:
        raise FileNotFoundError(f"Görüntü okunamadı veya dosya yolu hatalı: {e}")

def analyze_histogram(image_bytes: bytes, is_encrypted: bool) -> np.ndarray:
    """ 
    Histogram verisini hesaplar. Şifreli veri için ham bayt dağılımına bakar.
    """
    try:
        # Şifreli değilse (orijinal/çözülmüş), PIL ile açıp tek kanala (griye) çevirir.
        if not is_encrypted:
            img = Image.open(io.BytesIO(image_bytes)).convert('L')
            data = np.array(img).ravel()
        else:
            # Şifreliyse, ham bayt dizisinin dağılımına bakar (rastgelelik kanıtı)
            data = np.frombuffer(image_bytes, dtype=np.uint8)

        # 0-255 aralığında histogram verisi hesapla
        hist, bins = np.histogram(data, 256, [0, 256])
        return hist
    except Exception as e:
        print(f"Histogram analizi hatası: {e}")
        return np.zeros(256)

def calculate_hash(data: bytes) -> str:
    """ Verinin bütünlüğünü kanıtlamak için SHA-256 hash değeri hesaplar. """
    return hashlib.sha256(data).hexdigest()

def calculate_correlation(image_bytes: bytes) -> float:
    """
    Korelasyon katsayısını hesaplar. Şifreli görüntüde 0'a yakın olmalıdır.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('L')
        img_array = np.array(img)
        # Basit bir yatay pikseller arası korelasyon hesapla
        x = img_array[:, :-1].ravel()
        y = img_array[:, 1:].ravel()
        
        # NumPy'ın korelasyon fonksiyonunu kullan
        correlation = np.corrcoef(x, y)[0, 1]
        return round(float(correlation), 4)
    except Exception:
        # Şifreli veri için hata verirse -1 döndür
        return -1.0
    
    # src/crypto_engine.py dosyasının EN ALTINA ekleyin

class SteganographyEngine:
    """
    LSB (Least Significant Bit) yöntemiyle görüntünün içine metin gizler.
    Bu, görüntü şifrelenmeden önce yapılan 'Veri Gizleme' katmanıdır.
    """
    
    def __str_to_bin(self, message):
        """Metni binary (010101) formatına çevirir."""
        return ''.join(format(ord(i), '08b') for i in message)

    def __bin_to_str(self, binary_data):
        """Binary veriyi tekrar okunabilir metne çevirir."""
        all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
        decoded_data = ""
        for byte in all_bytes:
            decoded_data += chr(int(byte, 2))
            if decoded_data.endswith("#####"): # Bitiş işaretçisi
                return decoded_data[:-5]
        return decoded_data

    def embed_data(self, image_bytes, secret_message):
        """
        Görüntü baytlarına gizli mesajı gömer.
        Dönüş: Mesaj gizlenmiş yeni görüntü baytları.
        """
        img = Image.open(io.BytesIO(image_bytes))
        img = img.convert("RGB") # LSB için RGB şart
        data = np.array(img)
        
        # Mesajı hazırla ve sonuna bitiş işareti (#####) ekle
        secret_message += "#####"
        binary_message = self.__str_to_bin(secret_message)
        data_len = len(binary_message)
        
        # Görüntü kapasite kontrolü
        if data_len > data.size:
            raise ValueError(f"Mesaj çok uzun! Bu resim en fazla {data.size} bit saklayabilir.")
        
        # Pikselleri düzleştir ve bitleri değiştir
        flat_data = data.flatten()
        for i in range(data_len):
            # Mevcut piksel değerinin son bitini temizle ve mesajın bitini koy
            # Örnek: 1101101[0] | [1] -> 11011011
            flat_data[i] = (flat_data[i] & 254) | int(binary_message[i])
            
        # Değiştirilmiş veriyi tekrar resim formatına sok
        reshaped_data = flat_data.reshape(data.shape)
        stego_img = Image.fromarray(reshaped_data.astype('uint8'), "RGB")
        
        output = io.BytesIO()
        stego_img.save(output, format="PNG")
        return output.getvalue()

    def extract_data(self, image_bytes):
        """
        Görüntüden gizli mesajı geri okur.
        """
        img = Image.open(io.BytesIO(image_bytes))
        img = img.convert("RGB")
        data = np.array(img)
        
        flat_data = data.flatten()
        binary_data = ""
        
        # Her pikselin son bitini oku
        for i in range(len(flat_data)):
            binary_data += str(flat_data[i] & 1)
            
            # Her 8 bitte bir (1 karakter) kontrol et, bitiş işareti var mı?
            if len(binary_data) % 8 == 0:
                # Performans için: Her karakterde kontrol etmek yerine belli aralıklarla bakılabilir
                # Ama burada basitlik için sona kadar gidiyoruz veya decoded string içinde kontrol edeceğiz.
                pass
                
        # Binary'yi stringe çevir (içinde ##### arar ve durur)
        return self.__bin_to_str(binary_data)