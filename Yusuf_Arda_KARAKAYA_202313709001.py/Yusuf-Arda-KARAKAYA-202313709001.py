import sys
import sqlite3
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
    QMessageBox, QListWidget
)

def veritabani_baglantisi():
    return sqlite3.connect("bilgiler.db")

def tablo_olustur():
    con = veritabani_baglantisi()
    cursor = con.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS kitaplar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kitap_adi TEXT NOT NULL,
            yazar TEXT NOT NULL,
            yil TEXT,
            ekleyen TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    con.commit()
    con.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class GirisFormu(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Giriş Ekranı")
        self.setGeometry(100, 100, 300, 250)
        self.current_user = None  # Giriş yapan kullanıcının bilgilerini saklamak için

        self.etiket_kullanici = QLabel("Kullanıcı Adı:", self)
        self.etiket_kullanici.move(20, 30)
        self.girdi_kullanici = QLineEdit(self)
        self.girdi_kullanici.move(120, 30)

        self.etiket_sifre = QLabel("Şifre:", self)
        self.etiket_sifre.move(20, 70)
        self.girdi_sifre = QLineEdit(self)
        self.girdi_sifre.setEchoMode(QLineEdit.Password)
        self.girdi_sifre.move(120, 70)

        self.buton_gorevli = QPushButton("Görevli Girişi", self)
        self.buton_gorevli.move(50, 120)
        self.buton_gorevli.clicked.connect(self.gorevli_giris)

        self.buton_ogrenci = QPushButton("Öğrenci Girişi", self)
        self.buton_ogrenci.move(150, 120)
        self.buton_ogrenci.clicked.connect(self.ogrenci_giris)

        self.buton_yonetici_kayit = QPushButton("Yönetici Kayıt", self)
        self.buton_yonetici_kayit.move(50, 160)
        self.buton_yonetici_kayit.clicked.connect(self.ac_yonetici_kayit)

        self.buton_ogrenci_kayit = QPushButton("Öğrenci Kayıt", self)
        self.buton_ogrenci_kayit.move(150, 160)
        self.buton_ogrenci_kayit.clicked.connect(self.ac_ogrenci_kayit)

    def gorevli_giris(self):
        username = self.girdi_kullanici.text().strip()
        password = hash_password(self.girdi_sifre.text().strip())
        con = veritabani_baglantisi()
        cursor = con.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = ? AND password = ?", (username, password))
        result = cursor.fetchone()
        con.close()
        if result:
            self.current_user = {"username": username, "type": "gorevli"}
            self.gorevli_formu = GorevliFormu(self.current_user)
            self.gorevli_formu.show()
            self.hide()
        else:
            QMessageBox.warning(self, "Hata", "Geçersiz kullanıcı adı veya şifre!")

    def ogrenci_giris(self):
        username = self.girdi_kullanici.text().strip()
        password = hash_password(self.girdi_sifre.text().strip())
        con = veritabani_baglantisi()
        cursor = con.cursor()
        cursor.execute("SELECT * FROM students WHERE username = ? AND password = ?", (username, password))
        result = cursor.fetchone()
        con.close()
        if result:
            self.current_user = {"username": username, "type": "ogrenci"}
            self.ogrenci_formu = OgrenciFormu(self.current_user)
            self.ogrenci_formu.show()
            self.hide()
        else:
            QMessageBox.warning(self, "Hata", "Geçersiz kullanıcı adı veya şifre!")

    def ac_yonetici_kayit(self):
        self.yonetici_kayit_formu = YoneticiKayitFormu()
        self.yonetici_kayit_formu.show()
        self.hide()

    def ac_ogrenci_kayit(self):
        self.ogrenci_kayit_formu = OgrenciKayitFormu()
        self.ogrenci_kayit_formu.show()
        self.hide()

class YoneticiKayitFormu(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Yönetici Kayıt")
        self.setGeometry(100, 100, 300, 200)

        self.etiket_kullanici = QLabel("Kullanıcı Adı:", self)
        self.etiket_kullanici.move(20, 30)
        self.girdi_kullanici = QLineEdit(self)
        self.girdi_kullanici.move(120, 30)

        self.etiket_sifre = QLabel("Şifre:", self)
        self.etiket_sifre.move(20, 70)
        self.girdi_sifre = QLineEdit(self)
        self.girdi_sifre.setEchoMode(QLineEdit.Password)
        self.girdi_sifre.move(120, 70)

        self.buton_kaydet = QPushButton("Kayıt Ol", self)
        self.buton_kaydet.move(50, 120)
        self.buton_kaydet.clicked.connect(self.kaydet)

        self.buton_geri = QPushButton("Geri", self)
        self.buton_geri.move(150, 120)
        self.buton_geri.clicked.connect(self.ac_giris_formu)

    def kaydet(self):
        username = self.girdi_kullanici.text().strip()
        password = self.girdi_sifre.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Hata", "Tüm alanlar doldurulmalıdır!")
            return

        con = veritabani_baglantisi()
        cursor = con.cursor()
        try:
            cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, hash_password(password)))
            con.commit()
            QMessageBox.information(self, "Başarılı", "Yönetici kaydedildi!")
            self.ac_giris_formu()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Hata", "Bu kullanıcı adı zaten alınmış!")
        finally:
            con.close()

    def ac_giris_formu(self):
        self.giris_formu = GirisFormu()
        self.giris_formu.show()
        self.hide()

class OgrenciKayitFormu(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Öğrenci Kayıt")
        self.setGeometry(100, 100, 300, 200)

        self.etiket_kullanici = QLabel("Kullanıcı Adı:", self)
        self.etiket_kullanici.move(20, 30)
        self.girdi_kullanici = QLineEdit(self)
        self.girdi_kullanici.move(120, 30)

        self.etiket_sifre = QLabel("Şifre:", self)
        self.etiket_sifre.move(20, 70)
        self.girdi_sifre = QLineEdit(self)
        self.girdi_sifre.setEchoMode(QLineEdit.Password)
        self.girdi_sifre.move(120, 70)

        self.buton_kaydet = QPushButton("Kayıt Ol", self)
        self.buton_kaydet.move(50, 120)
        self.buton_kaydet.clicked.connect(self.kaydet)

        self.buton_geri = QPushButton("Geri", self)
        self.buton_geri.move(150, 120)
        self.buton_geri.clicked.connect(self.ac_giris_formu)

    def kaydet(self):
        username = self.girdi_kullanici.text().strip()
        password = self.girdi_sifre.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Hata", "Tüm alanlar doldurulmalıdır!")
            return

        con = veritabani_baglantisi()
        cursor = con.cursor()
        try:
            cursor.execute("INSERT INTO students (username, password) VALUES (?, ?)", (username, hash_password(password)))
            con.commit()
            QMessageBox.information(self, "Başarılı", "Öğrenci kaydedildi!")
            self.ac_giris_formu()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Hata", "Bu kullanıcı adı zaten alınmış!")
        finally:
            con.close()

    def ac_giris_formu(self):
        self.giris_formu = GirisFormu()
        self.giris_formu.show()
        self.hide()

class GorevliFormu(QMainWindow):
    def __init__(self, current_user):
        super().__init__()
        self.setWindowTitle("Görevli Paneli")
        self.setGeometry(100, 100, 300, 400)
        self.current_user = current_user

        self.etiket = QLabel("Görevli Paneli", self)
        self.etiket.move(100, 20)

        self.buton_kitap_ekle = QPushButton("Kitap Ekle ve Sil", self)
        self.buton_kitap_ekle.resize(150, 40)
        self.buton_kitap_ekle.move(80, 60)
        self.buton_kitap_ekle.clicked.connect(self.ac_kitap_ekle)

        self.buton_kitap_listesi = QPushButton("Kitap Listesi", self)
        self.buton_kitap_listesi.resize(150, 40)
        self.buton_kitap_listesi.move(80, 110)
        self.buton_kitap_listesi.clicked.connect(self.ac_kitap_listesi)

        self.buton_kitap_ara = QPushButton("Kitap Ara", self)
        self.buton_kitap_ara.resize(150, 40)
        self.buton_kitap_ara.move(80, 160)
        self.buton_kitap_ara.clicked.connect(self.ac_kitap_ara)

        self.buton_cikis = QPushButton("Çıkış", self)
        self.buton_cikis.resize(150, 40)
        self.buton_cikis.move(80, 210)
        self.buton_cikis.clicked.connect(self.ac_giris_formu)

        self.kitap_listesi = QListWidget(self)
        self.kitap_listesi.setGeometry(20, 260, 260, 100)
        self.kitaplari_yukle()

    def kitaplari_yukle(self):
        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("SELECT kitap_adi, yazar FROM kitaplar")
            kitaplar = cursor.fetchall()
            con.close()

            self.kitap_listesi.clear()
            for kitap in kitaplar:
                self.kitap_listesi.addItem(f"{kitap[0]} - {kitap[1]}")
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Veritabanı hatası: {str(e)}")

    def ac_kitap_ekle(self):
        self.kitap_ekle_formu = KitapEkleFormu(self.current_user)
        self.kitap_ekle_formu.show()
        self.hide()

    def ac_kitap_listesi(self):
        self.kitap_listesi_formu = KitapListesiFormu(self.current_user)
        self.kitap_listesi_formu.show()
        self.hide()

    def ac_kitap_ara(self):
        self.ara_formu = KitapAraFormu(self.current_user, panel_turu="gorevli")
        self.ara_formu.show()
        self.hide()

    def ac_giris_formu(self):
        self.giris_formu = GirisFormu()
        self.giris_formu.show()
        self.hide()

class KitapEkleFormu(QMainWindow):
    def __init__(self, current_user):
        super().__init__()
        self.setWindowTitle("Kitap Ekle ve Sil")
        self.setGeometry(100, 100, 300, 350)
        self.current_user = current_user

        self.etiket_baslik = QLabel("Kitap Adı:", self)
        self.etiket_baslik.move(20, 30)
        self.girdi_baslik = QLineEdit(self)
        self.girdi_baslik.move(120, 30)

        self.etiket_yazar = QLabel("Yazar Adı:", self)
        self.etiket_yazar.move(20, 70)
        self.girdi_yazar = QLineEdit(self)
        self.girdi_yazar.move(120, 70)

        self.buton_kaydet = QPushButton("Ekle", self)
        self.buton_kaydet.move(20, 180)
        self.buton_kaydet.clicked.connect(self.kitap_ekle)

        self.buton_sil = QPushButton("Sil", self)
        self.buton_sil.move(90, 180)
        self.buton_sil.clicked.connect(self.kitap_sil)

        self.buton_menu = QPushButton("Ana Menü", self)
        self.buton_menu.move(160, 180)
        self.buton_menu.clicked.connect(self.ac_gorevli_formu)

        self.kitap_listesi = QListWidget(self)
        self.kitap_listesi.setGeometry(20, 220, 260, 100)
        self.kitaplari_yukle()

    def kitaplari_yukle(self):
        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("SELECT kitap_adi, yazar FROM kitaplar")
            kitaplar = cursor.fetchall()
            con.close()

            self.kitap_listesi.clear()
            for kitap in kitaplar:
                self.kitap_listesi.addItem(f"{kitap[0]} - {kitap[1]}")
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Veritabanı hatası: {str(e)}")

    def kitap_ekle(self):
        kitap = self.girdi_baslik.text().strip()
        yazar = self.girdi_yazar.text().strip()

        if not kitap or not yazar:
            QMessageBox.warning(self, "Hata", "Kitap adı ve yazar adı boş olamaz.")
            return

        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("INSERT INTO kitaplar (kitap_adi, yazar, ekleyen) VALUES (?, ?, ?)",
                           (kitap, yazar, "gorevli"))
            con.commit()
            con.close()
            QMessageBox.information(self, "Başarılı", "Kitap eklendi.")
            self.girdi_baslik.clear()
            self.girdi_yazar.clear()
            self.kitaplari_yukle()
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Kitap eklenirken hata: {str(e)}")

    def kitap_sil(self):
        kitap = self.girdi_baslik.text().strip()
        yazar = self.girdi_yazar.text().strip()

        if not kitap or not yazar:
            QMessageBox.warning(self, "Hata", "Silmek için kitap adı ve yazar adı giriniz.")
            return

        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("SELECT id FROM kitaplar WHERE kitap_adi = ? AND yazar = ?",
                           (kitap, yazar))
            sonuc = cursor.fetchone()

            if not sonuc:
                QMessageBox.warning(self, "Hata", "Bu kitap bulunamadı.")
                con.close()
                return

            cursor.execute("DELETE FROM kitaplar WHERE id = ?", (sonuc[0],))
            con.commit()
            con.close()
            QMessageBox.information(self, "Başarılı", "Kitap silindi.")
            self.girdi_baslik.clear()
            self.girdi_yazar.clear()
            self.kitaplari_yukle()
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Kitap silinirken hata: {str(e)}")

    def ac_gorevli_formu(self):
        self.gorevli_formu = GorevliFormu(self.current_user)
        self.gorevli_formu.show()
        self.hide()

class KitapListesiFormu(QMainWindow):
    def __init__(self, current_user):
        super().__init__()
        self.setWindowTitle("Kitap Listesi")
        self.setGeometry(100, 100, 300, 400)
        self.current_user = current_user

        self.etiket = QLabel("Kitap Listesi", self)
        self.etiket.move(100, 20)

        self.kitap_listesi = QListWidget(self)
        self.kitap_listesi.setGeometry(20, 50, 260, 300)

        self.buton_menu = QPushButton("Ana Menü", self)
        self.buton_menu.resize(200, 30)
        self.buton_menu.move(50, 360)
        self.buton_menu.clicked.connect(self.ac_gorevli_formu)

        self.kitaplari_yukle()

    def kitaplari_yukle(self):
        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("SELECT kitap_adi, yazar FROM kitaplar")
            kitaplar = cursor.fetchall()
            con.close()

            self.kitap_listesi.clear()
            for kitap in kitaplar:
                self.kitap_listesi.addItem(f"{kitap[0]} - {kitap[1]}")
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Veritabanı hatası: {str(e)}")

    def ac_gorevli_formu(self):
        self.gorevli_formu = GorevliFormu(self.current_user)
        self.gorevli_formu.show()
        self.hide()

class KitapAraFormu(QMainWindow):
    def __init__(self, current_user, panel_turu="gorevli"):
        super().__init__()
        self.setWindowTitle("Kitap Ara")
        self.setGeometry(100, 100, 300, 350)
        self.current_user = current_user
        self.panel_turu = panel_turu

        self.etiket = QLabel("Kitap Adı veya Yazar Adı:", self)
        self.etiket.move(20, 30)
        self.girdi_ara = QLineEdit(self)
        self.girdi_ara.move(150, 30)

        self.buton_ara = QPushButton("Ara", self)
        self.buton_ara.move(50, 70)
        self.buton_ara.clicked.connect(self.kitap_ara)

        self.buton_menu = QPushButton("Ana Menü", self)
        self.buton_menu.move(150, 70)
        self.buton_menu.clicked.connect(self.ac_ana_menu)

        self.kitap_listesi = QListWidget(self)
        self.kitap_listesi.setGeometry(20, 110, 260, 200)
        self.kitaplari_yukle()

    def kitaplari_yukle(self):
        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("SELECT kitap_adi, yazar FROM kitaplar")
            kitaplar = cursor.fetchall()
            con.close()

            self.kitap_listesi.clear()
            for kitap in kitaplar:
                self.kitap_listesi.addItem(f"{kitap[0]} - {kitap[1]}")
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Veritabanı hatası: {str(e)}")

    def kitap_ara(self):
        aranan = self.girdi_ara.text().strip()
        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("SELECT kitap_adi, yazar FROM kitaplar WHERE kitap_adi LIKE ? OR yazar LIKE ?",
                           (f'%{aranan}%', f'%{aranan}%'))
            kitaplar = cursor.fetchall()
            con.close()

            self.kitap_listesi.clear()
            if kitaplar:
                for kitap in kitaplar:
                    self.kitap_listesi.addItem(f"{kitap[0]} - {kitap[1]}")
            else:
                self.kitap_listesi.addItem("Sonuç bulunamadı.")
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Arama sırasında hata: {str(e)}")

    def ac_ana_menu(self):
        try:
            if self.panel_turu == "gorevli":
                self.gorevli_formu = GorevliFormu(self.current_user)
                self.gorevli_formu.show()
            else:
                self.ogrenci_formu = OgrenciFormu(self.current_user)
                self.ogrenci_formu.show()
            self.hide()
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Menüye dönerken hata: {str(e)}")

class OgrenciFormu(QMainWindow):
    def __init__(self, current_user):
        super().__init__()
        self.setWindowTitle("Öğrenci Paneli")
        self.setGeometry(100, 100, 300, 250)
        self.current_user = current_user

        self.etiket = QLabel("Öğrenci Paneli", self)
        self.etiket.move(100, 20)

        self.buton_bagisla_kitap = QPushButton("Kitap Bağışla", self)
        self.buton_bagisla_kitap.resize(150, 40)
        self.buton_bagisla_kitap.move(80, 60)
        self.buton_bagisla_kitap.clicked.connect(self.bagisla_kitap)

        self.buton_ara_kitap = QPushButton("Kitap Ara", self)
        self.buton_ara_kitap.resize(150, 40)
        self.buton_ara_kitap.move(80, 110)
        self.buton_ara_kitap.clicked.connect(self.ara_kitap)

        self.buton_cikis = QPushButton("Çıkış", self)
        self.buton_cikis.resize(150, 40)
        self.buton_cikis.move(80, 160)
        self.buton_cikis.clicked.connect(self.ac_giris_formu)

    def bagisla_kitap(self):
        self.bagisla_formu = KitapBagislaFormu(self.current_user)
        self.bagisla_formu.show()
        self.hide()

    def ara_kitap(self):
        self.ara_formu = KitapAraFormu(panel_turu="ogrenci")
        self.ara_formu.show()
        self.hide()

    def ac_giris_formu(self):
        self.giris_formu = GirisFormu()
        self.giris_formu.show()
        self.hide()

class KitapBagislaFormu(QMainWindow):
    def __init__(self, current_user):
        super().__init__()
        self.setWindowTitle("Kitap Bağışla")
        self.setGeometry(100, 100, 300, 250)
        self.current_user = current_user

        self.etiket_baslik = QLabel("Kitap Adı:", self)
        self.etiket_baslik.move(20, 30)
        self.girdi_baslik = QLineEdit(self)
        self.girdi_baslik.move(120, 30)

        self.etiket_yazar = QLabel("Yazar Adı:", self)
        self.etiket_yazar.move(20, 70)
        self.girdi_yazar = QLineEdit(self)
        self.girdi_yazar.move(120, 70)

        self.buton_bagisla = QPushButton("Bağışla", self)
        self.buton_bagisla.move(50, 120)
        self.buton_bagisla.clicked.connect(self.kitap_bagisla)

        self.buton_menu = QPushButton("Ana Menü", self)
        self.buton_menu.move(150, 120)
        self.buton_menu.clicked.connect(self.ac_ogrenci_formu)

    def kitap_bagisla(self):
        kitap = self.girdi_baslik.text().strip()
        yazar = self.girdi_yazar.text().strip()

        if not kitap or not yazar:
            QMessageBox.warning(self, "Hata", "Kitap adı ve yazar adı boş olamaz.")
            return

        try:
            con = veritabani_baglantisi()
            cursor = con.cursor()
            cursor.execute("INSERT INTO kitaplar (kitap_adi, yazar, ekleyen) VALUES (?, ?, ?)",
                           (kitap, yazar, "ogrenci"))
            con.commit()
            con.close()
            QMessageBox.information(self, "Başarılı", "Kitap bağışı yapıldı.")
            self.girdi_baslik.clear()
            self.girdi_yazar.clear()
            self.ac_ogrenci_formu()
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Hata", f"Kitap bağışlanırken hata: {str(e)}")

    def ac_ogrenci_formu(self):
        self.ogrenci_formu = OgrenciFormu(self.current_user)
        self.ogrenci_formu.show()
        self.hide()

if __name__ == "__main__":
    tablo_olustur()
    app = QApplication(sys.argv)
    giris_formu = GirisFormu()
    giris_formu.show()
    sys.exit(app.exec_())