from basic_gui import *
import logging
import dearpygui.dearpygui as dpg
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import os

# Création de la classe CypheredGUI depuis l'héritage de BasicGUI
class CypheredGUI(BasicGUI):
     
     # Constructeur de la classe
     def __init__(self) -> None:
        super().__init__() # surcharge du constructeur
        self._key = None # clé de chiffrement
    
    
    # Fonction pour ajouter un champ "password" dans la fenêtre de connexion
     def _create_connection_window(self)->None:
        # On reprend la méthode de la classe parente
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")
            
            # Ajout d'un champ "password" pour la clé de chiffrement
            dpg.add_text('password :')
            dpg.add_input_text(password=True, tag="connection_password")
            
            dpg.add_button(label="Connect", callback=self.run_chat)


        def run_chat(self, sender, data) -> None :
            super().run_chat() # surcharge de la classe run_chat
            password = dpg.get_value("connection_password") # récupération du password
            
            # Génération de la clé de chiffrement
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=16, # 16 bytes = 128 bits
                salt=b'je veux reussir mon semestre', 
                iterations=100000, # nombre d'itérations pour la génération de la clé
                backend=default_backend()
            )
            self._key = kdf.derive(password.encode()) # dérivation de la clé avec le password

    
        # Fonction de chiffrement
        def encrypt(self, message) -> None :
            iv = os.urandom(16) # génération d'un vecteur d'initialisation aléatoire
            cipher = Cipher(
                algorithms.AES(self._key), 
                modes.CBC(iv), 
                backend=default_backend()
                
                )
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(bytes(message,"utf8")) + padder.finalize()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return encrypted, iv
            
        
        # Fonction de déchiffrement
        def decrypt(self, message, iv) -> None :
            cipher = Cipher(
                algorithms.AES(self._key), 
                modes.CBC(iv), 
                backend=default_backend()
                )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(message) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            unpadded_data = unpadder.update(decrypted) + unpadder.finalize()
            return unpadded_data.str(message,"utf8")
        
        # Fonction pour envoyer un message
        def send(self, text) -> None :
            super().send() # surcharge de la classe send()
            encrypted, iv = self.encrypt(text) # on chiffre le message
            self._socket.sendall(encrypted) # on envoie le message chiffré
            self._socket.sendall(iv) # on envoie le vecteur d'initialisation

    
        # Fonction pour recevoir un message
        def recv(self) -> None :
            super().recv()
            encrypted = self._socket.recv(1024) # on reçoit le message chiffré
            iv = self._socket.recv(1024) # on reçoit le vecteur d'initialisation
            decrypted = self.decrypt(encrypted, iv) # on déchiffre le message
            return decrypted # on retourne le message déchiffré
        
        



        
            

            

        
            




if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = CypheredGUI()
    client.create()
    client.loop()