from basic_gui import *
import logging
import dearpygui.dearpygui as dpg
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import os

# Création de la classe CipheredGUI depuis l'héritage de BasicGUI
class CipheredGUI(BasicGUI):
     
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

    #Surcharge de la fonction run_chat pour ajouter la génération de la clé de chiffrement
     def run_chat(self, sender, app_data) -> None :
        # On reprend la méthode de la classe parente
        host = dpg.get_value("connection_host") # récupération de l'adresse
        port = int(dpg.get_value("connection_port")) # récupération du port
        name = dpg.get_value("connection_name") # récupération du nom
        self._log.info(f"Connecting {name}@{host}:{port}") # affichage dans la console
        self._callback = GenericCallback() # création d'un callback
        self._client = ChatClient(host, port) # création d'un client
        self._client.start(self._callback) # démarrage du client
        self._client.register(name) # enregistrement du nom
        password = dpg.get_value("connection_password") # récupération du password
        
        # Génération de la clé de chiffrement
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16, # 16 bytes = 128 bits
            salt=b'je veux reussir mon semestre', 
            iterations=100000, # nombre d'itérations pour la génération de la clé
            backend=default_backend())
        self._key = kdf.derive(bytes(password, "utf8")) # dérivation de la clé avec le password
        self._log.info(f"Clé {self._key}") # affichage de la clé dans la console
        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")


    
    # Fonction de chiffrement
     def encrypt(self, message) -> None :
        iv = os.urandom(16) # génération d'un vecteur d'initialisation aléatoire
        # Création du chiffreur
        cipher = Cipher(
            algorithms.AES(self._key), 
            modes.CBC(iv), 
            backend=default_backend()
            )
        # Chiffrement du message
        self._log.info("Message", message)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(bytes(message,"utf8")) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        self._log.info("Message chiffré", encrypted)
        return iv, encrypted    # on retourne le vecteur d'initialisation et le message chiffré
            
        
    # Fonction de déchiffrement
     def decrypt(self, message, iv) -> None :
        cipher = Cipher(
            algorithms.AES(self._key), 
            modes.CBC(iv), 
            backend=default_backend()
            )
        # Déchiffrement du message
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(message) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted) + unpadder.finalize()
        return unpadded_data.str(message,"utf8")
        
    # Fonction pour envoyer un message
     def send(self, text) -> None :
        message = self.encrypt(text) # on chiffre le message
        self._client.send_message(message) # on envoie le message chiffré
        
         
    # Fonction pour recevoir un message
  
        
     
        



        
            

            

        
            




if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = CipheredGUI()
    client.create()
    client.loop()