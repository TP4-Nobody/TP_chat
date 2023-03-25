from basic_gui import *
import logging
import dearpygui.dearpygui as dpg
from chat_client import ChatClient
from generic_callback import GenericCallback
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Création de la classe CipheredGUI depuis l'héritage de BasicGUI
class CipheredGUI(BasicGUI):
     
     # Constructeur de la classe
     def __init__(self) -> None:
        super().__init__() # surcharge du constructeur
        self._key = None # clé de chiffrement
    
    
    # Fonction pour ajouter un champ "password" dans la fenêtre de connexion
     def _create_connection_window(self) -> None:
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
        b_password = bytes(password, "utf8") #Passage du password en bytes
        self._key = kdf.derive(b_password) # dérivation de la clé avec le password
        self._log.info(f"Clé {self._key}") # affichage de la clé dans la console
        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    
    # Fonction de chiffrement
     def encrypt(self, message):
        iv = os.urandom(16) # génération d'un vecteur d'initialisation aléatoire
        # Création du chiffreur
        cipher = Cipher(
            algorithms.AES(self._key), 
            modes.CTR(iv), 
            backend=default_backend()
            )
        # Chiffrement du message
        self._log.info(f"Message {message}")
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder() # ajout de padding pour avoir la bonne taille de bloc
        b_message = bytes(message,"utf8") # passage du message en bytes
        padded_data = padder.update(b_message) + padder.finalize() 
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        self._log.info(f"Message chiffré {encrypted}")
        return iv, encrypted    # on retourne le vecteur d'initialisation et le message chiffré
            
        
    # Fonction de déchiffrement
     def decrypt(self, message):
        print(message)
        iv = base64.b64decode(message[0]['data']) # on récupère l'iv de la base64
        message = base64.b64decode(message[1]['data']) # on récupère le message de la base64
        cipher = Cipher(
            algorithms.AES(self._key), 
            modes.CTR(iv), 
            backend=default_backend()
            )
        # Déchiffrement du message
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(message) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted) + unpadder.finalize()
        self._log.info(f"Message déchiffré {unpadded_data}")
        return unpadded_data.str(message,"utf8")
        

    # Fonction pour envoyer un message
     def send(self, text) -> None :
        self._log.info("DRAGON 2")
        message = self.encrypt(text) # on chiffre le message
        self._log.info("DRAGON 3")
        self._client.send_message(message) # on envoie le message chiffré
        self._log.info("DRAGON 4")
        
         
    # Fonction pour recevoir un message
     def recv(self) -> None:
         if self._callback is not None:
            for user, message in self._callback.get():
                self._log.info("DRAGON 5")
                message = self.decrypt(message) # on déchiffre le message
                self._log.info("DRAGON 6")
                self.update_text_screen(f"{user} : {str(message, 'utf8')}") # on affiche le message déchiffré
                self._log.info("DRAGON 7")
            self._callback.clear()

    
    #Surcharge de la loop 
     def loop(self):
        # main loop
        while dpg.is_dearpygui_running():
            self.recv()
            dpg.render_dearpygui_frame()

        dpg.destroy_context()
     
        



        
            

            

        
            




if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = CipheredGUI()
    client.create()
    client.loop()