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

LENGTH_BYTES = 16 # Longueur d'octet
NB_ITERATIONS = 100000 # Nombre d'itérations
LENGTH_BLOCK = 128 # Longueur d'un bloc
SALT = b'je veux reussir mon semestre'

# Création de la classe CipheredGUI depuis l'héritage de BasicGUI
class CipheredGUI(BasicGUI):
     
     # Constructeur de la classe
     def __init__(self) -> None:
        super().__init__() # surcharge du constructeur
        self._key = None 
    
    
    # Fonction pour ajouter un champ "password" dans la fenêtre de connexion
     def _create_connection_window(self) -> None:

        # On reprend la méthode de la classe parente
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(default_value = DEFAULT_VALUES[field], tag = f"connection_{field}")

            # Ajout d'un champ "password" pour la clé de chiffrement
            dpg.add_text('password :')
            dpg.add_input_text(password = True, tag = "connection_password")
            
            dpg.add_button(label="Connect", callback=self.run_chat)


    #Surcharge de la fonction run_chat pour ajouter la génération de la clé de chiffrement
     def run_chat(self, sender, app_data) -> None :

        # On reprend la méthode de la classe parente
        host = dpg.get_value("connection_host") # récupération de l'adresse
        port = int(dpg.get_value("connection_port")) # récupération du port
        name = dpg.get_value("connection_name") # récupération du nom
        self._log.info(f"Connecting {name}@{host}:{port}") 
        self._callback = GenericCallback() 
        self._client = ChatClient(host, port) # création du client
        self._client.start(self._callback) # démarrage du client
        self._client.register(name) # enregistrement du nom
        password = dpg.get_value("connection_password") # récupération du password

        # Génération de la clé de chiffrement
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=LENGTH_BYTES, # longueur de la clé
            salt=SALT, 
            iterations=NB_ITERATIONS, 
            backend=default_backend()) 
        b_password = bytes(password, "utf8") #Passage du password en bytes
        self._key = kdf.derive(b_password) # dérivation de la clé avec le password
        self._log.info(f"Clé {self._key}") 
        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    
    # Fonction de chiffrement
     def encrypt(self, message):

        iv = os.urandom(LENGTH_BYTES) # génération d'un vecteur d'initialisation aléatoire

        # Création du chiffreur
        cipher = Cipher(
            algorithms.AES(self._key), 
            modes.CTR(iv), 
            backend=default_backend()
            )
        
        # Chiffrement du message
        self._log.info(f"Message {message}")
        encryptor = cipher.encryptor() # on crée le chiffreur
        padder = padding.PKCS7(LENGTH_BLOCK).padder() # ajout de padding pour avoir la bonne taille de bloc
        b_message = bytes(message,"utf8") # passage du message en bytes
        padded_data = padder.update(b_message) + padder.finalize() 
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        self._log.info(f"Message chiffré {encrypted}") 
        return iv, encrypted  # on retourne le vecteur d'initialisation et le message chiffré
            
        
    # Fonction de déchiffrement
     def decrypt(self, message):
        
        iv = base64.b64decode(message[0]['data'])
        msg = base64.b64decode(message[1]['data']) 
        cipher = Cipher(
            algorithms.AES(self._key), 
            modes.CTR(iv), 
            backend=default_backend()
            )
        
        # Déchiffrement du message
        decryptor = cipher.decryptor() # on crée le déchiffreur
        decrypted = decryptor.update(msg) + decryptor.finalize() # on déchiffre le message
        unpadder = padding.PKCS7(LENGTH_BLOCK).unpadder() # on retire le padding
        unpadded_data = unpadder.update(decrypted) + unpadder.finalize() 
        self._log.info(f"Message déchiffré {unpadded_data}")
        return unpadded_data.decode("utf8") # on retourne le message déchiffré en string
        

    # Fonction pour envoyer un message
     def send(self, text) -> None :
        message = self.encrypt(text) 
        self._client.send_message(message) 
        
         
    # Fonction pour recevoir un message
     def recv(self) -> None:
         if self._callback is not None:
            for user, message in self._callback.get(): # on récupère les messages
                message = self.decrypt(message) 
                self.update_text_screen(f"{user} : {message}") 
            self._callback.clear() # on vide la liste des messages


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = CipheredGUI()
    client.create()
    client.loop()
