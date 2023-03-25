from ciphered_gui import *
import logging
import dearpygui.dearpygui as dpg
from chat_client import ChatClient
from generic_callback import GenericCallback
import base64
import hashlib
from cryptography.fernet import Fernet

# Création de la classe FernetGUI depuis l'héritage de CipheredGUI
class FernetGUI(CipheredGUI):

    # Surcharge de la fonction run_chat
    def run_chat(self, sender, app_data) -> None :

        # On reprend la méthode de la classe parente
        host = dpg.get_value("connection_host") 
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name") 
        self._log.info(f"Connecting {name}@{host}:{port}")
        self._callback = GenericCallback() 
        self._client = ChatClient(host, port) 
        self._client.start(self._callback) 
        self._client.register(name) 
        password = dpg.get_value("connection_password")

        # Génération de la clé de chiffrement
        self._key = hashlib.sha256(password.encode()).digest() 
        self._log.info(f"Clé {self._key}") # affichage de la clé dans la console
        self._key = base64.b64encode(self._key) # encodage de la clé en base64
        self._log.info(f"Clé encodée {self._key}") # affichage de la clé encodée dans la console

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")


    # Surcharge de la fonction encrypt
    def encrypt(self, message) -> bytes:
        crypted_key = Fernet(self._key) # On chiffre la clef avec Fernet
        b_message = bytes(message, 'utf-8') # On encode le message en bytes
        msg = crypted_key.encrypt(b_message) # On chiffre le message
        self._log.info(f"Message chiffré : {msg}") # On affiche le message chiffré dans la console
        return msg # On retourne le message chiffré
    

    # Surcharge de la fonction decrypt
    def decrypt(self, message) -> str :
        message = base64.b64decode(message['data']) # On décode le message en base64
        decrypted_key = Fernet(self._key) # On déchiffre le message avec Fernet
        decrypted_message = decrypted_key.decrypt(message).decode('utf8') # On déchiffre le message
        self._log.info(f"Message déchiffré : {decrypted_message}") # On affiche le message déchiffré dans la console
        return decrypted_message # On retourne le message déchiffré
    

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = FernetGUI()
    client.create()
    client.loop()