from fernet_gui import *
import logging
import base64
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import time

TTL = 30

# Création de la classe FernetGUI depuis l'héritage de CipheredGUI
class TimeFernetGUI(FernetGUI):

    def encrypt(self, message) -> bytes:
        crypted= Fernet(self._key) 
        Time = time.time() # On récupère le temps
        Time = int (Time) # On le convertit en int
        #Time = Time -45
        b_message = bytes(message, 'utf-8') 
        crypted_message = crypted.encrypt_at_time(b_message, Time) # On chiffre le message
        return crypted_message # On retourne le message chiffré
    

    def decrypt(self, message) -> str :
        msg = base64.b64decode(message['data']) 
        decrypted= Fernet(self._key) 
        Time = time.time() 
        Time = int (Time)
        try:
            decrypted_message = decrypted.decrypt_at_time(msg, TTL, Time).decode('utf8') # On déchiffre le message
            return decrypted_message # On retourne le message déchiffré
        except InvalidToken:
            self._log.info("Le message a expiré")
            return "Le message a expiré"
    

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = TimeFernetGUI()
    client.create()
    client.loop()
