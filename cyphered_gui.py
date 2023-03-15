from basic_gui import BasicGUI
import logging
import dearpygui.dearpygui as dpg

# Création de la classe CypheredGUI depuis l'héritage de BasicGUI
class CypheredGUI(BasicGUI):
     def __init__(self)->None:
        # constructor
        self._client = None
        self._callback = None
        self._log = logging.getLogger(self.__class__.__name__)