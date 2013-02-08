MegaUp beta.0.1
===============

Utilidad de línea de comando para SUDIR ficheros a mega.co.nz

Instrucciones (MAC/LINUX):
--------------------------

Requisitos:

	Python 2.7 - http://www.python.org/getit/
    Librería PyCrypto    - https://github.com/dlitz/pycrypto
    Librería Python-Progressbar   - http://code.google.com/p/python-progressbar/

Instalación de librerías:

    1.  sudo pip install pycrypto
    2.  sudo pip install progressbar

 * Para instalar pip
 	sudo easy_install pip
    

Cómo funciona:

    python megaup.py fichero1 [fichero2 fichero3 fichero4 ... ficheroN]


Cómo configurar la cuenta de mega.co.nz
	
	1. Abrir el fichero << megaup.cfg >> con cualquier editor de textos
	2. Cambiar los valores actuales por vuestros datos
		email = escribeaqui@tuemail.com
		password = escribeaquitupassword

