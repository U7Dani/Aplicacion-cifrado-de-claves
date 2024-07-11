# Aplicacion-cifrado-de-claves
Guía de Uso de la Aplicación de Cifrado

Esta guía te ayudará a entender cómo usar la aplicación de cifrado para realizar operaciones de hash, HMAC, cifrado y descifrado utilizando varios algoritmos. La aplicación cuenta con una interfaz gráfica y permite generar claves y nonces, copiar resultados y restablecer los campos. También explicaremos qué es cada concepto clave utilizado en la aplicación.
Requisitos Previos
Antes de comenzar, asegúrate de tener instaladas las siguientes bibliotecas:
sh
Copiar código
pip install pycryptodome pyperclip 
Inicio de la Aplicación
Guarda el código proporcionado en un archivo, por ejemplo, crypto_app.py, y luego ejecuta el archivo:
sh
Copiar código
python crypto_app.py 
Interfaz de Usuario
1.	Message (Mensaje):
	Campo para introducir el mensaje sobre el cual deseas realizar operaciones criptográficas.
2.	Key (for HMAC/Encryption) (Clave para HMAC/Cifrado):
	Campo para introducir la clave que se usará en las operaciones de HMAC o cifrado.
	Clave (Key): Es un valor secreto utilizado en los algoritmos criptográficos para cifrar y descifrar datos. Debe ser protegida y conocida solo por las partes autorizadas.
3.	Nonce:
	Campo para introducir el nonce que se usará en ciertos algoritmos de cifrado (ChaCha20 y AES-GCM).
	Nonce: Es un valor único que se utiliza solo una vez en las operaciones criptográficas para garantizar que el mismo texto plano cifrado dos veces dará resultados diferentes. Ayuda a prevenir ataques de repetición.
4.	Hash Type (Tipo de Hash):
	Desplegable para seleccionar el tipo de algoritmo de hash. Las opciones son:
	sha256
	sha512
	sha3_256
	sha3_512
	Algoritmo de Hash: Un hash es una función que convierte una entrada (por ejemplo, un mensaje) en una cadena de texto de longitud fija, que actúa como un "huella digital" del mensaje. Es utilizado para verificar la integridad de los datos.
5.	Encryption Algorithm (Algoritmo de Cifrado):
	Desplegable para seleccionar el algoritmo de cifrado. Las opciones son:
	ChaCha20
	AES-CBC
	AES-GCM
	Algoritmo de Cifrado: Es un método utilizado para convertir datos legibles en un formato cifrado que solo puede ser leído por aquellos que tienen la clave adecuada. AES (Advanced Encryption Standard) y ChaCha20 son ejemplos de algoritmos de cifrado.
6.	Result (Resultado):
	Área de texto donde se muestran los resultados de las operaciones criptográficas.
Funcionalidades y Ejemplos de Uso
Generar Hash
1.	Introduce el mensaje en el campo "Message".
2.	Selecciona el tipo de hash en el desplegable "Hash Type".
3.	Haz clic en "Hash".
4.	El hash del mensaje se mostrará en el área de texto "Result".
Ejemplo:
·	Mensaje:Hola Mundo
·	Hash Type:sha256
·	Resultado:c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31e8c7c60
Generar HMAC
1.	Introduce el mensaje en el campo "Message".
2.	Introduce la clave en el campo "Key".
3.	Selecciona el tipo de hash en el desplegable "Hash Type".
4.	Haz clic en "HMAC".
5.	El HMAC del mensaje se mostrará en el área de texto "Result".
Ejemplo:
·	Mensaje:Hola Mundo
·	Key:5b06c165fc9a27675bc284dd42acc2bbca5aa461321dfde0
·	Hash Type:sha256
·	Resultado:9f3b3ab70a9f7da4c7d2fd7351a25cd0c44d6a0e56f4b5d6e8d9f93b8b732c43
HMAC (Código de Autenticación de Mensajes Basado en Hash): Es una técnica que utiliza una función hash junto con una clave secreta para proporcionar autenticación y verificación de integridad de los datos.
Cifrar un Mensaje
1.	Introduce el mensaje en el campo "Message".
2.	Introduce la clave en el campo "Key".
3.	Selecciona el algoritmo de cifrado en el desplegable "Encryption Algorithm".
4.	Si usas ChaCha20 o AES-GCM, genera un nonce haciendo clic en "Generate Nonce" y cópialo al campo "Nonce".
5.	Haz clic en "Encrypt".
6.	El mensaje cifrado se mostrará en el área de texto "Result".
Ejemplo con ChaCha20:
·	Mensaje:Estoy aprendiendo mucho con Felipe en la clase de Criptografía.
·	Key:5b06c165fc9a27675bc284dd42acc2bbca5aa461321dfde0
·	Encryption Algorithm:ChaCha20
·	Resultado:O1LzUJL3X6Yg=IvYsjX5Tz8RQF2Bfc8QR/EWmRF9t1lWTTLE2RnNEMOOp3uSObvxwQHrSwuhLO8sYswOGQrzEiOFAZ5duEDK=
Ejemplo con AES-CBC:
·	Mensaje:Estoy aprendiendo mucho con Felipe en la clase de Criptografía.
·	Key:5b06c165fc9a27675bc284dd42acc2bbca5aa461321dfde0
·	Encryption Algorithm:AES-CBC
·	Resultado:nonce+<ciphertext> (El nonce estará concatenado con el mensaje cifrado).
Descifrar un Mensaje
1.	Introduce el mensaje cifrado en el campo "Message".
2.	Introduce la clave en el campo "Key".
3.	Selecciona el algoritmo de cifrado en el desplegable "Encryption Algorithm".
4.	Introduce el nonce utilizado en el campo "Nonce".
5.	Haz clic en "Decrypt".
6.	El mensaje descifrado se mostrará en el área de texto "Result".
Ejemplo con ChaCha20:
·	Message:O1LzUJL3X6Yg=IvYsjX5Tz8RQF2Bfc8QR/EWmRF9t1lWTTLE2RnNEMOOp3uSObvxwQHrSwuhLO8sYswOGQrzEiOFAZ5duEDK=
·	Key:5b06c165fc9a27675bc284dd42acc2bbca5aa461321dfde0
·	Encryption Algorithm:ChaCha20
·	Resultado:Estoy aprendiendo mucho con Felipe en la clase de Criptografía.
Generar una Clave Aleatoria
1.	Haz clic en "Generate Key".
2.	La clave generada se mostrará en el campo "Key".
Clave (Key): Es un valor secreto utilizado en los algoritmos criptográficos para cifrar y descifrar datos. Debe ser protegida y conocida solo por las partes autorizadas.
Generar un Nonce Aleatorio
1.	Haz clic en "Generate Nonce".
2.	El nonce generado se mostrará en el campo "Nonce".
Nonce: Es un valor único que se utiliza solo una vez en las operaciones criptográficas para garantizar que el mismo texto plano cifrado dos veces dará resultados diferentes. Ayuda a prevenir ataques de repetición.
Guardar y Cargar una Clave
	Guardar una Clave:
1.	Introduce la clave en el campo "Key".
2.	Haz clic en "Save Key".
3.	Selecciona la ubicación y el nombre del archivo para guardar la clave.
	Cargar una Clave:
1.	Haz clic en "Load Key".
2.	Selecciona el archivo que contiene la clave.
3.	La clave cargada se mostrará en el campo "Key".
Copiar el Resultado
1.	Haz clic en "Copy Result".
2.	El contenido del área de texto "Result" se copiará al portapapeles.
Restablecer los Campos
1.	Haz clic en "Reset".
2.	Todos los campos de entrada y áreas de texto se restablecerán a sus valores predeterminados.
