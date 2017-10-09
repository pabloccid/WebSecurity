# WebSecurity
Web Application Security Analyzer
A partir de una URL ingresada, evalúa si contiene vulnerabilidades del tipo XSS y SQL Injection.
Aplica Multi Threading para analizar las URL que encuentre en la web ingresada.

# Instrucciones de Uso
Primero el programa muestra un formulario, donde se debe completar con la URL a analizar, la cantidad maxima de threads y, opcionalmente, las cookies que se van a incluir en los requests.
Luego del submit del formulario, el programa parsea la URL para obtener el dominio, carga la configuración de la base de datos del archivo config.xml e inserta un registro de análisis, obteniendo un id de ejecución. 
Se fija si en la ejecución actual ya se analizó la URL en cuestión.
Si no fue analizada, realiza un request a la URL, obteniendo la respuesta.
Si se obtuvo respuesta, inserta un registro de URL analizada.
Busca en la respuesta todos los valores de los atributos ID y name en la respuesta, para utilizarlos como posibles input de usuario.
Genera todas las combinaciones de caracteres de la “a” a la “z” (fuerza bruta), para probarlas como posibles input de usuario (en el código esta acotado hasta una longitud de 2 caracteres máximo, ya que si se ingresa un valor mayor el procesamiento se hace muy largo).
Entonces realiza un GET request por cada uno de estos posibles input, con cada uno de los scripts descriptos en un array. Cada uno de estos scripts esta asociado con un tag, que sera el utilizado para buscar la inyeccion exitosa en el codigo (ejemplo, para el script “<script>alert(‘XSS’)</script>” se asocia el tag “script”, para “<body onload=“<script>alert(‘XSS’)</script >”>” se buscará el tag “body”). 
La respuesta del request se analiza con la clase DomDocument, buscando el tag asociado al script que se esta probando. Si encuentra el script inyectado, construido correctamente, se determina el input como vulnerable y es agregado al registro de URL analizado, como input vulnerable. Esta clase no lo toma por valido si está dentro de otro elemento (no se ejecutaría, por ejemplo, como value de un input text, por mas que se encuentre el script sin caracteres escapados en la respuesta).
Si no es determinado como vulnerable, se prueba el mismo script e input, pero con un POST request, y se analiza la respuesta con el mismo procedimiento.
Finalmente, solo para la URL analizada inicialmente, se crea un pool de threads (limitado por la cantidad de threads máximos ingresados) y se buscan todas las URL del mismo dominio. Por cada una encontrada, se lanza un thread, que repite el procedimiento desde el paso 3, pero obviando el 11.
Se incluye archivo “payloads.txt” con posibles scripts a tratar de inyectar, que no están incluídos en el programa, pero bien podrían utilizarse. Utilizan diferentes técnicas para intentar evitar los filtros XSS.

# Instalación

# Pthreads 
(http://php.net/manual/es/book.pthreads.php)
El programa utiliza la API pthreads, que para poder ejecutar necesita que se habilite Zend Thread Safety.

# Config.xml
El programa requiere configurar los datos de acceso a la base de datos a utilizar (MySQL) en el archivo config.xml (host, user, password y db name).
Este archivo requiere ubicarse en el directorio base del servidor (esto se realizo de esta forma ya que los diferentes threads no comparten contexto, por lo que requieren una direccion absoluta para encontrar el config), es decir, el programa lo accede con "http://localhost/config.xml"
