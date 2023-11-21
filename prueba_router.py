import sys
import socket
import aux_functions

# tamaño del buffer
buff_size = 48

# headers
headers = sys.argv[1]
# ip del router inicial
ip_i = sys.argv[2]
# puerto del router inicial
port_i = int(sys.argv[3])

# se crea un socketUDP
sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# se le hace bind a una dirección no ocupada por los demás routers
sender_socket.bind(("127.0.0.1", 7001))

# variable que almacenará las lineas de los mensajes
m_lines = None

# se abre el archivo con las líneas a enviar
with open("prueba_router_mssg.txt") as f:
    # se leen todas las líneas y se guardan en una lista
    m_lines = f.readlines()

# se dividen los headers para obtener todas la componentes
headers = headers.split(",")
# se consiguen las componentes del mensaje
ip_mmsg = headers[0]
port_msgg = int(headers[1])
ttl = int(headers[2])

# para cada línea
for m_line in m_lines:
    # se crea el mensaje a enviar
    mssg = (aux_functions.create_packet([ip_mmsg,port_msgg,ttl, m_line])).encode()
    # se envía el mensaje al router inicial
    sender_socket.sendto(mssg, (ip_i, port_i))
