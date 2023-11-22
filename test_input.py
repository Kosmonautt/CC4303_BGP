import socket
import sys
import aux_functions

# el port del que va 
port_i = int(sys.argv[1])
# el port al que va
port_d = int(sys.argv[2])

# el mensaje a enviar
mssg = "hola!"
# estructura
struct = ["127.0.0.1", port_d, 10, 50, 0, len(mssg.encode()), 0, mssg]
# se pasa a mensaje
full_mssg = aux_functions.create_packet(struct)
# se pasa a bytes
full_mssg = full_mssg.encode()

print("TAMAÑO TOTAL EN BYTES DEL MENSAJE", len(full_mssg))

print("full_mssg", full_mssg)

# se crea el socket
test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# se envía el mensaje al socket en el puerto 8001
test_socket.sendto(full_mssg, ("127.0.0.1", port_i))