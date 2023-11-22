import socket
import sys
import aux_functions

# se crea el socket
test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i in range(0,10):

    # el mensaje a enviar
    mssg = "{}.este es un mensaje más bien corto".format(i)
    # estructura
    struct = ["127.0.0.1", 8883, 10, i, 0, len(mssg.encode()), 0, mssg]
    # se pasa a mensaje
    full_mssg = aux_functions.create_packet(struct)
    # se pasa a bytes
    full_mssg = full_mssg.encode()

    print("TAMAÑO TOTAL EN BYTES DEL MENSAJE", len(full_mssg))

    # se envía el mensaje al socket en el puerto 8001
    test_socket.sendto(full_mssg, ("127.0.0.1", 8881))
