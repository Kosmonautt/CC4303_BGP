import sys
import socket
import aux_functions

# tamaño del buffer
buff_size = 256

# ip del router
ip = sys.argv[1]
# puerto del router (simulando una IP)
port = int(sys.argv[2])
# nombre del archivo con la tabla de rutas
route_table = sys.argv[3]

# se crea un socketUDP
router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# se le hace bind a su dirección dada
router_socket.bind((ip, port))
# se crea el objeto para guardar las tablas de saltos
forwardList = aux_functions.ForwardList((ip, port))
# se crea un diccionario que gaurdará los fragmentos (en bytes) con el mismo id
frag_dicc = {}

# variable que almacenará las lineas de la tabla
r_lines = None

# se abre el archivo con la tabla de rutas
with open(route_table) as f:
    # se leen todas las líneas y se guardan en una lista
    r_lines = f.readlines()


# ciclo while donde se reciben mensajes
while True:
    # se espera a obtener un mensaje
    mssg, address = router_socket.recvfrom(buff_size)
    # se pasa a estrcutura
    struct_mssg = aux_functions.parse_packet(mssg)

    # se consigue el ttl
    ttl = struct_mssg[2]

    # si es 0 o menor, se debe ignorar el mensaje 
    if(ttl<=0):
        print("Se recibió paquete {} con TTL 0".format(struct_mssg[0]))
    # si el TTL no es 0, entonces se puede procesar
    else:
        # se revisa si el mensaje es para este router, si no, se hace forwarding
        if(struct_mssg[0] == ip and struct_mssg[1] == port):
            # el mensaje puede ser un fragmento
            # se consigue su ID
            frag_id = struct_mssg[3]
            # se debe agregar al diccionario o actualizar su lista
            if(frag_id in frag_dicc):
                (frag_dicc[frag_id]).append(mssg)
            else:
                frag_dicc[frag_id] = [mssg]

            # se intenta reconstruir el mensaje total
            final_mssg = aux_functions.reassemble_IP_packet(frag_dicc[frag_id])

            # si no es None, entonces se tiene un mensaje total y se imprime el mensaje (sin headers)
            if(final_mssg != None):
                # se borra la ID del diccionario
                frag_dicc.pop(frag_id)
                # se pasa a estructura
                final_mssg = aux_functions.parse_packet(final_mssg.encode())
                # se imprime el mensaje
                print(final_mssg[7])
        # si no, se debe hacer forwarding
        else:
            # se consigue la ruta para hacer forwarding
            (nxt_dir, MTU) = aux_functions.check_routes(r_lines, (struct_mssg[0], int(struct_mssg[1])), forwardList)

            # si es None, se descarta, si no, se hace forwarding
            if(nxt_dir == None):
                print("No hay rutas hacia {} para paquete {}".format(struct_mssg[1], struct_mssg[0]))
            else:
                # se debe disminuir su ttl, se crea un mensaje igual pero con el ttl disminuido en 1
                mssg = (aux_functions.create_packet([struct_mssg[0],struct_mssg[1],struct_mssg[2]-1,struct_mssg[3],struct_mssg[4],struct_mssg[5],struct_mssg[6],struct_mssg[7]])).encode()

                # se consigue la lista de fragmentos tal que sus tamaños sean menor o igual al MTU
                mssg_list = aux_functions.fragment_IP_packet(mssg, MTU)

                # en envían todos los mensaje de la lista
                for mssg_frag in mssg_list:
                    # se imprime el forwarding que se realiza
                    print("redirigiendo paquete {} con destino final {} desde {} hacia {}".format(struct_mssg[0], struct_mssg[1], port, nxt_dir[1]))
                    # se hace el forwarding            
                    router_socket.sendto(mssg_frag, nxt_dir)