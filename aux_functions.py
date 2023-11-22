import socket
import timerList

# tamaño del buffer
buff_size = 2048

# función que transforma un número en a su versión en string, con una cantidad a elegir de largo máximo
def to_set_size(num, size):
    # se transforma el número a string
    num_str = str(num)

    # si el largo del número en forma de string es mayor al de el size, entonces se lanza un error
    if(len(num_str)>size):
        raise Exception("Number does not fit in given size")
    
    # mientras el tamaño sea menor al size, se le agregan 0's al comienzo para rellenar
    while(len(num_str) < size):
        num_str = "0"+num_str

    # se retorna el número transformado
    return num_str

# función que un número en forma de string con número de dígitos fijo y lo tranforma a un int
def from_set_size(num):
    # solo se pasa a int
    return int(num)

# función que recibe un paquete y lo parsea, retornando cada componente en una estrucutra
def parse_packet(IP_packet):
    # el separador a usar
    separator = ";"

    # se le hace decode
    IP_packet = IP_packet.decode()
    # se divide por comas
    IP_packet = IP_packet.split(separator)
    
    # se guarda la dirección IP (siempre es localhost, 127.0.0.1)
    ip = IP_packet[0]
    # se guarda el puerto 
    port = from_set_size(IP_packet[1])
    # se guarda el TTL 
    ttl = from_set_size(IP_packet[2])
    # se guarda el ID del mensaje
    id = from_set_size(IP_packet[3])
    # se guarda el offset
    offset = from_set_size(IP_packet[4])
    # se guarda el tamaño
    size = from_set_size(IP_packet[5])
    # se guarda la flag
    flag = from_set_size(IP_packet[6])
    # el mensaje (quizá en forma de lista, osea con más de un elemento)
    mssg_list = IP_packet[7:len(IP_packet)]

    # el mensaje en forma de string
    mssg = ""

    # se recontruye el mensaje (si es necesario)
    for slice in mssg_list:
        # se agrega al mensaje final
        mssg += slice
        # si es que es el útlimo, no se agrega una coma, si no es el último, entonces se agrega
        if(slice == mssg_list[len(mssg_list)-1]):
            pass
        else:
            mssg += separator

    # se retorna la estrcutura
    return [ip, port, ttl, id, offset, size, flag, mssg]

# función que recibe una estrcutra y la transforma en un mensaje
def create_packet(parsed_IP_packet):
    # el separador a usar
    separator = ";"

    # se consigue la estrcutura para modificarla
    list_param = parsed_IP_packet

    # se actualizan las partes del mensaje para que sigan el formato correcto
    # puerto (4 dígitos)
    list_param[1] = to_set_size(list_param[1], 4)
    # ttl (3 dígitos)
    list_param[2] = to_set_size(list_param[2], 3)
    # ID (8 dígitos)
    list_param[3] = to_set_size(list_param[3], 8)
    # offset (8 dígitos)
    list_param[4] = to_set_size(list_param[4], 8)
    # tamaño (8 dígitos)
    list_param[5] = to_set_size(list_param[5], 8)
    # flag (1 dígito)
    list_param[6] = to_set_size(list_param[6], 1)

    # donde se guarda el mensaje final
    final_mssg = ""
    
    # se crea el mensaje final en el formato correcto
    for param in list_param:
        # se agrega al mensaje final
        final_mssg += param
        # si es que es el útlimo, no se agrega una coma, si no es el último, entonces se agrega
        if(param == list_param[len(list_param)-1]):
            pass
        else:
            final_mssg += separator    

    # se retorna el mensaje final
    return final_mssg

# # test de funcionalidad
# IP_packet_v1 = "127.0.0.1,8881,010,00223344,00345678,00000300,1,hola, cómo estás?".encode()
# parsed_IP_packet = parse_packet(IP_packet_v1)
# IP_packet_v2_str = create_packet(parsed_IP_packet)
# IP_packet_v2 = IP_packet_v2_str.encode()
# print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

# función que recibe el nombre del archivo con la rutas, la dirección de destino y el objeto ForwardList,
# retorna el par con la dirección de hacia donde debe "saltar", si no encuntrea ninguno retorna none
def check_routes(r_lines, destination_address, forwardList):
    
    # se debe recivsar si la dirección de destino no está en la lista de Forward
    if(not (forwardList.in_forward_list(destination_address))):
        # si no está, se debe agregar a la lista un objeto

        # se crea el nuevo objeto
        new_forward = Forward(destination_address)
        # se le incializa su lista
        new_forward.innit_jump_list(r_lines)
        # se agrega a forward list
        forwardList.add_forward(new_forward)
        
    # se retorna la dirección de salto y el MTU
    return forwardList.get_nxt_jump(destination_address)

# función que recibe un paquete (en bytes) y un MTU y retorna una lista con 1 o más fragmentos de tamaño a lo más MTU
def fragment_IP_packet(IP_packet, MTU):
    # si es que el tamaño del packet es menor o igual a MTU, se retorna una lista de inmediato, si no, se debe dividir en trozos
    if(len(IP_packet)<=MTU):
        return [IP_packet]
    
    # el paquete se pasa a estructura
    IP_packet_struct = parse_packet(IP_packet)

    # se consiguen los campos que siempre se mantienen constantes
    ip = IP_packet_struct[0]
    port = IP_packet_struct[1]
    ttl = IP_packet_struct[2]
    id = IP_packet_struct[3]

    # offset actual
    current_offset = IP_packet_struct[4]
    # flag del mensaje original
    flag = IP_packet_struct[6]
    # lista que guardará los fragmentos
    fragments = []

    # tamaño de los headers
    headers_size = 48

    # se consigue el mensaje y se pasa a bytes
    mssg_section = (IP_packet_struct[7]).encode()
    # se consigue el largo del mensaje (en bytes)
    len_mssg_section = IP_packet_struct[5]
    # assert (nuna debería fallar, si falla entonces fue mal puesto en el mensaje original el tamaño en bytes)
    if(len_mssg_section != len(mssg_section)):
        raise Exception("Size no set correctly!")
    # cantidad de bytes del mensaje que han sido encapsuladas
    bytes_encapsuled = 0

    # se consigue el largo máximo en bytes que tendra cada sección de mensaje (en bytes)
    new_len_mssg_section = MTU-headers_size

    # ciclo while en el que se van creando los fragmentos
    while bytes_encapsuled < len_mssg_section:
        # nuevo mensaje parcial (en bytes)
        new_mssg = mssg_section[bytes_encapsuled:bytes_encapsuled+new_len_mssg_section]
        # se calcula su tamaño
        new_mssg_size = len(new_mssg)
        # se pasa a string
        new_mssg = new_mssg.decode()
        # se aumenta el número de bytes que se han encapsulado
        bytes_encapsuled += new_mssg_size
        # se guarda el offset nuevo
        new_offset = current_offset
        # se aumenta el offset en la cantidad de bytes encapsulados
        current_offset += new_mssg_size

        # almacena la nueva flag
        new_flag = 1

        # se elige la flag, si es que se llegó al byte final del mensaje y la flag original era 0,
        #  entonces la nueva flag es 0, si no es 1
        if((flag == 0) and (bytes_encapsuled >= len_mssg_section)):
            new_flag = 0

        # se crea un nuevo fragmento 
        fragment = create_packet([ip, port, ttl, id, new_offset, new_mssg_size, new_flag, new_mssg])
        # se pasa a bytes
        fragment = fragment.encode()

        # se añade a la lista
        fragments.append(fragment)

    # se retorna la lista con los fragmentos
    return fragments

# función que recibe una lista de fragmentos (en bytes) y la reemsabla en orden
def reassemble_IP_packet(fragment_list):
    # se ve el caso que la lista tenga tamaño 1
    if(len(fragment_list) == 1):
        # se pasa a estructura
        one_fragment = parse_packet(fragment_list[0])
        # se consigue la flag
        one_flag = one_fragment[6]
        # se consigue sy offset
        one_offset = one_fragment[4]
        # si la flag es 0 y su offset es 0 entonces es un paquete entero y se retorna de inmediato (en str), si no, se retorna none
        if(one_flag == 0 and one_offset == 0):
            return (fragment_list[0]).decode()
        else:
            return None
    
    # se crea una lista con todos los elementos en forma de estrcutura
    struct_list = []

    # para cada fragmento en la lista de fragmentos
    for fragment in fragment_list:
        # se pasa a estrcutura
        f_struct = parse_packet(fragment)
        # se agrega a la lista
        struct_list.append(f_struct)
        
    # se crea una lista que tendrá los pares con el offset en la primera componente
    # y el índice con la posición en la lista de fragmentos en la segunda
    pair_list = []

    for i in range(0, len(fragment_list)):
        # se obtiene el elemento i-ésimo de la lista
        f_i = struct_list[i]
        # se obtiene el offset
        f_offset = f_i[4]
        # se crea el par (offset, indice)
        f_pair = (f_offset, i)
        # se agrega a la lista de pares
        pair_list.append(f_pair)

    # se ordena la lista de pares por su offset
    pair_list.sort()

    # lista que almacenará los fragmentos en orden
    ordered_list = []

    # se agregan los fragmentos en orden
    for pair in pair_list:
        # se obtiene el elemento en la posición i
        f_i = fragment_list[pair[1]]
        # se agrega a la lista ordenada (en forma de estructura)
        ordered_list.append(parse_packet(f_i))

    # si consigue el offset inicial 
    current_offset = ordered_list[0][4]

    # si el offset inicial no es 0, entonces la lista está incompleta y se retorna None
    if(current_offset != 0):
        return None
    
    # donde se guardará el mensaje reconstruido
    total_mssg = ""

    # para cada elemento de la lista ordenada
    for f in ordered_list:
        # se consigue el offset
        f_offset = f[4]
        # se consigue le tamaño (en bytes) del mensaje
        f_size = f[5]
        # se consigue el mensaje fragmentado
        f_mssg = f[7]

        # si el offset es diferente al actual, entonces faltan miembros en la lista
        if(f_offset != current_offset):
            return None
        
        # se agrega el mensaje al mensaje total
        total_mssg += f_mssg
        # y se actualiza el offset actual
        current_offset += f_size

    # se debe revisar que la flag del último fragmento sea 0, si no, faltan fragmentos
    last_flag = ordered_list[len(ordered_list) - 1][6]

    if(last_flag != 0):
        return None

    # se crean los parámetros del mensaje nuevo
    # los primeros 4 campos son iguales para todos así que simplemente se eligen los del primero de la lista
    new_ip = ordered_list[0][0]
    new_port = ordered_list[0][1]
    new_ttl = ordered_list[0][2]
    new_id = ordered_list[0][3]
    # su offset es 0 pues es el mensaje completo
    new_offset = 0
    # el tamaño nuevo es el largo en bytes del mensajes
    new_size = len(total_mssg.encode())
    # la flag es 0 pues es el mesnaje completo
    new_flag = 0
    
    # se crea el paquete
    new_packet = create_packet([new_ip, new_port, new_ttl, new_id, new_offset, new_size, new_flag, total_mssg])

    # se retorna el paquete (en bytes)
    return new_packet

# IP_packet_v1 = "127.0.0.1,8885,010,00000347,00000000,00000080,0,hola!, este es un mensaje muy largo para revisar que todo funcione correctamente".encode()
# MTU = 60

# # test con MTU menor al tamaño del paquete
# fragment_list = fragment_IP_packet(IP_packet_v1, MTU)
# IP_packet_v2_str = reassemble_IP_packet(fragment_list)
# IP_packet_v2 = IP_packet_v2_str.encode()
# print("IP_packet_v1 = IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

# # test con MTU mayor al tamaño del paquete
# fragment_list = fragment_IP_packet(IP_packet_v1, MTU*4)
# IP_packet_v2_str = reassemble_IP_packet(fragment_list)
# IP_packet_v2 = IP_packet_v2_str.encode()
# print("IP_packet_v1 = IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

# función que crea un mensaje BGP con el formato dado en las instrucciones, recibe el nombre del archivo con la tabla de rutas y el ASN asociado a este
def create_BGP_message(route_table, ASN):
    # variable que almacenará las lineas de la tabla
    r_lines = None

    # se abre el archivo con la tabla de rutas
    with open(route_table) as f:
        # se leen todas las líneas y se guardan en una lista
        r_lines = f.readlines()

    # donde se guardará el mensaje BGP
    bgp_mssg = "BGP_ROUTES\n{}\n".format(ASN)

    # para cada línea de la tabla de rutas
    for line in r_lines:
        # se divide el mensaje por el espacio
        line = line.split()
        # se consigue la lista con los ASN
        asn_list = line[1:len(line)-3]
        # para cada elemento de la lista
        for i in range(0,len(asn_list)):
            # se agrega al mensaje
            bgp_mssg += asn_list[i]
            # si no es el último, se agrega un espacio en blanco
            if(i != len(asn_list)-1):
                bgp_mssg += " "
            # si no, un salto de línea
            else:
                bgp_mssg += "\n"
        
    # finalmente se agrega el mensaje "END_ROUTES"
    bgp_mssg += "END_ROUTES"
             
    # se retorna el mensaje
    return bgp_mssg

# # test para comprobar que funcione 

# bgp_mssg_example = '''BGP_ROUTES
# 8882
# 8881 8882
# 8883 8882
# 8884 8882
# END_ROUTES'''

# bgp_output = create_BGP_message("rutas/rutas_R2_v3_mtu.txt", 8882)
# print("bgp_output = bgp_mssg_example ? {}".format(bgp_output == bgp_mssg_example))

# función que parsea un mensaje BGP, retornando una lista de listas, donde cada lista
# tiene el "camino" hacia el router de destino
def parse_BGP_message(bgp_message):
    # inicio mensaje bgp routes
    bgp_routes_start = "BGP_ROUTES"
    # final mensaje bgp routes
    bgp_routes_end = "END_ROUTES"

    # donde se guardará el ASN del router que envió la tabla
    asn = None

    # se divide el mensaje por saltos de línea
    routes_list = bgp_message.split("\n")

    # la primera línea del mensaje debe ser "BGP_ROUTES"
    # y la última "END_ROUTES", si no se ignora
    if((routes_list[0] == bgp_routes_start) and (routes_list[len(routes_list)-1] == bgp_routes_end)):
        # se actualiza el número del asn asociado
        asn = int(routes_list[1])

        # se actualiza a lista para solo tener las rutas ASN
        routes_list = routes_list[2:len(routes_list)-1]

        # para cada elemento de la lista
        for i in range(0, len(routes_list)):
            # para cada elemento se pasa de string a lista
            routes_list[i] = routes_list[i].split()
            # se pasa a una lista de int
            for j in range(0, len(routes_list[i])):
                # se pasa de string a int
                routes_list[i][j] = int(routes_list[i][j])

        # se devuelve un par con el asn y la lista
        return [asn, routes_list]

    else:
        # se retorna none
        return None
        

# test para comprobar que funcione 

# bgp_mssg_example = '''BGP_ROUTES
# 8882
# 8881 8882
# 8883 8882
# 8884 8882
# END_ROUTES'''

# bgp_output = create_BGP_message("rutas/rutas_R2_v3_mtu.txt", 8882)
# print("bgp_output = bgp_mssg_example ? {}".format(bgp_output == bgp_mssg_example))

# # la lista que debe retornar
# bgp_list = [8882, [[8881, 8882], [8883, 8882], [8884, 8882]]]

# bgp_output_parse = parse_BGP_message(bgp_output)
# print("bgp_output_parse = bgp_list ? {}".format(bgp_output_parse == bgp_list))

# función que recibe una tabla de rutas, y retorna una lista de pares con el puerto de destino y 
# puerto al que se debe envíar para que llegue al destino
def pairs_dest_hop(route_table):
    # se consiguen las líneas de la tabla de rutas 
    with open(route_table) as f:
        # se leen todas las líneas y se guardan en una lista
        r_lines = f.readlines()
    
    # lista con los pares
    pair_dest_hop_list = []

    # se consiguen las direcciones de salto para todos los vecinos
    for line in r_lines:
        # se divide cada linea por el espacio
        line = line.split()
        # se consifue la dirección (puerto) de destino
        dest = int(line[1])
        # se consigue el vecino al que se debe enviar
        hop = int(line[len(line)-2])
        # se agrega a la lista de pares
        pair_dest_hop_list.append((dest, hop))   

    return pair_dest_hop_list

# # test de funcionalidad
# pair_list = pairs_dest_hop("rutas_completas_3/rutas_R1_v3_mtu.txt")
# print("pair_list_func = pair_list ? {}".format(pair_list == [(8882,8882), (8883,8882)]))

# función que recibe una lista con el ASN en primera posición y en segunda posición una lista de listas
# que representan las rutas ASN, también recibe un arhcivo de texto y lo sobreescribe para crear una nueva
# tabla de rutas
def new_route_table(ASN_struct, route_table):
    # ip de localhost
    ip = "127.0.0.1"
    # MTU
    MTU = "1000"

    # texto que se escribirá en la tabla de rutas
    new_txt = ""
    # se abre el archivo
    f = open(route_table, "w")

    # para cada ruta en la lista de rutas
    for route in ASN_struct[1]:
        # se agrega la IP
        new_txt += ip
        # se consigue el siguiente salto
        nxt_jump = str(route[len(route)-2])
        # para cada ASN se agrega a la ruta 
        for ASN in route:
            new_txt += " "+str(ASN)
        # se agrega la IP de nuevo
        new_txt += " "+ip
        # se agrega el siguiente salto, MTU y el salto de linea
        new_txt += " "+nxt_jump+" "+MTU+"\n"
        
    # se elimina el útlimo salto de lnea
    new_txt = new_txt[0:len(new_txt)-1]

    # se sobreescribe el archivo
    f.write(new_txt)
    # se cierra el archivo
    f.close()

# # test de funcionamiento
# bgp_list = [8882, [[8881, 8882], [8883, 8882], [8884, 8882], [8885, 8884, 8882]]]
# new_route_table(bgp_list, "new_file.txt")

# función que ejecuta el algoritmo BGP, recibe el socketUDP que representa al router, el archivo de la tabla de rutas y el ASN
def run_BGP(socket_sender: socket.socket, route_table, ASN):
    # mensaje start bgp
    start_bgp = "START_BGP"
    # ip de localhost
    ip = "127.0.0.1"
    # ttl
    ttl = 10
    # id (va aumentando por cada mensaje)
    id = 0

    # se crea el mensaje BGP que se enviará a los otros routers
    bpg_routes = create_BGP_message(route_table, ASN)

    # lista que guardará pares con el vecino al que se quiere llegar y el vecino al que se debe ir
    pair_dest_hop_list = pairs_dest_hop(route_table)
    
    # se envía el mensaje de inicio para todos los vecinos
    for pair in pair_dest_hop_list:
        # se crea el mensaje
        start_mssg = create_packet([ip, pair[0], ttl, id, 0, len(start_bgp.encode()), 0, start_bgp]).encode()
        # se aumenta el id
        id += 1
        # se envía el mensaje start bgp
        socket_sender.sendto(start_mssg, (ip, pair[1]))

    # se envía el mensaje de rutas para todos los vecinos
    for pair in pair_dest_hop_list:
        # se crea el mensaje
        start_mssg = create_packet([ip, pair[0], ttl, id, 0, len(bpg_routes.encode()), 0, bpg_routes]).encode()
        # se aumenta el id
        id += 1
        # se envía el mensaje bgp
        socket_sender.sendto(start_mssg, (ip, pair[1]))  

    # timer
    timer = timerList.TimerList(5,1)
    timer.start_timer(0)

    # se deja el socket como no bloqueante
    socket_sender.setblocking(False)

    # se empieza a recibir mensajes BGP de los otros vecinos
    while True:
        # si se hace timeout, se debe retornar
        if len(timer.get_timed_out_timers()) == 1:
            # se hace que el socket sea bloqueante de nuevo
            socket_sender.setblocking(True)
            # se retorna
            return

        try:
            # se recibe un mensaje de vecino
            mssg, address = socket_sender.recvfrom(buff_size)
            # se pasa a estructura
            struct_mssg = parse_packet(mssg)
            # se consigue el contenido del mensaje
            mssg_text = struct_mssg[7]
            # si el mensaje es "START_BGP" se ignora, si no...
            if(mssg_text != start_bgp):
                # se le hace parse al mensaje
                parsed_bgp = parse_BGP_message(mssg_text)
                # si el mensaje parseado es una lista y no none, entonces se continua
                if(parsed_bgp != None):
                    # bgp_list = [8882, [[8881, 8882], [8883, 8882], [8884, 8882]]]
                    
                    # se obtiene la lista con las rutas (listas) del vecino que se acaba de recibir
                    ASN_routes_neighbor = parsed_bgp[1]
                    # se crea un mensaje BGP con las rutas ASN de nuestro router (de nuevo porque puede haber sido actualizada)
                    current_BPG_message = create_BGP_message(route_table, ASN)
                    # se pasa a una lista 
                    ASN_routes_self = parse_BGP_message(current_BPG_message)[1]
                    # el largo de la lista de rutas actual
                    len_ASN_routes_self = len(ASN_routes_self)
                    # dice si la tabla de rutas ha sido actualizada
                    updated = False

                    # se revisan las rutas que se recibieron del vecino
                    for ASN_new_route in ASN_routes_neighbor:
                        # si es que el ASN propio está en la lista de descarta pues puede generar ciclos
                        if(not (ASN in ASN_new_route)):
                            # se consigue la dirección de destino del la ruta nueva
                            new_route_dest = ASN_new_route[0]
                            # dice si la ruta hacia la dirección de destino estaba en la lista de rutas
                            existed = False 
                            # se revisa la lista de rutas actuales
                            for i in range(0, len_ASN_routes_self):
                                # para cada uno se consigue la i-ésima dirección de destino
                                dest_i = ASN_routes_self[i][0]
                                # si la ruta de destino es igual 
                                if(dest_i == new_route_dest):
                                    # se crea la nueva ruta
                                    new_route = ASN_new_route + [ASN]
                                    # entonces se debe elegir la ruta más corta
                                    if(len(ASN_new_route) < len(new_route)):
                                        ASN_routes_self[i] = new_route
                                        # también se cambian las flags de existed y updated
                                        existed = True
                                        updated = True
                            # en el caso de que no haya existido la ruta, se agrega a la lista de rutas, agregando nuestro ASN
                            if(not existed):
                                # se crea la nueva ruta
                                new_route = ASN_new_route + [ASN]
                                # se agrega a la lista actual de rutas
                                ASN_routes_self.append(new_route)
                                # se actualiza 
                                updated = True
                    
                    # si se actualizó
                    if(updated):
                        # se debe actualizar la tabla de rutas
                        new_route_table([ASN, ASN_routes_self], route_table)

                        # y se deben enviar mensaje nuevos
                        # se crea un mensaje de rutas nuevo
                        new_BGP_mssg_str = create_BGP_message(route_table, ASN)

                        # se consigue una nueva lista de pares lista que guardará 
                        # pares con el vecino al que se quiere llegar y el vecino al que se debe ir
                        new_pair_dest_hop_list = pairs_dest_hop(route_table)
                        
                        # se envía el mensaje BGP nuevo para todos los vecinos
                        for pair in new_pair_dest_hop_list:
                            # se crea el mensaje
                            new_BGP_mssg = (create_packet([ip, pair[0], ttl, id, 0, len(new_BGP_mssg_str.encode()), 0, new_BGP_mssg_str])).encode()
                            # se aumenta el id
                            id += 1
                            # se envía el mensaje start bgp
                            socket_sender.sendto(new_BGP_mssg, (ip, pair[1]))      

                        # luego de enviar los mensaje se reinicia el timer
                        timer = timerList.TimerList(5,1)
                        timer.start_timer(0)      

        except BlockingIOError:
            pass

# clase que representa todas las posibles salidas del router para una dirección de destino específica, en el router actual
class Forward:
    def __init__(self, destination_address):
        self.destination_address = destination_address
        self.jumps = None
        self.i = None
        self.len = None

    # función que inicializa la lista con todas las posibles salidas
    def innit_jump_list(self, route_table):
        # la lista de saltos se inicializa como una lista vacía
        self.jumps = []

        # se obtienen la dirección IP y puerto de destino
        ip_destination = self.destination_address[0]
        port_destination = self.destination_address[1]

        # se lee cada linea de la tabla
        for line in route_table:
            # se divide la línea por componente
            line = line.split()
            # se consigue el largo de la lista
            len_line = len(line)
            
            # IP que reprsenta la red
            cidr = line[0]
            # puerto de destino de la tabla
            port_destination_table = int(line[1])

            # si se encuentra una línea que corresponde
            if((ip_destination == cidr) and (port_destination_table == port_destination)):
                # se actualiza la lista con el par ip lista y el MTU
                self.jumps.append(((line[len_line-3], int(line[len_line-2])), int(line[len_line-1])))
        
        # se inicializa el índice
        self.i = 0
        # se guarda el largo de la lista
        self.len = len(self.jumps)

    # función que retorna el siguiente valor de la lista cíclica y actualiza el índice
    def get_nxt_jump(self):
        # si es que la lista es de tamaño 0 (vacía, osea no hay saltos) se retorna none
        if (self.len == 0):
            return None
        
        # se consigue el elemento de la lista
        nxt_jump = self.jumps[self.i]
        # se actualiza el índice
        self.i = (self.i+1)%self.len
        # se retorna el siguiente salto
        return nxt_jump

# clase que representa todas las listas de salidas de el router para cada dirección de destino
class ForwardList:
    def __init__(self, current_address):
        self.current_address = current_address
        self.forward_list = []

    # función que agrega un objeto Forward a la lista
    def add_forward(self, new_forward):
        self.forward_list.append(new_forward)

    # función que dice si es que se encuentra el objeto 
    # asociado a la dirección de destino dada
    def in_forward_list(self, destination_address):
        # dice si está o no en la lista
        in_list = False

        # para cada obejto en la lista
        for forward in self.forward_list:
            # si la dirección de destino es correcta
            if(forward.destination_address == destination_address):
                # está en la lista
                in_list = True
        
        return in_list

    # función que recibe una dirección de destino (ip y puerto)
    # y retorna el par (ip, puerto) que le corresponde del round 
    # robin (puede ser None)
    def get_nxt_jump(self, destination_address):
        # para cada obejto en la lista
        for forward in self.forward_list:
            # si la dirección de destino es correcta
            if(forward.destination_address == destination_address):
                # se consigue el siguiente salto (y actualiza su indice)
                nxt_jump = forward.get_nxt_jump()
                # se retorna el valor
                return nxt_jump