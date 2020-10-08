def start_node(nodes, inbound, outbound):
    import socket
    global socket
    from node import node
    global server_socket
    global sockets_list
    host = "0.0.0.0"
    port = 9999
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setblocking(0)
    bind_socket(host, port)
    sockets_list = [server_socket]
    main(nodes, inbound, outbound)


def main(nodes, inbound, outbound):
    import select
    from node import node
    global socket
    global server_socket
    global sockets_list
    while True:
        read_sockets, write, exception_sockets = select.select(sockets_list, sockets_list, sockets_list, 0)
        for soc in read_sockets:
            if soc == server_socket:
                new_soc = server_socket.accept()
                new_node = node(new_soc, "inbound", "version")
                sockets_list.append(new_node.socket)
                nodes[new_node.address] = new_node
            else:
                new_message = receive_message(soc)
                if not new_message:
                    sockets_list.remove(soc)
                    del nodes[soc.getpeername()]
                else:
                    inbound.put([soc, new_message])

        for exception in exception_sockets:
            sockets_list.remove(expection)
            del nodes[exception]

        if not outbound.empty():
            comm, body = outbound.get()
            if comm == "connect":
                addr, vers = body
                new_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    new_soc.connect((addr, 9999))
                    new_node = node((new_soc, new_soc.getpeername()), "outbound", "version")
                    sockets_list.append(new_node.socket)
                    nodes[new_node.address] = new_node
                    send_message(new_node.socket, vers)
                except socket.error as e:
                    print(f"Address-related error connecting to server: {e}")
            elif comm == "send":
                soc, message = body
                send_message(soc, message)
            elif comm == "broadcast":
                skip_soc, tx = body
                for soc in sockets_list:
                    if soc == server_socket or soc.getpeername() == skip_soc:
                        continue
                    send_message(soc, tx)
            elif comm == "end":
                for soc in sockets_list:
                    soc.close()
                break


def send_message(soc, message):
    global socket
    try:
        soc.send(message)
    except socket.error as e:
        print(f"Error sending data: {e}")


def bind_socket(host, port):
    global socket
    try:
        global server_socket
        server_socket.bind((host, port))
        server_socket.listen()

    except socket.error as e:
        print(f"Socket Binding error {e}\nRetrying...")
        bind_socket()


def receive_message(soc):
    global socket
    try:
        message_header = soc.recv(16)
        if message_header == b"":
            return False
        message_header = message_header.hex()
        payload_lenght = int(message_header[24:], 16)
        payload = soc.recv(payload_lenght)
        return message_header + payload.hex()
    except socket.error as e:
        print(f"Error receiving data: {e}")
        return False
