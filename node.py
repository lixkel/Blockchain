class node:
    def __init__(self, output, conn, exp):
        self.socket, self.address = output
        self.authorized = False
        self.connection = conn
        self.expecting = exp
        self.best_height = 0
        self.port = self.address[1]
