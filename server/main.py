# file - main.py
# author - Gil Alpert
# this file will be used to run the server, I.E. this is the start script to run

import utils
import server


if __name__ == "__main__":
    port = utils.read_port_from_file('port.info')
    serv = server.Server(port)
    e = serv.start()
    if e is not None:
        utils.fatal_error(e)
