# UDP Server
import socket
import logging
import argparse
import struct

from util import construieste_mesaj_raw

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)



def calculeaza_checksum(mesaj_binar):
    '''
        TODO: scrieti o functie care primeste un mesaj raw de bytes
        si calculeaza checksum pentru UDP
        exemplu de calcul aici:
        https://www.securitynik.com/2015/08/calculating-udp-checksum-with-taste-of.html
    '''
    checksum = 0
    get_list_2bytes = [mesaj_binar[i : i+ 2] for i in range(0, len(mesaj_binar), 2)]
    for bytes in get_list_2bytes:
        if(len(bytes) < 2):
            bytes = struct.unpack('B', bytes)[0]
            bytes = struct.pack('H', bytes)
        checksum += struct.unpack('!H', bytes)[0]

    first = checksum >> 16
    masca = 0b1111111111111111

    last = checksum & masca

    complement = first + last
    checksum_complemented = ~complement & masca

    return int(checksum_complemented)



def run_server(server_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(server_address)
    logging.info("Serverul a pornit pe %s si portnul portul %d", server_address[0], server_address[1])
    
    while True:
        logging.info('Asteptam mesaje...')
        data, address = sock.recvfrom(4096)
        logging.info(address)
        logging.info("Am primit %s octeti de la %s", len(data), address)
        logging.info('Content primit: "%s"', data)
        mesaj_binar = construieste_mesaj_raw(address[0], server_address[0], address[1], server_address[1], data)
        valoare_numerica = calculeaza_checksum(mesaj_binar)
        valoare = hex(valoare_numerica)

        logging.info('Checksum calculat: %s', str(valoare))
        sock.sendto(str(valoare).encode(), address)
        logging.info('Sent')
        

def main():
    parser = argparse.ArgumentParser(description='Server UDP',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--port', '-p', dest='port', action='store', type=int,
                        required=True, help='Portul serverului.')
    args = parser.parse_args()

    ip_server = socket.gethostbyname(socket.gethostname())
    server_address = (ip_server, args.port)
    run_server(server_address)


if __name__ == '__main__':
    main()
