# UDP client
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
    get_list_2bytes = [mesaj_binar[i: i + 2] for i in range(0, len(mesaj_binar), 2)]
    for bytes in get_list_2bytes:
        if (len(bytes) < 2):
            bytes = struct.unpack('B', bytes)[0]
            bytes = struct.pack('H', bytes)
        checksum += struct.unpack('!H', bytes)[0]

    first = checksum >> 16
    masca = 0b1111111111111111

    last = checksum & masca

    complement = first + last
    checksum_complemented = ~complement & masca

    return int(checksum_complemented)


def send_message(server_address, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ip_client = socket.gethostbyname(socket.gethostname())
        logging.info('Trimitem mesajul "%s" catre %s:%d', message, server_address[0], server_address[1])
        address = (ip_client, 50451)
        sock.bind(address)
        sock.sendto(message.encode('utf-8'), server_address)
        logging.info('Asteptam un raspuns...')
        data, server = sock.recvfrom(4096)
        mesaj_binar = construieste_mesaj_raw(server[0], address[0], server[1], address[1], data)
        checksum = calculeaza_checksum(mesaj_binar)
        logging.info('Content primit: "%s"', data.decode('UTF-8'))
        logging.info('Checksum calculat: {}'.format(hex(checksum)))

    finally:
        logging.info('closing socket')
        sock.close()


def main():
    parser = argparse.ArgumentParser(description='Client UDP',
                                 formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--server', '-s', dest='server', action='store',
                        required=True, help='Adresa IP a serverului')
    parser.add_argument('--port', '-p', dest='port', action='store', type=int,
                        required=True, help='Portul serverului.')
    parser.add_argument('--mesaj', '-m', dest='mesaj', action='store',
                        default="", help='Mesaj de trimis prin UDP')
    args = parser.parse_args()
    server_address = (args.server, args.port)

    send_message(server_address, args.mesaj)


if __name__ == '__main__':
    main()
