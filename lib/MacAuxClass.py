from ipaddress import ip_address
import socket
import netifaces

class MacAux:
    @staticmethod
    def get_machine_info():

        network_data = netifaces.ifaddresses('lo')[2][0]

        return dict(hostname=socket.gethostname(), host_ip=socket.gethostbyname(socket.gethostname()), addr=network_data['addr'], netmask=network_data['netmask'], peer=network_data['peer'])

    @staticmethod
    def get_remote_machine_info():
        remote_host = "www.python.org"
        try:
            print(
                "IP address of %s: %s"
                % (remote_host, socket.gethostbyname(remote_host))
            )
        except socket.error as err_msg:
            print("%s: %s" % (remote_host, err_msg))
