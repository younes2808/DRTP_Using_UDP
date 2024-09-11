import os
import socket
import argparse
import struct
import sys
import datetime
import time

# Constants
HEADER_SIZE = 6 # bytes
DATA_SIZE = 994 # bytes
TIMEOUT = 0.5  # in seconds

# Flag positions
SYN_FLAG = 0b1000
ACK_FLAG = 0b0100
FIN_FLAG = 0b0010
# Description: Packs header information into a binary string.
# Arguments:
# - seq_num: Sequence number.
# - ack_num: Acknowledgment number.
# - flags: Flags representing packet properties.
# This function takes sequence number, acknowledgment number, and flags as input,
# packs them into a binary string according to the specified format, and returns the packed header.
# Returns:
# Packed binary header string.
# Functions for packing and unpacking headers
def pack_header(seq_num, ack_num, flags):
    return struct.pack('!HHH', seq_num, ack_num, flags)
# Description: Unpacks header information from a binary string.
# Arguments:
# - header: Binary string containing header information.
# This function takes a binary string containing header information as input,
# unpacks it according to the specified format, and returns the unpacked sequence number,
# acknowledgment number, and flags.
# Returns:
# Tuple containing unpacked sequence number, acknowledgment number, and flags.
def unpack_header(header):
    return struct.unpack('!HHH', header)
# Description: Initializes the client-side instance with necessary attributes.
# Arguments:
# - host: IP address of the server.
# - port: Port number of the server.
# - file_path: Path of the file to be transferred.
# - window_size: Size of the sliding window for flow control.
# This constructor method initializes the client instance with the provided parameters,
# sets up the initial window parameters, creates a UDP socket, and sets the timeout.
# Returns:
# None.
class Client:
    def __init__(self, host, port, file_path, window_size):
        self.host = host
        self.port = port
        self.file_path = file_path
        self.window_start = 0  # Start of the sliding window
        self.window_size = window_size  # Size of the sliding window
        self.window = set()  # Initialize an empty set to store sent packets within the window
        self.seq_num = 0
        self.ack_num = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(TIMEOUT)  # Set socket timeout
# Description: Initiates the file transfer process from the client side.
# Arguments:
# None.
# This method initiates the file transfer process from the client side. It attempts to
# establish a connection with the server, sends a SYN packet to initiate the connection,
# and continues with sending data packets. It handles various exceptions such as connection
# refusal, timeouts, and general errors.
# Returns:
# None.
    def send_file(self):
        try:
            # Attempt to connect to the server with a timeout
            self.sock.settimeout(TIMEOUT)
            self.sock.connect((self.host, self.port))
            print("Connection established Phase:")
            self.send_syn_packet()
            # Continuing with file transfer logic
            # (e.g., send file data packets)
        except ConnectionRefusedError:
            print("Error: Connection refused. Server is not available at {}:{}".format(self.host, self.port))
            print("closing connection")
            self.close_connection()
        except socket.timeout:
            print("Error: Connection attempt timed out. Server is not available at {}:{}".format(self.host, self.port))
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("Error sending file:", e)
            print("closing connection")
            self.close_connection()
# Description: Sends a SYN packet to the server to initiate connection.
# Arguments:
# None.
# This method sends a SYN packet to the server to initiate the connection establishment process.
# It constructs the packet header, sends it over the UDP socket, and awaits a response.
# Returns:
# None.
    def send_syn_packet(self):
        try:
            header = pack_header(self.seq_num, self.ack_num, SYN_FLAG)
            self.sock.settimeout(TIMEOUT)
            self.sock.sendto(header, (self.host, self.port))
            print("SYN packet is sent")
            self.receive_syn_ack()
        except socket.timeout:
            print("Timeout: Couldnt send SYN pack")
            print("closing connection")
            self.close_connection()
        except socket.error as e:
            print("Socket error:", e)
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("Error:", e)
            print("closing connection")
            self.close_connection()
# Description: Receives SYN-ACK packet from the server.
# Arguments:
# None.
# This method waits to receive a SYN-ACK packet from the server in response to the SYN packet
# sent earlier. It checks if the received packet has both SYN and ACK flags set, updates the
# acknowledgment number, and sends an acknowledgment packet in return.
# Returns:
# None.
    def receive_syn_ack(self):
        try:
            # Attempt to receive a packet from the socket
            received_header, sender_address = self.sock.recvfrom(HEADER_SIZE)

            # Unpack the received header to extract sequence number, acknowledgment number, and flags
            _, received_ack_num, received_flags = unpack_header(received_header)

            # Check if the received packet has both SYN and ACK flags set
            if received_flags & SYN_FLAG and received_flags & ACK_FLAG:
                print("SYN-ACK packet is received")

                # Update acknowledgment number
                self.ack_num = received_ack_num
                # Client sending acknowledgment
                self.send_ack(sender_address)
        except socket.timeout:
            print("Socket timeout occurred while waiting for SYN-ACK packet.")
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("There is no server running\n")
            self.close_connection()
# Description: Sends an acknowledgment packet to the server.
# Arguments:
# sender_address: Address of the server to send the acknowledgment to.
# This method constructs and sends an acknowledgment packet to the server, acknowledging the
# receipt of a packet or confirming the initiation of the connection.
# Returns:
# None.
    def send_ack(self, sender_address):
        try:
            # Craft the ACK packet header
            header = pack_header(self.seq_num, self.ack_num, ACK_FLAG)
            # Set timeout for sending ACK packet
            self.sock.settimeout(TIMEOUT)
            # Send the ACK packet to the server
            self.sock.sendto(header, sender_address)
            print("ACK packet is sent")
            self.send_data_packets()
        except socket.timeout:
            print("Timeout: Unable to send ACK packet")
            print("closing connection")
            self.close_connection()
        except socket.error as e:
            print("Socket error:", e)
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("Error:", e)
            print("closing connection")
            self.close_connection()
# Description: Sends data packets containing file content to the server.
# Arguments:
# None.
# This method reads data from the file, constructs data packets with appropriate headers,
# and sends them to the server. It maintains a sliding window for flow control and handles
# retransmission of unacknowledged packets.
# Returns:
# None.
    def send_data_packets(self):
        print("Data Transfer:\n")
        with open(self.file_path, 'rb') as file:
            while True:
                while len(self.window) < self.window_size:               
                    # Read data from file
                    data = file.read(DATA_SIZE)
                    # Send packet if within window
                    # # Create packet
                    header = pack_header(self.seq_num, self.ack_num, 0)
                    packet = header + data
                    self.sock.send(packet)        
                    self.window.add(self.seq_num)
                    current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                    print(f"{current_time} -- Data packet with seq = {self.seq_num} is sent, sliding window = {self.window}")       
                    self.seq_num += 1
                self.receive_ack()
                # Check if the sent packet is the last one
                if len(data) < DATA_SIZE:
                    break
        #The while loop will end when everything has been sent so,
        #There will be the length of the last window acknowledgements left
        for _ in range(len(self.window)):
            self.receive_ack()
        # Send FIN packet for connection teardown
        self.send_fin_packet()
# Description: Receives acknowledgment packets from the server.
# Arguments:
# None.
# This method waits to receive acknowledgment packets from the server for the sent data packets.
# It handles timeouts, retransmits unacknowledged packets, and updates the sliding window.
# If a duplicate acknowledgment is received, it is ignored.
# Returns:
# None.
    def receive_ack(self):
        try:
            # Set socket timeout
            self.last_received_ack = None
            self.sock.settimeout(TIMEOUT)
            received_header, _ = self.sock.recvfrom(HEADER_SIZE)
            _, received_ack_num, received_flags = unpack_header(received_header)
            if received_flags & ACK_FLAG:
                current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"{current_time} -- ACK for packet = {received_ack_num} is received")
                # Check if the acknowledgment is a duplicate
                if received_ack_num == self.last_received_ack:
                    current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                    print(f"{current_time} -- Duplicate ACK for packet = {received_ack_num} received. Ignoring.")
                    return  # Ignore duplicate acknowledgment
                # Update last received acknowledgment number
                self.last_received_ack = received_ack_num
                # Acknowledge the correct sequence number
                if received_ack_num in self.window:
                    self.window.remove(received_ack_num)
                # Slide window if possible
                while self.window_start in self.window:
                    self.window.remove(self.window_start)
                    self.window_start += 1
            # Reset socket timeout
            self.sock.settimeout(None)
        except socket.timeout:
            current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(f"{current_time} -- Socket timeout occurred while waiting for ACK packet. Retransmitting unacknowledged packets.")
            # Retransmit unacknowledged packets
            for seq_num in self.window:
                with open(self.file_path, 'rb') as file:
                    print("RTO occured")
                    file.seek(seq_num * DATA_SIZE)
                    data = file.read(DATA_SIZE)
                    header = pack_header(seq_num, self.ack_num, 0)
                    packet = header + data
                    self.sock.send(packet)
                    current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                    print(f"{current_time} -- Retransmitted data packet with seq = {seq_num}")
        except Exception as e:
            current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(f"{current_time} -- Error receiving ACK packet:", e)
# Description: Sends a FIN packet to the server to initiate connection teardown.
# Arguments:
# None.
# This method sends a FIN packet to the server to initiate the connection teardown process
# after all data has been transmitted. It awaits a FIN-ACK packet from the server.
# Returns:
# None.
    def send_fin_packet(self):
        try:
            header = pack_header(self.seq_num, self.ack_num, FIN_FLAG)
            self.sock.send(header)
            print("FIN packet is sent")
            self.receive_fin_ack()
        except socket.timeout:
            print("Timeout: No response received for FIN ACK")
            print("closing connection")
            self.close_connection()
        except socket.error:
            print("Couldn't connect to socket")
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("Error:", e)
            print("closing connection")
            self.close_connection()
# Description: Receives FIN-ACK packet from the server.
# Arguments:
# None.
# This method waits to receive a FIN-ACK packet from the server in response to the FIN packet
# sent earlier. Upon receiving the FIN-ACK packet, it closes the connection.
# Returns:
# None.
    def receive_fin_ack(self):
        try:
            received_header = self.sock.recv(HEADER_SIZE)
            _, received_ack_num, received_flags = unpack_header(received_header)

            if received_flags & ACK_FLAG and received_flags & FIN_FLAG:
                print("FIN-ACK packet is received")
                # Close the connection
                self.close_connection()
        except socket.timeout:
            print("Socket timeout occurred while waiting for FIN-ACK packet.")
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("Error receiving FIN-ACK packet:", e)
            print("closing connection")
            self.close_connection()
# Description: Closes the client-side connection.
# Arguments:
# None.
# This method closes the UDP socket used for communication on the client side and exits the program.
# Returns:
# None.
    def close_connection(self):
        try:
            print("Connection Closed")
            self.sock.close()
            sys.exit(1)
        except socket.error:
            print("Error: Couldn't close socket")
            sys.exit(1)
        except Exception as e:
            print("Error:", e)
            sys.exit(1)

class Server:
# Description: Initializes the server-side instance with necessary attributes.
# Arguments:
# - host: IP address of the server.
# - port: Port number of the server.
# - discard: Sequence number to discard for testing purposes.
# This constructor method initializes the server instance with the provided parameters,
# creates a UDP socket, binds it to the specified address and port, and sets up initial
# parameters for handling connections.
# Returns:
# None.    
    def __init__(self, host, port, discard):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.discard = discard
        # Remove timeout for the initial connection phase
        self.sock.settimeout(None)
        
# Description: Starts the server and waits for connections.
# Arguments:
# None.
# This method starts the server and waits for incoming connections. It listens for SYN packets
# from clients and initiates the connection establishment process by sending SYN-ACK packets.
# Returns:
# None.        
    def start_server(self):
        print("Waiting for connection...")
        self.receive_syn_packet()
# Description: Receives SYN packet from the client.
# Arguments:
# None.
# This method waits to receive a SYN packet from a client to initiate the connection establishment
# process. Upon receiving the SYN packet, it responds with a SYN-ACK packet.
# Returns:
# None.        
    def receive_syn_packet(self):
        # Attempt to receive a packet from the socket
        try:
            packet, sender_address = self.sock.recvfrom(HEADER_SIZE)

            # Unpack the packet header to extract sequence number and flags
            _, _, flags = unpack_header(packet)

            # Check if the SYN flag is set in the received packet
            if flags & SYN_FLAG:
                print("SYN packet received")
                self.send_syn_ack(sender_address)  # Add this line to call the send_syn_ack method
        except Exception as e:
            print("Error receiving SYN packet:", e)
            print("closing connection")
            self.close_connection()
# Description: Sends SYN-ACK packet to the client.
# Arguments:
# sender_address: Address of the client to send the SYN-ACK packet to.
# This method constructs and sends a SYN-ACK packet to the client in response to a received SYN packet.
# Returns:
# None.
    def send_syn_ack(self, sender_address):
        try:
            # Craft the SYN-ACK packet header
            flags = SYN_FLAG | ACK_FLAG 
            syn_ack_packet = pack_header(0, 1, flags)
            # Send the SYN-ACK packet to the client
            self.sock.sendto(syn_ack_packet, sender_address)
            print("SYN-ACK packet is sent")
            self.receive_ack()
        except socket.timeout:
            print("Timeout: No response received for ACK")
            print("closing connection")
            self.close_connection()
        except socket.error as e:
            print("Socket error:", e)
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("Error:", e)
            print("closing connection")
            self.close_connection()
# Description: Receives acknowledgment packet from the client.
# Arguments:
# None.
# This method waits to receive an acknowledgment packet from the client in response to the
# SYN-ACK packet sent earlier. Upon receiving the acknowledgment, it proceeds with data transfer.
# Returns:
# None.
    def receive_ack(self):
        try:
            # Attempt to receive a packet from the socket
            received_header, sender_address = self.sock.recvfrom(HEADER_SIZE)

            # Unpack the received header to extract sequence number, acknowledgment number, and flags
            _, received_ack_num, received_flags = unpack_header(received_header)

            # Check if the received packet has both SYN and ACK flags set
            if received_flags & ACK_FLAG:
                print("ACK packet is received")
                self.receive_data_packets(sender_address)
                #Begin file transfer
            
        except socket.timeout:
            print("Socket timeout occurred while waiting for ACK packet.")
            print("closing connection")
            self.close_connection()
        except Exception as e:
            print("Error receiving ACK packet:", e)
# Description: Receives data packets from the client.
# Arguments:
# sender_address: Address of the client sending the data packet.
# This method receives data packets from the client, writes the received data to a file,
# sends acknowledgments for the received packets, and handles retransmission requests and timeouts.
# The code also handles duplicate packets by checking the expected sequence number and not writing the file
# if it does not match the expected sequence number
# Returns:
# None.    
    def receive_data_packets(self, sender_address):
        try:
            print("\nConnection Established")
            expected_seq_num =0
            discard_seq_num = None  # Initialize discard sequence number
            if self.discard:
                discard_seq_num = self.discard  # Store the sequence number to discard     
                       
            with open("received_image.jpg", 'wb') as file:
                start_time = time.time()
                while True:
                    # Receive the packet
                    received_packet, sender_address = self.sock.recvfrom(HEADER_SIZE + DATA_SIZE)
                    
                    # Extract the header and data from the received packet
                    header = received_packet[:HEADER_SIZE]
                    data = received_packet[HEADER_SIZE:]

                    # Unpack the header to extract sequence number, acknowledgment number, and flags
                    seq_num, ack_num, received_flags = unpack_header(header)
                    # Check if the packet contains the FIN flag
                    if received_flags & FIN_FLAG:
                        break  # Exit the loop if the FIN flag is set
                    if seq_num == discard_seq_num:
                        current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        print(f"{current_time} -- Discarding packet {seq_num}")
                        discard_seq_num=None
                        #Turning off the timeout to wait for packets
                        self.sock.settimeout(None)
                        continue  # Skip processing this packet and wait for the client to resend it
                    if seq_num == expected_seq_num:
                        current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        print(f"{current_time} -- Packet {seq_num} is received")
                        # Write the received data to the file
                        file.write(data)
                        # Send an acknowledgment for the received packet
                        current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        print(f"{current_time} -- Sending ACK for the received {seq_num}")
                        ack_header = pack_header(0, seq_num, ACK_FLAG)
                        self.sock.sendto(ack_header, sender_address)
                        expected_seq_num +=1             
                    else:
                        #Turning off the timeout to wait for packets
                        self.sock.settimeout(None)
                        current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        print(f"{current_time} -- OUT OF ORDER Packet {seq_num} is received")
                        print("Discarded")
                        continue
                    # Check if the received packet is the last one
                    if len(data) < DATA_SIZE:
                        break  # Exit the loop if the last packet is received
                end_time = time.time()
                throughput = (file.tell() * 8) / (end_time - start_time) / 1e6  # in Mbps
                print(f"The throughput is {throughput:.2f} Mbps")

            # rECEIVE FIN packet for connection teardown
            self.receive_fin_packet(sender_address)
        except Exception as e:
            print("Error receiving data packets:", e)
# Description: Sends FIN packet to the client to initiate connection teardown.
# Arguments:
# sender_address: Address of the client to send the FIN packet to.
# This method sends a FIN packet to the client to initiate the connection teardown process
# after all data has been received. It awaits a FIN-ACK packet from the client.
# Returns:
# None.            
    def receive_fin_packet(self, sender_address):         
        # Attempt to receive a packet from the socket
        try:
            packet, sender_address = self.sock.recvfrom(HEADER_SIZE)
            # Unpack the packet header to extract sequence number and flags
            _, _, flags = unpack_header(packet)



            # Check if the SYN flag is set in the received packet
            if flags & FIN_FLAG:
                print("FIN packet received")
                self.send_fin_ack(sender_address)  # Add this line to call the send_syn_ack method
        except Exception as e:
            print("Error receiving FIN packet:", e)
            print("closing connection")
            self.close_connection()
# Description: Sends FIN packet to the client to initiate connection teardown.
# Arguments:
# sender_address: Address of the client to send the FIN packet to.
# This method sends a FIN packet to the client to initiate the connection teardown process
# after all data has been received. It awaits a FIN-ACK packet from the client.
# Returns:
# None.            
    def send_fin_ack(self, sender_address):
        try:
            header = pack_header(0, 0, ACK_FLAG|FIN_FLAG)
            self.sock.sendto(header, sender_address)
            print("FIN ACK packet is sent")
            self.close_connection()
        except socket.error:
            print("Error: Couldn't send FIN ACK packet")
            self.close_connection()
        except Exception as e:
            print("Error:", e)
            self.close_connection()
# Description: Closes the server-side connection.
# Arguments:
# None.
# This method closes the UDP socket used for communication on the server side and exits the program.
# Returns:
# None.
    def close_connection(self):
        try:
            print("Connection Closed")
            self.sock.close()
            sys.exit(1)
        except socket.error:
            print("Error: Couldn't close socket")
            sys.exit(1)
        except Exception as e:
            print("Error:", e)
            sys.exit(1)
# Description: Parses command-line arguments.
# Arguments:
# None.
# This function parses the command-line arguments using the argparse module.
# It defines the available options such as server mode, client mode, server IP address,
# port number, file path, sliding window size, and a custom test case to skip a sequence number.
# After parsing the arguments, it returns the parsed arguments object.
# Returns:
# Parsed arguments object.
def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DRTP File Transfer Application")
    parser.add_argument('-s', '--server', action='store_true', help="Enable server mode")
    parser.add_argument('-c', '--client', action='store_true', help="Enable client mode")
    parser.add_argument('-i', '--ip', type=str, default='127.0.0.1', help="Server IP address (default: 127.0.0.1)")
    parser.add_argument('-p', '--port', type=int, default=8088, help="Port number (default: 8088)")
    parser.add_argument('-f', '--file', type=str, help="File path")
    parser.add_argument('-w', '--window', type=int, default=3, help="Sliding window size (default: 3)")
    parser.add_argument('-d', '--discard', type=int, help="Custom test case to skip a sequence number")
    return parser.parse_args()
# Description: Checks the server arguments and starts the server.
# Arguments:
# - args: Command-line arguments passed to the server.
# This function checks the server arguments for validity. It ensures that the server
# does not specify a file path, allows only the client to change the window size,
# validates the port number range, and verifies the IP address format. If all checks pass,
# it creates a server instance and starts the server to listen for incoming connections.
# Returns:
# None.
def check_server(args):
    """Check the server arguments."""
    if args.file:
        print("-s option cannot accept -f argument.")
        sys.exit(1)    
    if args.window != 3:
        print("Only client can change the window")
        sys.exit(1)
    if args.port and not 1024 <= args.port <= 65535:
        print("Error: Port number must be between 1024 and 65535.")
        sys.exit(1)
    if args.ip and not is_valid_ip(args.ip):
        print("Error: Invalid IP address format.")
        sys.exit(1)

    server = Server(args.ip, args.port, args.discard)
    server.start_server()
# Description: Checks the client arguments and initiates the file transfer process.
# Arguments:
# - args: Command-line arguments passed to the client.
# This function checks the client arguments for validity and initiates the file transfer process.
# It verifies that the file path is provided, the port number is within the valid range,
# the file extension is correct, and the IP address format is valid. It then creates a client
# instance and starts the file transfer process. It handles exceptions such as connection
# refusal.
# Returns:
# None.
def check_client(args):
    """Check the client arguments."""
    if args.discard:
        print("-c option cannot accept -d argument.")
        sys.exit(1)
    if not args.file:
        print("Error: File path is required in client mode.")
        sys.exit(1)
    if args.port and not 1024 <= args.port <= 65535:
        print("Error: Port number must be between 1024 and 65535.")
        sys.exit(1)
    if args.file:
        _, file_extension = os.path.splitext(args.file)
        if file_extension.lower() not in ('.jpg', '.jpeg'):
            print("Error: File must have a '.jpg' or '.jpeg' extension.")
            sys.exit(1)
    if args.ip and not is_valid_ip(args.ip):
        print("Error: Invalid IP address format.")
        sys.exit(1)

    sender = Client(args.ip, args.port, args.file, args.window)
    try:
        sender.send_file()
    except ConnectionRefusedError:
        print("Error: Connection refused. Server is not available at {}:{}".format(args.ip, args.port))
        sys.exit(1)
# Description: Checks if the IP address and port are in the correct format.
# Arguments:
# - ip: IP address of the server.
# - port: Port number of the server.
# - Use of other input and output parameters in the function.
# This function verifies that the provided IP address is in dotted decimal notation
# and that the port number falls within the valid range (1024 to 65535).
# Returns: 
# True if the IP address is in the correct format and the port number is within the valid range,
# False otherwise.
def is_valid_ip(ip):
    """Check if the IP address is in dotted decimal notation."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False
# Description: Main entry point of the program.
# Arguments:
# None.
# This function serves as the main entry point of the program. It parses the command-line arguments,
# determines whether to run the program in server or client mode based on the provided arguments,
# and calls the respective functions to check and initiate the server or client process.
# If neither server nor client mode is specified, it prints an error message and exits the program.
# Returns:
# None.    
def main():
    """Main function."""
    args = parse_arguments()

    if args.server:
        check_server(args)
    elif args.client:
        check_client(args)
    else:
        print("Error: Please specify either server (-s) or client (-c) mode.")
        sys.exit(1)


if __name__ == "__main__":
    main()
