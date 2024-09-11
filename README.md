# Reliable Transport Protocol (DRTP)

**Candidate Number:** s374220  
**Course Code:** DATA2410  
**Course Name:** Datanettverk og skytjenester  
**Study Program:** Bachelor i Dataingeniørfag  
**Submission Deadline:** 21.05.2024

**Grade:** A

![Python-Logo](https://learnersgalaxy.ai/wp-content/uploads/2024/01/Python-Symbol.png)

## Overview

The Reliable Transport Protocol (DRTP) is a file transfer application that ensures reliable data transmission over UDP. This project was developed as part of the Exam for DATA2410 class, focusing on data networks and cloud services.

The DRTP application includes client and server components, which work together to reliably transfer files. The design and functionality were guided by theoretical concepts covered in lectures and tested using Mininet, a network emulator.

### Key Features

- **UDP Socket Communication:** Utilizes UDP sockets to handle file transfers.
- **Sliding Window Mechanism:** Implements a sliding window protocol to manage data flow and ensure reliability.
- **Three-Way Handshake:** Establishes a connection between the client and server using a three-way handshake.
- **Connection Teardown:** Properly closes the connection after file transfer is complete.
- **Go-Back-N Protocol:** Ensures reliability through retransmission of lost packets and acknowledgement of received packets.

## Implementation Details

For detailed implementation information, including code and technical descriptions, please refer to the provided PDF document titled `s374220.pdf`. The PDF comprehensively explains the code structure, tests, methods used, and the overall protocol design.

## Getting Started

To use the DRTP application, follow these steps:

Server:
python application.py -s -i <ip> -p <port> -d <discard_sequence_number>

Client:
python application.py -c -i <ip> -p <port> -f <file_path> -w <window_size>

They must be on the same IP and port

How to test Application.py:
- **Install Ubuntu inside Oracle VM VirtualBox**
- **Install Mininet, Xterm, and Ubuntu Utils**
- **Add a shared folder between Host OS and Ubuntu OS where you have your py file**
- **Run this folder in Ubuntu using sudo mn(--custom for custom topo file)**
- **Use Xterm to test separate nodes on how they react to your application(in this instance client h1 server h2)**
- **Done**

For further instructions and usage details, consult the PDF document.

## Contact
For questions or feedback, please contact me on LinkedIn: [https://www.linkedin.com/in/younes-benhaida-44495827b/]

Note: The PDF document provides in-depth technical details of the DRTP implementation and should be referred to for a complete understanding of the protocol and code.
