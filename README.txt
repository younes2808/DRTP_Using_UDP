How to RUN Application.py:

Server:
python application.py -s -i <ip> -p <port> -d <discard_sequence_number>

Client:
python application.py -c -i <ip> -p <port> -f <file_path> -w <window_size>

They must be on same ip and port
How to test Application.py:
- Install Ubuntu inside Oracle VM VirtualBox
- Install Mininet, Xterm, and Ubuntu Utils
- Add a shared folder between Host OS and Ubuntu OS where you have your py file
- Run this folder in Ubuntu using sudo mn(--custom for custom topo file)
- Use Xterm to test separate nodes on how they react to your application(in this instance client h1 server h2)
- Done