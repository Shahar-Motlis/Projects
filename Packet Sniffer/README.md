#This is packet sniffer using python, that runs on the linux distribution - Ubuntu.
-----------------------------------------------------------------------------------
#Requirements:

--> Ubuntu OS.  You can download and run it on virtual environment, such as VirtualBox.

--> Do the following instructions for running the project...
    > Open VirtualBox.
    > Create a new virtual machine (Ubuntu).
    > Before you start the machine, go to 'Settings -> Network -> Adapter 1 -> Enable network adapter ->
      Attached to: Bridged Adapter'.
    > Start the machine.
    > Enter the command line.
    > For this program, we need to ensure that you have some python modules.  If not, we install them.
      *Run the following commands:
      > `sudo apt update -y && sudo apt upgrade -y`
      > `sudo apt install python3-pip`
      > `sudo pip3 install scapy`
      > `sudo pip3 install art`
      > `sudo pip3 install termcolor` 
      
    > Command for running the program -> `sudo python3 packet_sniffer.py` and then, just follow the program.
    > When the program has finished, you can easily see the log file that you created, with the command -> 
      `cat <insert the file name that chosen in the last section of the program>`.
       
