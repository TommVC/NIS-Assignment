NOTE: Both Alice.py and Bob.py are essentially copies of each other, Alice.py has been documented to explain what the components of our code are doing.

HOW TO RUN THE SYSTEM:
1. To ensure all packages are installed please run the following:
    pip install -Ur requirements.txt
2. Once these are installed run CA.py in a terminal window as follows:
    python CA.py
    or 
    python3 CA.py if the first did not work
3. In two separate terminal windows run Alice and Bob:
    python Alice.py
    python Bob.py
4. Once all the necessary setup is finished it will prompt both Alice and Bob to enter the file name of the image they want to send
    4.1 Choose either Alice or Bob to be a sender and the other to be a reciever (Note they can both consecutively send and receive continuously, but only one send and receive is necessary to represent the workings of the system)
    4.2 We have a testing image mesh.png that can be used, alternatively add your own image to the file directory to test with
    4.3 Type mesh.png into the sender's terminal and then whatever caption you would like to send
    4.4 The image should appear in the output file
    4.5 Type Q into both Alice and Bob's terminals to end the connection
5. The testing files under the testing folders will now have written all the session testing data, you can view these to see evidence of testing.
