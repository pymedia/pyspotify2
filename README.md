# pyspotify2
Unofficial spotify connect.  
Python port from: https://github.com/plietar/librespot  
pyspotify2 is very limited port. Only supports spotify track playback function. 
Made for testing purpose only, to check the best way to interact with Spotify. If you want to expand the functionality, feels free to join the effort.
Have fun !

## How to run
1. You will need python35 at least

2. Download and install DiffieHellman:  
   git clone http://www.github.com/chrisvoncsefalvay/diffiehellman  
   cd diffiehellman  
   python3 setup.py install  
   cd ..  
   git clone https://github.com/ricmoo/pyaes/  
   cd pyaes  
   python3 setup.py install  
   cd ..  
   git clone https://github.com/google/protobuf  
   <Follow protobuf/python/README.md>  

   * you may substitute pyaes with https://github.com/dlitz/pycrypto
   
3. Run python3 spotify.py **username** **password** **track_id**
