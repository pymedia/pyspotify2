
import os,         \
       sys,        \
       subprocess, \
       socket,     \
       struct,     \
       inspect,    \
       random,     \
       hmac,       \
       hashlib,    \
       enum,       \
       threading,  \
       time
import diffiehellman.diffiehellman as diffiehellman
import shannon

# patch DH with non RFC prime to be used for handshake
if not 1 in diffiehellman.PRIMES:
  diffiehellman.PRIMES.update( { 1: { 
      "prime": 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff,
      "generator": 2
  } } )

try:
  import protocol.impl.keyexchange_pb2 as keyexchange
  import protocol.impl.authentication_pb2 as authentication
  import protocol.impl.mercury_pb2 as mercury
  import protocol.impl.metadata_pb2 as metadata
except:
  raise Exception( "PROTO stubs were not found or have been corrupted. Please regenerate from .proto files using process_proto.py" ) 

KEY_LENGTH=               96
SPOTIFY_AP_ADDRESS=       ( 'guc3-accesspoint-b-cz1w.ap.spotify.com', 80 )
SPOTIFY_API_VERSION=      0x10800000000
INFORMATION_STRING=       "pyspotify2"
DEVICE_ID=                "984816fd329622876e14907634264e6f332e9fb3"
VERSION_STRING=           "pyspotify2-0.1"

LOGIN_REQUEST_COMMAND=    0xAB
AUTH_SUCCESSFUL_COMMAND=  0xAC
AUTH_DECLINED_COMMAND=    0xAD
MAC_SIZE=                 4
HEADER_SIZE=              3

TRACK_PATH_TEMPLATE=      'hm://metadata/3/track/%s'

# ----------------------------------- Plain Connection to server ----------------------------------
class Connection:
  class CONNECT_TYPE(enum.Enum):
    CONNECT_TYPE_HANDSHAKE= 1
    CONNECT_TYPE_STREAM=    2

  def __init__( self ):
    self._socket = socket.socket(socket.AF_INET, 
                                socket.SOCK_STREAM)
    self._socket.connect( SPOTIFY_AP_ADDRESS )
    self._connect_type= Connection.CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE
    
  def send_packet( self, 
                   prefix, 
                   data ):
    if prefix== None:
      prefix= b""
    
    if self._connect_type== Connection.CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE:
      size=    len( prefix )+ 4+ len( data )
      request= prefix+ struct.pack(">I", size )+ data
    else:
      self._encoder.set_nonce( self._encoder_nonce )
      self._encoder_nonce+= 1

      request= bytes( [ prefix ] )+ struct.pack(">H", len( data ) )+ data
      request= self._encoder.encrypt( request )
      request+= self._encoder.finish( MAC_SIZE )

    self._socket.send( request )
    return request

  def recv_packet( self, timeout= 0 ):
    if timeout:
      self._socket.setblocking( 0 )
      self._socket.settimeout( timeout )
    else:
      self._socket.setblocking( 1 )
      
    if self._connect_type== Connection.CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE:
      size_packet= self._socket.recv( 4 )
      size= struct.unpack( ">I",  size_packet )
      return '', size[ 0 ], size_packet+ self._socket.recv( size[ 0 ]- 4 )
    else:
      self._decoder.set_nonce( self._decoder_nonce )
      self._decoder_nonce+= 1

      recv_header= self._socket.recv( HEADER_SIZE )
      header= self._decoder.decrypt( recv_header )
      size= struct.unpack( ">H", header[ 1: ] )[ 0 ]
      recv_body= self._socket.recv( size )
      mac= self._socket.recv( MAC_SIZE )
      body= self._decoder.decrypt( recv_body )
      calculated_mac= self._decoder.finish( MAC_SIZE )
      if calculated_mac!= mac:
        raise Exception( 'RECV MAC not matching', calculated_mac, mac )
        
      return header[ 0 ], size, body

  def handshake_completed( self, send_key, recv_key ):
    self._connect_type= Connection.CONNECT_TYPE.CONNECT_TYPE_STREAM
    
    # Generate shannon streams
    self._encoder_nonce= 0
    self._encoder= shannon.Shannon( send_key )
    
    self._decoder_nonce= 0
    self._decoder= shannon.Shannon( recv_key )
    

# ----------------------------------- Session connection ----------------------------------
class Session:
  def _sendClientHelloRequest( self ):
    diffiehellman_hello= keyexchange.LoginCryptoDiffieHellmanHello( **{ 'gc':                self._local_keys.public_key.to_bytes( KEY_LENGTH, byteorder='big' ), \
                                                                        'server_keys_known': 1 } )                                            

    request = keyexchange.ClientHello( **{ 'build_info':             keyexchange.BuildInfo( **{ 'product':  keyexchange.PRODUCT_PARTNER, 
                                                                                                'platform': keyexchange.PLATFORM_LINUX_X86, 
                                                                                                'version':  SPOTIFY_API_VERSION } ),
                                           'cryptosuites_supported': [ keyexchange.CRYPTO_SUITE_SHANNON ],
                                           'login_crypto_hello':     keyexchange.LoginCryptoHelloUnion( **{ 'diffie_hellman': diffiehellman_hello } ),
                                           'client_nonce' :          bytes( [ int( random.random()* 0xFF ) for x in range( 0, 0x10 ) ] ),
                                           'padding':                bytes( [ 0x1E ] ),
                                           'feature_set':            keyexchange.FeatureSet( **{ 'autoupdate2': True } ) } )
    return self._connection.send_packet( b"\x00\x04", 
                                         request.SerializeToString()  )
  
  def _processAPHelloResponse( self, init_client_packet ):
    prefix, size, init_server_packet= self._connection.recv_packet()
    response= keyexchange.APResponseMessage()
    response.ParseFromString( init_server_packet[ 4: ] )
    remote_key= response.challenge.login_crypto_challenge.diffie_hellman.gs
    self._local_keys.generate_shared_secret(int.from_bytes(remote_key, 
                                                           byteorder='big'));
    mac_original= hmac.new( self._local_keys.shared_secret.to_bytes( KEY_LENGTH,
                                                                     byteorder='big' ), 
                            digestmod= hashlib.sha1 )
    data= []                         
    for i in range( 1, 6 ):
      mac= mac_original.copy()
      mac.update( init_client_packet+ init_server_packet+ bytes([i]) )
      data+= mac.digest()
      
    mac= hmac.new( bytes( data[ :0x14 ] ), 
                   digestmod= hashlib.sha1 )
    mac.update( init_client_packet+ init_server_packet )
    
    return ( mac.digest(),
             bytes( data[ 0x14 : 0x34 ] ),
             bytes( data[ 0x34 : 0x54 ] ) )

  """ Send handsheke challenge """
  def _sendClientHandshakeChallenge( self, 
                                     challenge ):
    diffie_hellman= keyexchange.LoginCryptoDiffieHellmanResponse( **{ 'hmac': challenge } )
    crypto_response= keyexchange.LoginCryptoResponseUnion( **{ 'diffie_hellman':  diffie_hellman } )
    packet = keyexchange.ClientResponsePlaintext( **{ 'login_crypto_response':  crypto_response,
                                                      'pow_response': {},
                                                      'crypto_response': {} } )
    self._connection.send_packet( prefix= None, 
                                  data=   packet.SerializeToString()  )
             
  def connect( self, connection ):
    self._connection= connection 
    init_client_packet= self._sendClientHelloRequest()
    challenge, send_key, recv_key= self._processAPHelloResponse( init_client_packet )
    self._sendClientHandshakeChallenge( challenge )
    self._connection.handshake_completed( send_key, 
                                          recv_key )
    return self                                   
  
  def authenticate( self, username, auth_data, auth_type ):
    auth_request = authentication.ClientResponseEncrypted( **{ 'login_credentials': authentication.LoginCredentials( **{ 'username':      username, 
                                                                                                                         'typ':           auth_type, 
                                                                                                                         'auth_data':     auth_data } ),
                                                               'system_info': authentication.SystemInfo( **{ 'cpu_family':                authentication.CPU_UNKNOWN, 
                                                                                                             'os':                        authentication.OS_UNKNOWN, 
                                                                                                             'system_information_string': INFORMATION_STRING, 
                                                                                                             'device_id':                 DEVICE_ID } ),
                                                               'version_string': VERSION_STRING  } )
    packet= self._connection.send_packet( LOGIN_REQUEST_COMMAND, 
                                          auth_request.SerializeToString() )
    # Get response
    command, size, body= self._connection.recv_packet()
    if command== AUTH_SUCCESSFUL_COMMAND:
      auth_welcome= authentication.APWelcome()
      auth_welcome.ParseFromString( body )
      return auth_welcome.reusable_auth_credentials
    elif command== AUTH_DECLINED_COMMAND:
      raise Exception( 'AUTH DECLINED. Code: %02X' % command )
    
    raise Exception( 'UNKNOWN AUTH CODE %02X' % command )
    
  def __init__( self ):
    # Generate local keys`
    self._local_keys= diffiehellman.DiffieHellman(group=1, key_length=KEY_LENGTH)
    self._local_keys.generate_private_key()
    self._local_keys.generate_public_key()

# ----------------------------------- Mercury related classes ----------------------------------
class MercuryManager( threading.Thread ):
  
  class REQUEST_TYPE(enum.Enum):
    SEND=      1
    GET =      2
    
    def __str__(self):
      return self.name
      
    def as_command( self ):
      if self.name== 'SEND' or \
         self.name== 'GET':
        return 0xb2

  def __init__( self, connection ):
    super(MercuryManager, self).__init__()
    self._connection= connection
    self._sequence= 0x0000000000000000
    self._callbacks= {}
    self._terminated= False
    self.start()
    
  def set_callback( self, response_code, func ):
    self._callbacks[ response_code ]= func
  
  def is_terminated( self ):
    return self._terminated
    
  def terminate( self ):
    self._terminated= True
    
  def run( self ):
    while not self._terminated:
      try:
        response_code, size, payload= connection.recv_packet( 0.1 )
        print( 'Received:', hex( response_code ), ' len ', size )
      except socket.timeout:
        pass
      
  def execute( self, request_type, uri, callback ):
    header= mercury.Header( **{ 'uri':    uri,
                                'method': str( request_type ) } )
    buffer= b'\x00\x08'+   \
            self._sequence.to_bytes( 8, byteorder='big' )+  \
            b'\x01'+       \
            b'\x00\x01'+   \
            struct.pack(">H", len( header.SerializeToString() ) )+ \
            header.SerializeToString()
    self._sequence+= 1
    #buffer= bytes( [0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 35, 10, 28, 104, 109, 58, 47, 47, 114, 101, 109, 111, 116, 101, 47, 51, 47, 117, 115, 101, 114, 47, 120, 101, 104, 105, 121, 111, 117, 120, 47, 26, 3, 83, 85, 66] )
    print( 'Req sent', hex( request_type.as_command() ), [ hex(x) for x in buffer ] )
    response_code, callback_func= callback
    self.set_callback( response_code, callback_func )
    self._connection.send_packet( request_type.as_command(), buffer )   
    print( header )
    
# ----------------------------------- Track metadata and stream ----------------------------------
class Track:
  TRACK_INFO_REQUEST_COMMAND= 0x22
  TRACK_INFO_RESPONSE_COMMAND= 0xFF
  
  def __init__( self, mercury_manager, uri ):
    self._mercury_manager= mercury_manager
    self._uri= uri
    self._track= metadata.Track()
    self._event= threading.Event()
    
  def _process_track_info( self, response_code, payload ):
    print( 'Response code:', hex( payload ), ' length:', track_data[ 1 ] )
    self._track.ParseFromString( payload )
    self._event.set()
    
  def load( self ):
    self._mercury_manager.execute( MercuryManager.REQUEST_TYPE.GET, 
                                   TRACK_PATH_TEMPLATE % self._uri,
                                   ( Track.TRACK_INFO_RESPONSE_COMMAND, self._process_track_info ) )
    self._event.wait( 1 )                              

if __name__ == '__main__':

  if len( sys.argv )!= 4:
    print( 'Usage: spotify.py <username> <password> <track_uri>' )
  else:
    import signal
    manager= None
    
    def signal_handler(signal, frame):
      print( 'CTRL-C pressed' )
      if manager:
        manager.terminate()
    
    signal.signal(signal.SIGINT, signal_handler)

    connection = Connection()
    session= Session().connect( connection )
    reusable_token= session.authenticate( sys.argv[ 1 ], 
                                          bytes( sys.argv[ 2 ], 'ascii' ), 
                                          authentication.AUTHENTICATION_USER_PASS )
    print( 'AUTH successfull. Token: ', reusable_token )
    track= None
    manager= MercuryManager( connection )
    while not manager.is_terminated():
      time.sleep(1)
      if not track:
        track= Track( manager, sys.argv[ 3 ] )
        track.load()
      
    