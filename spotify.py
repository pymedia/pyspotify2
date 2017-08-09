
import os,         \
       sys,        \
       subprocess, \
       socket,     \
       struct,     \
       inspect,    \
       random,     \
       hmac,       \
       hashlib,    \
       enum
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
except:
  raise Exception( "PROTO stubs were not found or have been corrupted. Please regenerate from .proto files using process_proto.py" ) 

KEY_LENGTH=               96
SPOTIFY_AP_ADDRESS=       ( 'guc3-accesspoint-b-cz1w.ap.spotify.com', 80 )
SPOTIFY_API_VERSION=      105900395  # Value taken from Windows client
INFORMATION_STRING=       "pyspotify2"
DEVICE_ID=                "UNKNOWN"
VERSION_STRING=           "0.1"
LOGIN_REQUEST_COMMAND=    0xAB
MAC_SIZE=                 4

class CONNECT_TYPE(enum.Enum):
  CONNECT_TYPE_HANDSHAKE= 1
  CONNECT_TYPE_STREAM=    2

# -------------------------------------------------------------------------------      
def print_hello_request( hello ):
  print( 'build_info', hello.build_info )
  print( 'fingerprints_supported', hello.fingerprints_supported )
  print( 'cryptosuites_supported', hello.cryptosuites_supported )
  print( 'powschemes_supported', hello.powschemes_supported )
  print( 'login_crypto_hello', len( hello.login_crypto_hello.diffie_hellman.gc ), '\n',  hello.login_crypto_hello )
  print( 'client_nonce', len( hello.client_nonce ), '\n', hello.client_nonce )
  print( 'padding', len( hello.padding ), '\n', hello.padding )
  print( 'feature_set', hello.feature_set )

def print_hello_response( ap_resp ):
  print( 'remote_key gs', ap_resp.challenge.login_crypto_challenge.diffie_hellman.gs )

# ----------------------------------- Plain Connection to server ----------------------------------
class Connection:
  def __init__( self ):
    self._socket = socket.socket(socket.AF_INET, 
                                socket.SOCK_STREAM)
    self._socket.connect( SPOTIFY_AP_ADDRESS )
    self._connect_type= CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE
  
  def send_packet( self, 
                   prefix, 
                   data ):
    if prefix== None:
      prefix= b""
    
    if self._connect_type== CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE:
      size=    len( prefix )+ 4+ len( data )
      request= prefix+ struct.pack(">I", size )+ data
    else:
      self._encoder.set_nonce( self._encoder_nonce )
      request= bytes( [ prefix ] )+ struct.pack(">H", len( data ) )+ data
      request= self._encoder.encrypt( request )
      request+= self._encoder.finish( MAC_SIZE )
      self._encoder_nonce+= 1

    self._socket.send( request )
    return request

  def recv_packet( self ):
    if self._connect_type== CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE:
      size_packet= self._socket.recv( 4 )
      size= struct.unpack( ">I",  size_packet )
      return '', size[ 0 ], self._socket.recv( size[ 0 ] )
    else:
      self._decoder.set_nonce( self._decoder_nonce )
      self._decoder_nonce+= 1
      resp_header= self._decoder.decrypt( self._socket.recv( 3 ) )
      size= struct.unpack( ">H", resp_header[ 1: ] )[ 0 ]
      resp_body= self._decoder.decrypt( self._socket.recv( size ) )
      return resp_header[ 0 ], size, resp_body

  def handshake_completed( self, send_key, recv_key ):
    self._connect_type= CONNECT_TYPE.CONNECT_TYPE_STREAM
    
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

    request = keyexchange.ClientHello( **{ 'build_info':             keyexchange.BuildInfo( **{ 'product':  keyexchange.PRODUCT_LIBSPOTIFY_EMBEDDED, 
                                                                                                'platform': keyexchange.PLATFORM_LINUX_X86, 
                                                                                                'version':  SPOTIFY_API_VERSION } ),
                                           'fingerprints_supported': [ keyexchange.FINGERPRINT_GRAIN ],
                                           'cryptosuites_supported': [ keyexchange.CRYPTO_SUITE_SHANNON ],
                                           'powschemes_supported':   [ keyexchange.POW_HASH_CASH ],
                                           'login_crypto_hello':     keyexchange.LoginCryptoHelloUnion( **{ 'diffie_hellman': diffiehellman_hello } ),
                                           'client_nonce' :          bytes( [ int( random.random()* 0xFF ) for x in range( 0, 0x10 ) ] ),
                                           'padding':                bytes( [ 0 for x in range( 0, 0x1E ) ] ),
                                           'feature_set':            keyexchange.FeatureSet( **{ 'autoupdate2': True } ) } )
                                           
    return self._connection.send_packet( b"\x00\x04", 
                                        request.SerializeToString()  )
  
  def _processAPHelloResponse( self, init_client_packet ):
    prefix, size, init_server_packet= self._connection.recv_packet()
    response= keyexchange.APResponseMessage()
    response.ParseFromString( init_server_packet )
    #print_hello_response(response)
    remote_key= response.challenge.login_crypto_challenge.diffie_hellman.gs
    self._local_keys.generate_shared_secret(int.from_bytes(remote_key, 
                                                           byteorder='big'));
    mac_original= hmac.new( self._local_keys.shared_secret.to_bytes( KEY_LENGTH,
                                                                     byteorder='big' ), 
                            digestmod= hashlib.sha1 )
    data= []                         
    for i in range( 1, 6 ):
      mac= mac_original.copy()
      mac.update( bytes(init_client_packet) + bytes( init_server_packet)+ bytes([i]) )
      data+= mac.digest()
      
    mac= hmac.new( bytes( data[ :0x14 ] ), 
                   digestmod= hashlib.sha1 )
    mac.update( bytes(init_client_packet) )
    mac.update( bytes(init_server_packet) )
    
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
    print( 'AUTH request', packet, ' len ', len( packet ) )
    print( 'Resp 0x%x' % command, 'Size %d' % size )
    print( 'Body', [ hex( x ) for x in body ] )
    
  def __init__( self ):
    # Generate local keys`
    self._local_keys= diffiehellman.DiffieHellman(group=1, key_length=KEY_LENGTH)
    self._local_keys.generate_private_key()
    self._local_keys.generate_public_key()
    
if __name__ == '__main__':
  if len( sys.argv )!= 3:
    print( 'Usage: spotify.py <username> <password>' )
  else:
    connection = Connection()
    session= Session()
    session.connect( connection )
    session.authenticate( sys.argv[ 1 ], 
                          bytes( sys.argv[ 2 ], 'ascii' ), 
                          authentication.AUTHENTICATION_USER_PASS )

