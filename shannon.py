""" 
   Shannon: Shannon stream cipher and MAC -- reference implementation, ported from C code written by Greg Rose
   https://github.com/sashahilton00/spotify-connect-resources/blob/master/Shannon-1.0/ShannonRef.c
 
   Copyright 2017, Dmitry Borisov

   THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE AND AGAINST
   INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
 
import struct, \
       copy

# Constants  
N=         16
INITKONST= 0x6996c53a
KEYP=      13           # where to insert key/MAC/counter words
FOLD=      N            # how many iterations of folding to do

class Shannon:
  @staticmethod
  def ROTL( w, x ):
    return  (( w << x ) | ( w >> (32-x) ) ) & 0xFFFFFFFF
    
  @staticmethod
  def ROTR( w, x ):
    return  (( w >> x ) | ( w << (32-x) ) ) & 0xFFFFFFFF

  """ Nonlinear transform (sbox) of a word.
    There are two slightly different combinations. """
  @staticmethod
  def sbox1( w ):
    w ^= Shannon.ROTL( w, 5 ) | Shannon.ROTL( w, 7 ) 
    w ^= Shannon.ROTL( w, 19 ) | Shannon.ROTL( w, 22 )
    return w
    
  """ Nonlinear transform (sbox) of a word.
    There are two slightly different combinations. """
  @staticmethod
  def sbox2( w ):
    w ^= Shannon.ROTL( w, 7 ) | Shannon.ROTL( w, 22 )
    w ^= Shannon.ROTL( w, 5 ) | Shannon.ROTL( w, 19 )
    return w
  
  """ initialise to known state """
  def _initstate(self):
    global N,         \
           INITKONST
           
    # Generate fibonacci numbers up to N
    self._R= [ 1, 1 ]
    for x in range( 1, N- 1 ):
      self._R.append( self._R[ x ]+ self._R[ x-1 ] ) 
    
    self._konst= INITKONST

  """ cycle the contents of the register and calculate output word in _sbuf.  """
  def _cycle( self ):
    # nonlinear feedback function
    t = self._R[12] ^ self._R[13] ^ self._konst
    t = Shannon.sbox1(t) ^ Shannon.ROTL(self._R[0], 1)
    
    # Shift to the left
    self._R= self._R[ 1: ]+ [ t ]
    t = Shannon.sbox2( self._R[2] ^ self._R[15] )
    self._R[0] ^= t
    self._sbuf = t ^ self._R[8] ^ self._R[12]
  
  """ The Shannon MAC function is modelled after the concepts of Phelix and SHA.
      Basically, words to be accumulated in the MAC are incorporated in two
      different ways:
      1. They are incorporated into the stream cipher register at a place
         where they will immediately have a nonlinear effect on the state
      2. They are incorporated into bit-parallel CRC-16 registers; the
         contents of these registers will be used in MAC finalization. """

  
  """ Accumulate a CRC of input words, later to be fed into MAC.
      This is actually 32 parallel CRC-16s, using the IBM CRC-16
     polynomial x^16 + x^15 + x^2 + 1. """
  def _crcfunc( self, i ): 
    t = self._CRC[0] ^ self._CRC[2] ^ self._CRC[15] ^ i
    # Accumulate CRC of input 
    self._CRC= self._CRC[ 1: ]+ [ t ]

  """ Normal MAC word processing: do both stream register and CRC. """
  def _macfunc(self, i):
    global KEYP

    self._crcfunc( i )
    self._R[ KEYP ] ^= i

  """ extra nonlinear diffusion of register for key and MAC """
  def _diffuse(self):
    global FOLD

    for i in range( FOLD ):
      self._cycle()
  
  """ Common actions for loading key material
      Allow non-word-multiple key and nonce material.
      Note also initializes the CRC register as a side effect. """
  def _loadkey(self, key ):
    global KEYP,   \
           N
    
    # Pad key with 00s to align on 4 bytes and add key_len
    padding_size= int( ( len( key )+ 3 )/ 4 )* 4- len( key )
    key= key+ ( b'\x00' * padding_size ) + struct.pack( "<I", len( key ) )
    for i in range( 0, len( key ), 4 ):
      self._R[ KEYP ]= self._R[ KEYP ] ^ struct.unpack( "<I", key[ i: i+ 4 ] )[ 0 ]  # Little Endian order
      self._cycle()
    
    # save a copy of the register
    self._CRC= copy.copy( self._R )

    # now diffuse 
    self._diffuse();

    # now xor the copy back -- makes key loading irreversible */
    for i in range( N ):
      self._R[ i ] ^= self._CRC[ i ]

  """ Constructor """
  def __init__( self, key ):
    self._initstate()
    self._loadkey(key)
    self._konst= self._R[ 0 ]     # in case we proceed to stream generation 
    self._initR= copy.copy( self._R )
    self._nbuf = 0
    
  """ Published "IV" interface """
  def set_nonce(self, nonce ):
    global INITKONST
    
    if type( nonce )== int:
      # Accept int as well
      nonce= bytes( struct.pack( "<I", nonce ))
      
    self._R= copy.copy( self._initR )
    self._konst = INITKONST
    self._loadkey( nonce )
    self._konst = self._R[0] 
    self._nbuf = 0 
    self._mbuf = 0
 
  """ Encrypt small chunk """
  def _encrypt_chunk( self, chunk ):
    result= []
    for c in chunk:
      self._mbuf ^= c << ( 32- self._nbuf ) 
      result.append( c ^ (self._sbuf >> (32 - self._nbuf)) & 0xFF )
      self._nbuf-= 8
    
    return result
    
  """ Combined MAC and encryption.
      Note that plaintext is accumulated for MAC. """
  def encrypt( self, buf ):
    # handle any previously buffered bytes 
    result= []
    if self._nbuf != 0:
      head= buf[ : ( self._nbuf >> 3 ) ]
      buf=  buf[ ( self._nbuf >> 3 ): ]
      result= self._encrypt_chunk( head )
      if self._nbuf != 0:
        return bytes( result )
          
      # LFSR already cycled
      self._macfunc( self._mbuf )

    # Handle body
    i= 0
    while len( buf )>= 4:
      self._cycle();
      t = struct.unpack( "<I", buf[ i: i+ 4 ] )[ 0 ]
      self._macfunc( t );
      t ^= self._sbuf
      result+= struct.pack( "<I", t )
      buf= buf[ 4: ]

    # handle any trailing bytes
    if len( buf ):
      self._cycle()
      self._mbuf = 0
      self._nbuf = 32
      result+= self._encrypt_chunk( buf )
        
    return bytes( result )

  """ Decrypt small chunk """
  def _decrypt_chunk( self, chunk ):
    result= []
    for c in chunk:
      result.append( c ^ (self._sbuf >> (32 - self._nbuf)) & 0xFF )
      self._mbuf ^= result[ -1 ] << ( 32- self._nbuf ) 
      self._nbuf-= 8
    
    return result

  """ Combined MAC and decryption.
      Note that plaintext is accumulated for MAC. """
  def decrypt( self, buf ):
    # handle any previously buffered bytes 
    result= []
    if self._nbuf != 0:
      head= buf[ : ( self._nbuf >> 3 ) ]
      buf=  buf[ ( self._nbuf >> 3 ): ]
      result= self._decrypt_chunk( head )
      if self._nbuf != 0:
        return bytes( result )
          
      # LFSR already cycled
      self._macfunc( self._mbuf )
        
    # Handle whole words
    i= 0
    while len( buf )>= 4:
      self._cycle()
      t = struct.unpack( "<I", buf[ i: i+ 4 ] )[ 0 ] ^ self._sbuf
      self._macfunc( t )
      result+= struct.pack( "<I", t )
      buf= buf[ 4: ]

    # handle any trailing bytes 
    if len( buf ):
      self._cycle()
      self._mbuf = 0
      self._nbuf = 32
      result+= self._decrypt_chunk( buf )

    return bytes( result )

  """ Having accumulated a MAC, finish processing and return it.
      Note that any unprocessed bytes are treated as if
      they were encrypted zero bytes, so plaintext (zero) is accumulated. """
  def finish( self, buf_len ):
    global KEYP,       \
           INITKONST
           
    # handle any previously buffered bytes
    if self._nbuf != 0:
      # LFSR already cycled 
      self._macfunc(self._mbuf)
    
    #    perturb the MAC to mark end of input.
    #    Note that only the stream register is updated, not the CRC. This is an
    #    action that can't be duplicated by passing in plaintext, hence
    #    defeating any kind of extension attack.
    self._cycle()
    self._R[ KEYP ] ^= INITKONST ^ (self._nbuf << 3)
    self._nbuf = 0

    # now add the CRC to the stream register and diffuse it
    for i in range( N ):
      self._R[i] ^= self._CRC[i]
      
    self._diffuse()

    result= []
    # produce output from the stream buffer 
    i= 0
    for i in range( 0, buf_len, 4 ):
      self._cycle()
      if i+ 4 <= buf_len:
        result+= struct.pack( "<I", self._sbuf )
      else:
        sbuf= self._sbuf
        for j in range( i, buf_len ):
          result.append( sbuf & 0xFF )
          sbuf>>= 8

    return bytes( result )

if __name__ == '__main__':
  TESTSIZE= 20
  TEST_KEY= b"test key 128bits"
  TEST_PHRASE= b'\x00' * 20
  
  sh= Shannon( TEST_KEY )
  sh.set_nonce( 0 )
  encr= [ sh.encrypt( bytes( [ x ] ) ) for x in TEST_PHRASE ]
  print( 'Encrypted 1-by-1 (len %d)' % len( encr ), [ hex( x[ 0 ] ) for x in encr ] )
  print( '  sbuf %08x' %  sh._sbuf )
  print( '  MAC', [ hex( x ) for x in sh.finish( TESTSIZE ) ] )

  sh.set_nonce( 0 )
  encr= sh.encrypt( TEST_PHRASE )
  print( 'Encrypted whole (len %d)' % len( encr ), [ hex( x )for x in encr ] )
  print( '  sbuf %08x' %  sh._sbuf )
  print( '  MAC', [ hex( x ) for x in sh.finish( TESTSIZE ) ] )

  sh.set_nonce( 0 )
  print( 'Decrypted whole', [ hex( x ) for x in sh.decrypt( encr ) ] )
  print( '  MAC', [ hex( x ) for x in sh.finish( TESTSIZE ) ] )
  
  sh.set_nonce( 0 )
  decr= [ sh.decrypt( bytes( [ x ] )) for x in encr ]
  print( 'Decrypted 1-by-1', [ hex( x[ 0 ] ) for x in decr ] )
  print( '  MAC', [ hex( x ) for x in sh.finish( TESTSIZE ) ] )
  
  
  