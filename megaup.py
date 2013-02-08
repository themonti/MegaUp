# -*- coding: utf-8 -*-

# MEGAUP beta.0.1

# Script basado en la información publicada en el blog:
# http://julien-marchand.fr/blog/using-the-mega-api-how-to-download-a-public-file-or-a-file-you-know-the-key-without-logging-in/
# y en el proyecto https://github.com/CyberjujuM/MegaFS

# Adptaciones e implementación como gestor de subida realizadas por TheMonti


from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from progressbar import  Bar, ETA, \
     FileTransferSpeed,  Percentage, \
    ProgressBar,  Timer

import base64
import binascii
import json
import os
import random
import struct
import sys
import urllib
import ConfigParser
import signal


sid = ''
seqno = random.randint(0, 0xFFFFFFFF)
 
master_key = ''
rsa_priv_key = ''

total = 0
 
def base64urldecode(data):
  data += '=='[(2 - len(data) * 3) % 4:]
  for search, replace in (('-', '+'), ('_', '/'), (',', '')):
    data = data.replace(search, replace)
  return base64.b64decode(data)
 
def base64urlencode(data):
  data = base64.b64encode(data)
  for search, replace in (('+', '-'), ('/', '_'), ('=', '')):
    data = data.replace(search, replace)
  return data
 
def a32_to_str(a):
  return struct.pack('>%dI' % len(a), *a)
 
def a32_to_base64(a):
  return base64urlencode(a32_to_str(a))
 
def str_to_a32(b):
  if len(b) % 4: # Add padding, we need a string with a length multiple of 4
    b += '\0' * (4 - len(b) % 4)
  return struct.unpack('>%dI' % (len(b) / 4), b)
 
def base64_to_a32(s):
  return str_to_a32(base64urldecode(s))
 
def aes_cbc_encrypt(data, key):
  encryptor = AES.new(key, AES.MODE_CBC, '\0' * 16)
  return encryptor.encrypt(data)
 
def aes_cbc_decrypt(data, key):
  decryptor = AES.new(key, AES.MODE_CBC, '\0' * 16)
  return decryptor.decrypt(data)
 
def aes_cbc_encrypt_a32(data, key):
  return str_to_a32(aes_cbc_encrypt(a32_to_str(data), a32_to_str(key)))
 
def aes_cbc_decrypt_a32(data, key):
  return str_to_a32(aes_cbc_decrypt(a32_to_str(data), a32_to_str(key)))
 
def stringhash(s, aeskey):
  s32 = str_to_a32(s)
  h32 = [0, 0, 0, 0]
  for i in xrange(len(s32)):
    h32[i % 4] ^= s32[i]
  for _ in xrange(0x4000):
    h32 = aes_cbc_encrypt_a32(h32, aeskey)
  return a32_to_base64((h32[0], h32[2]))
 
def prepare_key(a):
  pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]
  for _ in xrange(0x10000):
    for j in xrange(0, len(a), 4):
      key = [0, 0, 0, 0]
      for i in xrange(4):
        if i + j < len(a):
          key[i] = a[i + j]
      pkey = aes_cbc_encrypt_a32(pkey, key)
  return pkey
 
def encrypt_key(a, key):
  return sum((aes_cbc_encrypt_a32(a[i:i+4], key) for i in xrange(0, len(a), 4)), ())
 
def decrypt_key(a, key):
  return sum((aes_cbc_decrypt_a32(a[i:i+4], key) for i in xrange(0, len(a), 4)), ())
 
def mpi2int(s):
  return int(binascii.hexlify(s[2:]), 16)
 
def api_req(req):
  global seqno
  url = 'https://g.api.mega.co.nz/cs?id=%d%s' % (seqno, '&sid=%s' % sid if sid else '')
  seqno += 1
  return json.loads(post(url, json.dumps([req])))[0]
 
def post(url, data):
  return urllib.urlopen(url, data).read()
 
def login(email, password):
  global sid, master_key, rsa_priv_key
  password_aes = prepare_key(str_to_a32(password))
  uh = stringhash(email.lower(), password_aes)
  res = api_req({'a': 'us', 'user': email, 'uh': uh})
 
  enc_master_key = base64_to_a32(res['k'])
  master_key = decrypt_key(enc_master_key, password_aes)
  if 'tsid' in res:
    tsid = base64urldecode(res['tsid'])
    if a32_to_str(encrypt_key(str_to_a32(tsid[:16]), master_key)) == tsid[-16:]:
      sid = res['tsid']
  elif 'csid' in res:
    enc_rsa_priv_key = base64_to_a32(res['privk'])
    rsa_priv_key = decrypt_key(enc_rsa_priv_key, master_key)
 
    privk = a32_to_str(rsa_priv_key)
    rsa_priv_key = [0, 0, 0, 0]
 
    for i in xrange(4): 
      l = ((ord(privk[0]) * 256 + ord(privk[1]) + 7) / 8) + 2;
      rsa_priv_key[i] = mpi2int(privk[:l])
      privk = privk[l:]
 
    enc_sid = mpi2int(base64urldecode(res['csid']))
    decrypter = RSA.construct((rsa_priv_key[0] * rsa_priv_key[1], 0L, rsa_priv_key[2], rsa_priv_key[0], rsa_priv_key[1]))
    sid = '%x' % decrypter.key._decrypt(enc_sid)
    sid = binascii.unhexlify('0' + sid if len(sid) % 2 else sid)
    sid = base64urlencode(sid[:43])
 
def enc_attr(attr, key):
  attr = 'MEGA' + json.dumps(attr)
  if len(attr) % 16:
    attr += '\0' * (16 - len(attr) % 16)
  return aes_cbc_encrypt(attr, a32_to_str(key))
 
def dec_attr(attr, key):
  attr = aes_cbc_decrypt(attr, a32_to_str(key)).rstrip('\0')
  return json.loads(attr[4:]) if attr[:6] == 'MEGA{"' else False
 
def get_chunks(size):
  chunks = {}
  p = pp = 0
  i = 1
 
  while i <= 8 and p < size - i * 0x20000:
    chunks[p] = i * 0x20000;
    pp = p
    p += chunks[p]
    i += 1
 
  while p < size:
    chunks[p] = 0x100000;
    pp = p
    p += chunks[p]
 
  chunks[pp] = size - pp
  if not chunks[pp]:
    del chunks[pp]
 
  return chunks

def megaup_uploadfile(infile,ul_url,ul_key,encryptor,file_mac,chunklist,pbar):
  global total

  for chunk_start, chunk_size in chunklist:
    chunk = infile.read(chunk_size)

    chunk_mac = [ul_key[4], ul_key[5], ul_key[4], ul_key[5]]

    for i in xrange(0, len(chunk), 16):
      block = chunk[i:i+16]
      if len(block) % 16:
        block += '\0' * (16 - len(block) % 16)
      block = str_to_a32(block)
      # print 'BLOCK',block
      
      chunk_mac = [chunk_mac[0] ^ block[0], chunk_mac[1] ^ block[1], chunk_mac[2] ^ block[2], chunk_mac[3] ^ block[3]]
      chunk_mac = aes_cbc_encrypt_a32(chunk_mac, ul_key[:4])

    file_mac = [file_mac[0] ^ chunk_mac[0], file_mac[1] ^ chunk_mac[1], file_mac[2] ^ chunk_mac[2], file_mac[3] ^ chunk_mac[3]]
    file_mac = aes_cbc_encrypt_a32(file_mac, ul_key[:4])

    chunk = encryptor.encrypt(chunk)
    outfile = urllib.urlopen(ul_url + "/" + str(chunk_start), chunk)
    completion_handle = outfile.read()
    outfile.close()
    total+=chunk_size
    pbar.update(total)
  
  return completion_handle,file_mac

 
def uploadfile(filename):
  global total
  infile = open(filename, 'rb')
  size = os.path.getsize(filename)
  ul_url = api_req({'a': 'u', 's': size})['p']
 
  ul_key = [random.randint(0, 0xFFFFFFFF) for _ in xrange(6)]
  encryptor = AES.new(a32_to_str(ul_key[:4]), AES.MODE_CTR, counter = Counter.new(128, initial_value = ((ul_key[4] << 32) + ul_key[5]) << 64))
 
  file_mac = [0, 0, 0, 0]

  #Impresión de la descarga
  print "Subiendo %s [%s]" % (filename, megaup_GetHumanReadable(size))

  widgets = ['Estado: ', Percentage(), ' ', Bar(marker='#'),
               ' ', ETA(), ' ', FileTransferSpeed()]
  pbar = ProgressBar(widgets=widgets, maxval=size).start()
  #--------------------------------

  
  total=0
  chunklist=sorted(get_chunks(size).items())
  completion_handle,file_mac=megaup_uploadfile(infile,ul_url,ul_key,encryptor,file_mac,chunklist,pbar)   

  pbar.finish() 
  infile.close()
 
  meta_mac = (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])
 
  attributes = {'n': os.path.basename(filename)}
  enc_attributes = enc_attr(attributes, ul_key[:4])
  key = [ul_key[0] ^ ul_key[4], ul_key[1] ^ ul_key[5], ul_key[2] ^ meta_mac[0], ul_key[3] ^ meta_mac[1], ul_key[4], ul_key[5], meta_mac[0], meta_mac[1]]
  return api_req({'a': 'p', 't': root_id, 'n': [{'h': completion_handle, 't': 0, 'a': base64urlencode(enc_attributes), 'k': a32_to_base64(encrypt_key(key, master_key))}]})
 
def downloadfile(file, attributes, k, iv, meta_mac):
  dl_url = api_req({'a': 'g', 'g': 1, 'n': file['h']})['g']
 
  infile = urllib.urlopen(dl_url)
  outfile = open(attributes['n'], 'wb')
  decryptor = AES.new(a32_to_str(k), AES.MODE_CTR, counter = Counter.new(128, initial_value = ((iv[0] << 32) + iv[1]) << 64))
 
  file_mac = [0, 0, 0, 0]
  for chunk_start, chunk_size in sorted(get_chunks(file['s']).items()):
    chunk = infile.read(chunk_size)
    chunk = decryptor.decrypt(chunk)
    outfile.write(chunk)
 
    chunk_mac = [iv[0], iv[1], iv[0], iv[1]]
    for i in xrange(0, len(chunk), 16):
      block = chunk[i:i+16]
      if len(block) % 16:
        block += '\0' * (16 - (len(block) % 16))
      block = str_to_a32(block)
      chunk_mac = [chunk_mac[0] ^ block[0], chunk_mac[1] ^ block[1], chunk_mac[2] ^ block[2], chunk_mac[3] ^ block[3]]
      chunk_mac = aes_cbc_encrypt_a32(chunk_mac, k)
 
    file_mac = [file_mac[0] ^ chunk_mac[0], file_mac[1] ^ chunk_mac[1], file_mac[2] ^ chunk_mac[2], file_mac[3] ^ chunk_mac[3]]
    file_mac = aes_cbc_encrypt_a32(file_mac, k)
 
  outfile.close()
  infile.close()
 
  if (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]) != meta_mac:
    print "MAC mismatch"
 
def getfiles():
  global root_id, inbox_id, trashbin_id
 
  files = api_req({'a': 'f', 'c': 1})
  for file in files['f']:
    if file['t'] == 0 or file['t'] == 1:
      key = file['k'][file['k'].index(':') + 1:]
      key = decrypt_key(base64_to_a32(key), master_key)
      if file['t'] == 0:
        k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
        iv = key[4:6] + (0, 0)
        meta_mac = key[6:8]
      else:
        k = key
      attributes = base64urldecode(file['a'])
      attributes = dec_attr(attributes, k)
      # print attributes['n']
 
      if file['h'] == '0wFEFCTa':
        downloadfile(file, attributes, k, iv, meta_mac)
    elif file['t'] == 2:
      root_id = file['h']
    elif file['t'] == 3:
      inbox_id = file['h']
    elif file['t'] == 4:
      trashbin_id = file['h']
def login_anon():
  global sid, master_key
  master_key = [random.randint(0, 0xFFFFFFFF)] * 4
  password_key = [random.randint(0, 0xFFFFFFFF)] * 4
  session_self_challenge = [random.randint(0, 0xFFFFFFFF)] * 4
 
  user_handle = api_req({
      'a': 'up',
      'k': a32_to_base64(encrypt_key(master_key, password_key)),
      'ts': base64urlencode(a32_to_str(session_self_challenge) + a32_to_str(encrypt_key(session_self_challenge, master_key)))
  })
 
  # print "ephemeral user handle: %s" % user_handle
  res = api_req({'a': 'us', 'user': user_handle})
 
  enc_master_key = base64_to_a32(res['k'])
  master_key = decrypt_key(enc_master_key, password_key)
  if 'tsid' in res:
    tsid = base64urldecode(res['tsid'])
    if a32_to_str(encrypt_key(str_to_a32(tsid[:16]), master_key)) == tsid[-16:]:
      sid = res['tsid']
def getpublicurl(file):
  public_handle = api_req({'a': 'l', 'n': file['h']})
  key = file['k'][file['k'].index(':') + 1:]
  decrypted_key = a32_to_base64(decrypt_key(base64_to_a32(key), master_key))
  return "http://mega.co.nz/#!%s!%s" % (public_handle, decrypted_key)


def megaup_GetHumanReadable(size,precision=2):
  suffixes=['B','KB','MB','GB','TB']
  suffixIndex = 0
  while size > 1024:
      suffixIndex += 1 #increment the index of the suffix
      size = size/1024.0 #apply the division
  return "%.*f %s" % (precision,size,suffixes[suffixIndex])


def megaup_upload(fichero,anonimo,config):
  if anonimo=='no':
    login(config.get('mega.co.nz','email'), config.get('mega.co.nz','password'))
  else:
    login_anon()
  getfiles()
  uploaded_file = uploadfile(fichero)
  print '\n\nLink público en mega.co.nz:\n ',getpublicurl(uploaded_file['f'][0])

def megaup_anonimo(config):
  anonimo='no'
  if len(config.get('mega.co.nz','email'))>0:
    anonimo='no'
  else:
    subir=raw_input('No ha configurado su cuenta de mega.co.nz. ¿Quiere subir el fichero de forma anónima? (s/n): ')
    if subir == 'n':
      print 'Por favor edite el fichero megaup.cfg y configure sus datos de acceso a mega.co.nz.'
      anonimo='cancelar'
    else:
      anonimo='si'
  return anonimo

def megaup_init(args):
  config = ConfigParser.ConfigParser()
  config.readfp(open('megaup.cfg'))

  print "%s %s - %s\n"%(config.get('MEGAUP','app'),config.get('MEGAUP','version'),config.get('MEGAUP','title'))

  anonimo = megaup_anonimo(config)

  if anonimo!='cancelar':
    if len(args)>1:
      for x in args[1:]:
        megaup_upload(x,anonimo,config)
    else:
      fichero=raw_input('Introduzca el nombre del fichero que desea subir a mega.co.nz:')    
      while len(fichero)==0:
        fichero=raw_input('Nombre inválido. Introduzca el nombre del fichero que desea subir a mega.co.nz:')    
      megaup_upload(fichero,anonimo,config)

    
def megaup_signal_handler(signal, frame):
  print '\nLa subida ha sido abortada.\n\nGracias por utilizar MegaUp.'
  sys.exit(0)


def split_list(alist, wanted_parts=1):
  length = len(alist)
  return [ alist[i*length // wanted_parts: (i+1)*length // wanted_parts] 
           for i in range(wanted_parts) ]

if __name__ == '__main__':
  signal.signal(signal.SIGINT, megaup_signal_handler)
  megaup_init(sys.argv)
  print '\n\nGracias por utilizar MegaUp.\n\n'

