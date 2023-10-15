import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

iv = b"infinity_edgehtb"
key = bytes.fromhex("4d65bdbad183f00203b1e80cf96fba549663dabeab12fab153a921b346975cdd")
def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext
i1 = 0
with open('http.txt','r') as f:  
    for i in  f.readlines():
      try:
        encrypted = base64.b64decode(bytes.fromhex(i).decode())
        with open(f'/home/kali/Desktop/decrypt/{i1}.cs', 'wb') as f1:
          f1.write(decrypt(encrypted, key, iv))
        # print(decrypt(encrypted, key, iv))
        i1+=1
      except:
        continue 
