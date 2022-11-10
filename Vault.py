import os
import base64
import subprocess

#os.system("vault kv get secret/hello")

#os.system("set VAULT_ADDR='http://127.0.0.1:8200'")

#output_stream = os.popen("vault server -dev")
#output_stream.read()
#get_key = subprocess.check_output("vault server -dev",shell=True)
#print(get_key)

#os.system("vault secrets enable transit")

def start_server(add, token):
    os.environ["VAULT_ADDR"] = add
    os.environ["VAULT_TOKEN"] = token
    #os.system("vault secrets enable transit")

def base64EncodeToString(message):
    b = base64.b64encode(bytes(message, 'utf-8'))  # bytes
    return b







if __name__ == "__main__":
    address = input("Enter address:")
    token = input("Enter token:")
    start_server(address, token)
    os.system("vault write transit/keys/mytestkey type=aes256-gcm96")


    message = input("Enter message:")
    string_message = str(base64EncodeToString(message), 'utf-8')

    os.system("vault write transit/encrypt/k1 plaintext="+string_message)

    cripher_text = input("Enter cipher text:")
    decrypted_message = os.system("vault write transit/decrypt/k1 ciphertext=" + cripher_text )


    base64_message = input("Enter decrypted base64:")
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    final_message = message_bytes.decode('ascii')

    print(final_message)






#http://127.0.0.1:8200
#hvs.IomuBFLArUVMpRXXwuqcAnAD






