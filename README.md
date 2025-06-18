port used is 9090

# Encrypt
curl -X POST http://localhost:9090/api/encrypt -H "Content-Type: text/plain" -d "HelloWorld"

# => Returns base64-encoded encrypted string

# Decrypt
curl -X POST http://localhost:9090/api/decrypt -H "Content-Type: text/plain" -d "<output-above>"
# => HelloWorld
