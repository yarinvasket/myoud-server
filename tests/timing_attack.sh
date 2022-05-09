while :
do
    curl -X POST http://localhost:5000/api/register -H 'Content-Type: application/json' -d '{"user_name":"aehtaiuh", "public_key":"agaaaa", "signature":"a", "encrypted_private_key":"aa", "hashed_password":"a"}' &
done
