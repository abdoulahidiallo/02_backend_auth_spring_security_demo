#POST
http://127.0.0.1:8081/api/v1/auth/register
{
        "firstname": "Abdoulaye",
        "lastname": "DIALLO",
        "email": "admin@gmail.com",
        "password": "password",
        "role": "ADMIN"

    }

    {
            "firstname": "USER",
            "lastname": "01",
            "email": "user1@gmail.com",
            "password": "password",
            "role": "USER"

        }

http://127.0.0.1:8081/api/v1/auth/authenticate
{
    "email": "user1@gmail.com",
    "password": "password"
}
{
    "email": "admin@gmail.com",
    "password": "password"
}