# dynamic-auth

This package provides customizable authentication middleware for Express.js applications. It allows users to easily implement user signup and login functionality with MongoDB and JWT authentication. Users can specify their own Mongoose model for the user and define the fields for user data dynamically.

## Installation

1) Create a backend folder

2) install express, mongoose, nodemon, cors, jsonwebtoken and bycrypt packages:

        npm i express mongoose nodemon cors jsonwebtoken bcrypt
3) Create a model in a folder and call it in the index.js

4) Connect the mongodb using mongoose

5) Install the package "dynamic-auth"
        npm i dynamic-auth
6) After the installing the package initialize it with " const createAuthMiddleware = require('dynamic-auth'); "

7) In the userDataFields constant give the details required for signup

8) Call the backend using
        app.use('/auth', createAuthMiddleware({ jwtSecret: process.env.JWT_SECRET, UserModel: User, userDataFields }));

9) For Signin use - http://localhost:3000/auth/signup - this path and POST method
       Login use - http://localhost:3000/auth/login - this path and POST method

10) Finally don't forget to add the env file '.env' for PORT, MONGODB_URI, JWT_SECRET

11) Your backend dynamic authentication is ready.

### Github link for reference repository

https://github.com/Deepakraja03/dynamic-auth-user-repo.git
