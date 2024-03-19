const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

function createAuthMiddleware(options) {
    const router = express.Router();
    const UserModel = options.UserModel;
    const userDataFields = options.userDataFields;

    router.post('/signup', async (req, res) => {
        try {
            const userData = req.body;
            const { password, ...userInfo } = userData;

            const hashedPassword = await bcrypt.hash(password, 10);


            const userFields = {};
            userDataFields.forEach(field => {
                if (userInfo[field]) userFields[field] = userInfo[field];
            });
            userFields.password = hashedPassword;

            const user = new UserModel(userFields);
            await user.save();

            res.status(201).json({ message: "User is created successfully", user });
        } catch (error) {
            res.status(500).json({ message: "Error creating user", error: error.message });
        }
    });

    router.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body;
    
            const user = await UserModel.findOne({ email });
            if (!user) {
                return res.status(404).json({ error: "User not found" });
            }
    
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return res.status(401).json({ error: "Invalid credentials" });
            }
    
            const token = jwt.sign({ _userid: user._id }, options.jwtSecret, { expiresIn: '1h' });
    
            res.json({ token });
        } catch (error) {
            res.status(500).json({ error: "Internal server error", message: error.message });
        }
    });    

    return router;
}

const createMongoDBConnection =  (uri,port,app) => {
    mongoose
    .connect(uri)
    .then(() => {
      console.log("Connected to MongoDB");
    })
    .catch((err) => {
      console.error("Error connecting to MongoDB:", err.message);
    });
    app.listen(port, () => {
        console.log(`Server is listening on port ${port}`);
      });
  };


  module.exports = {
    createMongoDBConnection: createMongoDBConnection,
    createAuthMiddleware: createAuthMiddleware
};