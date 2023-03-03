import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import User from '../models/user.js';

export const signin = async (req, res) => {
    // Getting user input from the sign-in form in the client
    const {email, password} = req.body;
    try {
        // Querying user in database
        const existingUser = await User.findOne({ email }); 

        // Checking if the user exists in database
        if (!existingUser) return res.status(404).json({message: "User doesn't exist."}); 

        // Comparing input password with the password in the database
        const isPasswordCorrect = await bcrypt.compare(password, existingUser.password); 
        if (!isPasswordCorrect) return res.status(400).json({message: "Invalid credentials."});

        // Issuing a json webtoken back to the client
        const token = jwt.sign({email: existingUser.email, id: existingUser._id}, 'test', {expiresIn: '1h'}); // 'test' is the secret that should be saved in a .env file when production
        res.status(200).json({result: existingUser, token});

    } catch (error) {
        res.status(500).json({message: "Something went wrong."});
    }
}

export const signup = async (req, res) => {
    // Getting user input from the sign-up form in the client
    const {email, password, confirmPassword, firstName, lastName} = req.body;

    try {
        // Checking if the user already exists in database
        const existingUser = await User.findOne({email});
        if (existingUser) return res.status(400).json({message: "User already exists."});

        // Checking if the user typed different passwords when in the sign-up form
        if (password !== confirmPassword) return res.status(400).json({message: "Passwords don't match"});

        // Hashing the password the user input in the sign-up form before creating a user
        const hashedPassword = await bcrypt.hash(password, 12);

        // Creating the user and send the json webtoken back to client
        const result = await User.create({email, password: hashedPassword, name: `${firstName} ${lastName}`});
        const token = jwt.sign({email: result.email, id: result._id}, 'test', {expiresIn: '1h'}); 
        res.status(200).json({result, token});

    } catch (error) {
        res.status(500).json({message: "Something went wrong."});
    }
}