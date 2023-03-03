import jwt from 'jsonwebtoken';

/*
    For example, if a user wants to like a post
    like button clicked => auth middleware checking if the user is authorized, if so, next() => calls like controller...
*/

const auth = async (req, res, next) => {
    try {
        // Getting the json webtoken from the front-end if the client is signed in
        const token = req.headers.authorization.split(" ")[1];

        // Check to see if the token is from jwt or from google auth
        const isCustomAuth = token.length < 500;

        let decodedData;

        if (token && isCustomAuth) {
            decodedData = jwt.verify(token, 'test'); // 'test' is the secret from the auth controller
            req.userId = decodedData?.id;
        } else {
            decodedData = jwt.decode(token);
            req.userId = decodedData?.sub; // Google's name for a specific id that differentiates every Google user
        }

        next();

    } catch (error) {
        console.log(error);
    }
}

export default auth;