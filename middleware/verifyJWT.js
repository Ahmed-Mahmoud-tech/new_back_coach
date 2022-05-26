// const jwt = require('jsonwebtoken');
// const {handleRefreshToken} = require('../service/global/refreshToken');

// const verifyJWT = (req, res, next) => {
//     const authHeader = req.headers.authorization || req.headers.Authorization;
//     if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);
//     const token = authHeader.split(' ')[1];
//     console.log(token)
//     jwt.verify(
//         token,
//         process.env.ACCESS_TOKEN_SECRET,
//         (err, decoded) => {
//             if (err) return handleRefreshToken(req, res); //return res.sendStatus(403); //invalid token
//             req.user = decoded.UserInfo.username;
//             req.roles = decoded.UserInfo.roles;
//             next();
//         }
//     );
// }

// module.exports = verifyJWT

const jwt = require('jsonwebtoken');
const {handleRefreshToken} = require('../service/global/refreshToken');

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);
    const token = authHeader.split(' ')[1];
    console.log(token)
    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if (err) {
             handleRefreshToken(req, res, next); //return res.sendStatus(403); //invalid token
            }else{
                req.user = decoded.UserInfo.username;
                req.roles = decoded.UserInfo.roles;
                next();
            }
        }
    );
}

module.exports = verifyJWT