const User = require('../../model/User');
const jwt = require('jsonwebtoken');

const handleRefreshToken = async (req, res, next) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {

            const foundUser = await User.findOne({ username: decoded.username }).exec();

            if (err || !foundUser) return res.sendStatus(403);
                
            const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": decoded.username,
                        "roles": roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '10s' }
            );
            
            const refreshToken = jwt.sign(
                { "username": foundUser.username },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: '1d' }
            );
            res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
            req.user = foundUser.username;
            req.roles = roles;
            res.newToken={ roles, accessToken }
            next();
        }
    );
}

module.exports = { handleRefreshToken }