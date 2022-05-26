const User = require('../model/User');

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken

    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204); //No content
    //, secure: true for production only // res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None'});
    res.sendStatus(204);
}

module.exports = { handleLogout }