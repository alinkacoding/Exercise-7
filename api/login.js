import { Router } from 'express';
import jwt from 'jsonwebtoken';
import {getUsers} from '../database.js'
let router = Router()
let users = getUsers()

router.post('/', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    let user;

    if( user = users.find(a => (a.username === username)&&(a.password === password))) {
        const token = jwt.sign({username: username}, 'my_secret_key', {
            expiresIn: '8h'
        })
/*
        const refreshToken = jwt.sign({username: username}, 'my_secret_key', {
            expiresIn: '1d'
        })

        res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'strict' })
        .header('Authorization', 'Bearer '+accessToken)
        .json({
          "username": username, 
          "expires_in": "1h"
        });
*/        
        user.token = token;
        res.json( {
            'username': username,
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': '8h'
        });
    } else
        res.status(401).json({"error": "Login failed"});
})

export default router;