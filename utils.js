import jwt from 'jsonwebtoken'
import {getUsers} from './database.js'
import * as settings from './config.json' with { type: 'json' }
const limiterSettings = settings.default.rateLimiterSettings

const sum = (a, b) => {
    return a + b;
}

const rateLimiter = (user, req, res) => {
    const window = getLimiterWindow()
    if ( user.rateLimiting.window < window ) {
        user.rateLimiting.window = window;
        user.rateLimiting.requestCounter = 1;
        res.set('X-RateLimit-Remaining', limiterSettings.limit - user.rateLimiting.requestCounter)
    } else { 
        if ( user.rateLimiting.requestCounter >= limiterSettings.limit ) { 
            res.set('X-RateLimit-Remaining', 0)
            res.status(429).end()   
            return true             
        } else { 
            user.rateLimiting.requestCounter++;
            res.set('X-RateLimit-Remaining', limiterSettings.limit - user.rateLimiting.requestCounter)
        } 
    }
    return false 
}

const getLimiterWindow = () => {
    const window = Math.round( Date.now() / limiterSettings.windowSizeInMillis )
    return window
}

const verifyToken = (req, res, next) => {
    const bearer_token = req.header('Authorization');
    if(bearer_token && bearer_token.toLowerCase().startsWith('bearer ')) {
        const token = bearer_token.substring(7);
        try {
            const decodedToken = jwt.verify(token, 'my_secret_key')
            const now = Date.now() / 1000
            const isValid = (decodedToken.exp - now) >= 0 ? true : false;
            if(isValid) {
                let user = getUsers().find(a => (a.username === decodedToken.username)&&(a.token === token));
                if( user != null ) {
                    if (! rateLimiter( user, req, res ))
                        next()
                } else
                    res.status(401).json({"error": "Unauthorized"})
            } else
            res.status(401).json({"error": "Invalid token"})
        } catch (err) {
            res.status(401).json({"error": "Invalid token"})
        }
    } else
        res.status(401).json({"error": "Invalid token"})
} 

export {
    sum,
    verifyToken,
    getLimiterWindow
}