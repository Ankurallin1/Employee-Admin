require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const app = express();
const cors = require('cors');
const port = 5000;
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const Router_crud = require('./Routes/Router');
const UserLogin = require('./Routes/userRoutes')
require('./DB/Connect');
app.use(express.json());
app.use(cors(
    {
        credentials: true,
    }
));
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: 'Too many requests, please try again later.'
});

const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, 
    delayAfter: 50, 
    delayMs: 500 
});

app.use(limiter); 
app.use(speedLimiter);

app.get('/', (req, res) => {
    res.send('Hello World');
});
app.use('/', Router_crud);
app.use('/api/users', UserLogin);
app.listen(port, () => { console.log(`Server Running on Port ${port}`) });
