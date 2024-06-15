require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const app = express();
const cors = require('cors');
const port = 5000;
const Router_crud = require('./Routes/Router');
const UserLogin = require('./Routes/userRoutes')
require('./DB/Connect');
app.use(express.json());
app.use('/uploads',express.static('uploads'));
app.use(cors(
    {
        credentials: true,
    }
));
app.use('/', Router_crud);
app.use('/api/users', UserLogin);
app.listen(port, () => { console.log(`Server Running on Port ${port}`) });
