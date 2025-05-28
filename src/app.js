import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import cors from 'cors';

import authRoutes from './routes/authRoutes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 
    }
  }));

app.use(cors({
    origin:process.env.CORS_ORIGIN?.split(',') || ['http://localhost:5173'],
    methods:['GET','POST','PUT','DELETE'],
    allowedHeaders:['Content-Type', 'Authorization']
}));

app.use('/api/auth',authRoutes);

app.use('/health',(req,res)=>{
    res.json({status:'OK'});
});

app.use((err,req,res,next)=>{
    console.error(err.stack);
    res.status(500).json({
        error:err.message,
        ...(process.env.NODE_ENV ==='developement' && { stack: err.stack })
    });
});

app.listen(PORT,()=>{
    console.log(`Server is listening on port ${PORT}`)
});