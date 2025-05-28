import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import connectDB from './src/config/db.js';
import authRoutes from './src/routes/Auth_Routes.js';

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended:true}));

//Routes
app.use('/api/auth',authRoutes);

//Health checck endpoint
app.get('/health',(req,res)=>{
    res.status(200).json({status:'ok',message:'Auth Service is running good'})
});

// Error handling middleware
app.use((err,req,res,next)=>{
    console.error(err.stack);
    res.status(500).json({
        error:'Internal Server Error!',
        message: process.env.NODE_ENV === 'development' ?err.message : "Something went wrong!"  
    });
});

const PORT = process.env.PORT || 5000;

const startServer = async () =>{
    try{
        await connectDB();
        app.listen(PORT,()=>{
            console.log(`Server is running on ${PORT}`)
        });
    }catch(error){
        console.error('Failed to start the server:',error);
        process.exit(1);
    }
}

startServer();