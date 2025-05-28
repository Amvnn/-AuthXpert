import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const connectDB = async () => {
    try {
        console.log("Connecting to MongoDB...");
        console.log("Connection string:", process.env.MONGO_URI); // Check this matches what you expect
        
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log("✅ MongoDB connected successfully");
        
        // Verify the database name
        console.log("Connected to database:", mongoose.connection.name);
        
        // List all collections
        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log("Collections in database:", collections.map(c => c.name));
        
    } catch (err) {
        console.error("❌ MongoDB connection error:", err.message);
        process.exit(1);
    }
};

export default connectDB;