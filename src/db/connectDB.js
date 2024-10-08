import mongoose from "mongoose"
import { DB_NAME } from "../constants.js"

async function connectDB(){
    try {
        const connectionInstance = await mongoose.connect(`${process.env.DATABASE_URI}/${DB_NAME}`);
        console.log(`\nMONGODB connected !! DB HOST: ${connectionInstance.connection.host}`)
    } catch (error) {
        console.log("DATABASE CONNECTION FAILED: ",error);
        process.exit(1);
    }
}

export default connectDB