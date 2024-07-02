import 'dotenv/config'
import connectDB from "./db/connectDB.js";
import app from './app.js';

connectDB()
.then(() => {
    app.listen(process.env.PORT || 8000, ()=>{
        console.log(`Server running on port: ${process.env.PORT || 8000}`);
    });
})
.catch((err)=>{
    console.log("MONGODB connection Failed: ", err);
})