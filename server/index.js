import express from 'express';
import cors from 'cors';
import router from '../app/routes';
import mongoose from 'mongoose';

const dotenv = require('dotenv');
dotenv.config();

const app = express()
const port = process.env.APP_PORT
const app_url = process.env.APP_URL + process.env.APP_PORT

app.use(express.urlencoded({ extended: true }));
app.use(express.json({limit:'500mb'}));
app.use(cors({
    credentials: true,
    origin: 'http://localhost:4000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
}));

const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI, {
}).then(() => {
    console.log('Connected to mongodb successfully');
}).catch((e) => {
    console.error('Could not connect to MongoDB', e);
});

app.use("/api", router);

app.route("/").get((req, res) => {
  res.send('Welcome to the innovent')
})


app.listen(port, () => {
  console.log(`Listening on port ${port}`)
  console.log(`App started on ${app_url}`)
})